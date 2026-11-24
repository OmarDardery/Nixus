package main

// Bounded management probes, clock sanity and settings reading. No tokens,
// passwords or raw service logs appear in reports.

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const cockpitTemplate = "/etc/nixus/cockpit-base.conf"
const cockpitConfig = "/run/nixus/cockpit.conf"

func clockStatus(at float64) M {
	if at == 0 {
		at = now()
	}
	plausible := !math.IsInf(at, 0) && !math.IsNaN(at) && at >= 1767225600 && at < 4102444800
	var synchronized any
	if plausible {
		res, err := run([]string{"timedatectl", "show", "--property=NTPSynchronized", "--value"}, nil, 3*time.Second, nil, "")
		value := strings.TrimSpace(string(res.Stdout))
		if err == nil && res.Code == 0 && (value == "yes" || value == "no") {
			synchronized = value == "yes"
		}
	}
	state := "plausible-but-unsynchronized"
	if !plausible {
		state = "invalid-clock"
	} else if isTrue(synchronized) {
		state = "synchronized"
	}
	guidance := ""
	if state != "synchronized" {
		guidance = "Check the host date, time synchronization service, DNS and network reachability; then refresh. " +
			"Unsynchronized timestamps are not reliable backup or qualification evidence."
	}
	return M{"state": state, "synchronized": synchronized, "timestampPlausible": plausible,
		"evidenceWarning": state != "synchronized", "guidance": guidance}
}

func requirePlausibleClock() error {
	if str(clockStatus(0)["state"]) == "invalid-clock" {
		return Public("Host clock is grossly invalid; correct the date/time before issuing a browser certificate")
	}
	return nil
}

func managementAddress(settings M) (string, error) {
	iface := str(jget(settings, "management", "interface"))
	out, err := check([]string{"ip", "-j", "-4", "address", "show", "dev", iface}, nil, 10*time.Second)
	if err != nil {
		return "", err
	}
	var assigned []string
	for _, link := range list(must(parseJSON(out))) {
		for _, a := range list(obj(link)["addr_info"]) {
			addr := obj(a)
			if str(addr["family"]) == "inet" && str(addr["scope"]) == "global" {
				assigned = append(assigned, str(addr["local"]))
			}
		}
	}
	configured := str(jget(settings, "management", "address"))
	for _, a := range assigned {
		if a == configured {
			return configured, nil
		}
	}
	if len(assigned) > 0 && !isTrue(jget(settings, "management", "configure")) {
		return assigned[0], nil
	}
	return "", Public("Management interface has no usable address: " + iface)
}

func managementClient() (*http.Client, error) {
	pool := x509.NewCertPool()
	ca, err := os.ReadFile(filepath.Join(STATE, "ca.crt"))
	if err != nil {
		return nil, err
	}
	pool.AppendCertsFromPEM(ca)
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func probeRequest(client *http.Client, address string, port int, p string) (int, error) {
	resp, err := client.Get(fmt.Sprintf("https://%s:%d%s", address, port, p))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if len(data) > 65536 {
		return 0, Hidden("Oversized management response")
	}
	return resp.StatusCode, nil
}

func probe(settings M) (M, error) {
	address, err := managementAddress(settings)
	if err != nil {
		return nil, err
	}
	type target struct {
		name string
		port int
		path string
	}
	var targets []target
	ready := isTrue(settings["ready"])
	if ready {
		targets = append(targets, target{"Incus API", 8443, "/1.0"}, target{"Incus UI", 8443, "/ui/"})
	}
	setupPort, _ := intValue(jget(settings, "setup", "port"))
	if isTrue(jget(settings, "setup", "enable")) {
		targets = append(targets, target{"Nixus", setupPort, "/"})
	}
	if ready && isTrue(jget(settings, "cockpit", "enable")) {
		p, _ := intValue(jget(settings, "cockpit", "port"))
		targets = append(targets, target{"Cockpit", p, "/ping"})
	}
	client, cerr := managementClient()
	checks := []any{}
	ok := true
	for _, t := range targets {
		url := fmt.Sprintf("https://%s:%d", address, t.port)
		if cerr != nil {
			checks = append(checks, M{"name": t.name, "url": url, "ok": false, "detail": "CertificateError"})
			ok = false
			continue
		}
		status, err := probeRequest(client, address, t.port, t.path)
		if err != nil {
			checks = append(checks, M{"name": t.name, "url": url, "ok": false, "detail": "ConnectionError"})
			ok = false
			continue
		}
		checks = append(checks, M{"name": t.name, "url": url, "ok": status == 200, "detail": fmt.Sprintf("HTTP %d", status)})
		ok = ok && status == 200
	}
	if isTrue(jget(settings, "setup", "enable")) {
		plain := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		url := fmt.Sprintf("http://%s:80", address)
		resp, err := plain.Get(url + "/")
		if err != nil {
			checks = append(checks, M{"name": "Nixus HTTP entry", "url": url, "ok": false, "detail": "ConnectionError"})
			ok = false
		} else {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			targetOK := resp.Header.Get("Location") == fmt.Sprintf("https://%s:%d/", address, setupPort)
			detail := fmt.Sprintf("HTTP %d", resp.StatusCode)
			if targetOK {
				detail += " → HTTPS"
			} else {
				detail += " (invalid target)"
			}
			good := resp.StatusCode == 308 && targetOK
			checks = append(checks, M{"name": "Nixus HTTP entry", "url": url, "ok": good, "detail": detail})
			ok = ok && good
		}
	}
	return M{"address": address, "ok": ok, "checks": checks}, nil
}

func waitReady(settings M, timeout time.Duration) (M, error) {
	if timeout == 0 {
		timeout = 180 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		report, err := probe(settings)
		if err != nil {
			report = M{"ok": false, "error": "Management health probe failed"}
		}
		if isTrue(report["ok"]) {
			return report, nil
		}
		if time.Now().After(deadline) {
			writeJSON(filepath.Join(STATE, "last-health.json"), report)
			raw, _ := json.Marshal(report)
			return nil, Public("Management health checks failed: " + string(raw) + "; run sudo nixus doctor")
		}
		time.Sleep(2 * time.Second)
	}
}

// writeCockpitOrigins renders the template with the WebService Origins line.
func writeCockpitOrigins(address string, settings M) error {
	raw, err := os.ReadFile(cockpitTemplate)
	if err != nil {
		return err
	}
	port, _ := intValue(jget(settings, "cockpit", "port"))
	set := map[string]bool{address: true, "127.0.0.1": true, "localhost": true, str(settings["hostName"]): true}
	var hosts []string
	for h := range set {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	var origins []string
	for _, h := range hosts {
		origins = append(origins, fmt.Sprintf("https://%s:%d", h, port))
	}
	originLine := "Origins = " + strings.Join(origins, " ")
	var out bytes.Buffer
	inWeb, wrote, hasWeb := false, false, false
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			if inWeb && !wrote {
				out.WriteString(originLine + "\n")
				wrote = true
			}
			inWeb = trimmed == "[WebService]"
			hasWeb = hasWeb || inWeb
		} else if inWeb {
			if k, _, ok := strings.Cut(trimmed, "="); ok && strings.TrimSpace(k) == "Origins" {
				continue
			}
		}
		out.WriteString(line + "\n")
	}
	if !hasWeb {
		out.WriteString("\n[WebService]\n")
	}
	if !wrote {
		out.WriteString(originLine + "\n")
	}
	return atomic(cockpitConfig, out.Bytes(), 0o644, "")
}

func identityRefresh(settings M) (string, error) {
	address, err := managementAddress(settings)
	if err != nil {
		return "", err
	}
	if isTrue(jget(settings, "cockpit", "enable")) {
		if err := writeCockpitOrigins(address, settings); err != nil {
			return "", err
		}
	}
	cert := filepath.Join(STATE, "tls.crt")
	valid := false
	if isFile(cert) {
		res, err := run([]string{"openssl", "x509", "-in", cert, "-noout", "-checkip", address}, nil, 10*time.Second, nil, "")
		valid = err == nil && res.Code == 0 && strings.Contains(string(res.Stdout), "does match certificate")
	}
	if !valid {
		if err := issueTLS(address, str(settings["hostName"])); err != nil {
			return "", err
		}
	}
	return address, nil
}

func doctor(settings M) M {
	report, err := probe(settings)
	if err != nil {
		report = M{"ok": false, "error": "Management health probe failed"}
	}
	report["clock"] = clockStatus(0)
	services := []any{}
	for _, unit := range []string{"incus", "incus-preseed", "nixus-management-identity",
		"nixus-admin-backend", "nixus-ui", "nixus-rollback-guard.service", "cockpit.socket", "cockpit.service"} {
		data := systemctlShow(unit, "Id,LoadState,ActiveState,SubState,Result,ExecMainStatus")
		if data["LoadState"] == "loaded" {
			services = append(services, data)
			if data["ActiveState"] == "failed" {
				report["ok"] = false
			}
		}
	}
	report["services"] = services
	active := readObj(filepath.Join(STATE, "active.json"))
	if id := str(active["id"]); id != "" {
		job := readObj(filepath.Join(STATE, "jobs", id, "job.json"))
		transaction := M{}
		for _, k := range []string{"id", "status", "error", "rollbackError"} {
			if v, ok := job[k]; ok {
				transaction[k] = v
			}
		}
		for _, field := range []string{"error", "rollbackError"} {
			if v := transaction[field]; v != nil && v != "" && v != false {
				transaction[field] = "Transaction did not complete; inspect the host recovery state"
			}
		}
		report["transaction"] = transaction
		report["log"] = filepath.Join(STATE, "jobs", id, "build.log")
	}
	writeJSON(filepath.Join(STATE, "last-health.json"), report)
	return report
}

// systemctlShow returns `systemctl show -p ...` properties as a map.
func systemctlShow(unit, properties string) M {
	res, _ := run([]string{"systemctl", "show", unit, "-p", properties}, nil, 10*time.Second, nil, "")
	data := M{}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			data[k] = v
		}
	}
	return data
}

// settingsInputs are every file site.nix can read; their stat fingerprint
// keys the settings cache.
var settingsInputs = []string{"site.nix", "site-defaults.nix", "lib/machine.nix", "lib/settings-migrations.nix",
	"machine/format.json", "machine/settings.json"}

var settingsCache = struct {
	sync.Mutex
	entries map[string]settingsEntry
}{entries: map[string]settingsEntry{}}

type settingsEntry struct {
	key   string
	value M
}

func settingsFingerprint(root string) string {
	var b strings.Builder
	for _, rel := range settingsInputs {
		if info, err := os.Stat(filepath.Join(root, rel)); err == nil {
			fmt.Fprintf(&b, "%s:%d:%d;", rel, info.Size(), info.ModTime().UnixNano())
		} else {
			fmt.Fprintf(&b, "%s:-;", rel)
		}
	}
	return b.String()
}

// readSettings evaluates the selected source's pure site.nix entrypoint. The
// result is cached until one of its input files changes.
func readSettings(root string) (M, error) {
	key := settingsFingerprint(root)
	settingsCache.Lock()
	entry, ok := settingsCache.entries[root]
	settingsCache.Unlock()
	if ok && entry.key == key {
		return cloneM(entry.value), nil
	}
	m, err := evalSettings(root)
	if err != nil {
		return nil, err
	}
	settingsCache.Lock()
	settingsCache.entries[root] = settingsEntry{key, cloneM(m)}
	settingsCache.Unlock()
	return m, nil
}

func evalSettings(root string) (M, error) {
	res, err := run([]string{"nix-instantiate", "--eval", "--strict", "--json", filepath.Join(root, "site.nix")}, nil, 10*time.Second, nil, "")
	if err != nil {
		return nil, Public("Nix settings evaluation is unavailable; inspect the host console")
	}
	if res.Code != 0 {
		if strings.Contains(string(res.Stderr), "Unsupported Nixus settings schema version") {
			return nil, Public("Unsupported Nixus settings schema version; use compatible platform source")
		}
		return nil, Public("Nix settings evaluation failed; inspect the source from the host console")
	}
	v, err := parseJSON(res.Stdout)
	if err != nil {
		return nil, Public("Nix settings evaluation returned invalid JSON")
	}
	m := obj(v)
	if m == nil {
		return nil, Public("Nix settings evaluation must return an object")
	}
	return m, nil
}
