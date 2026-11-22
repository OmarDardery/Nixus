package main

// Bounded host health diagnostics and commissioning evidence.

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

var healthUnits = []string{"incus.service", "incus-preseed.service", "nixus-kvm-check.service", "nixus-instances.service",
	"cockpit.socket", "cockpit.service", "nginx.service", "nixus-admin-backend.service", "nixus-ui.service",
	"nixus-project-backup.timer", "nixus-storage.target", "nixus-rollback-guard.service", "smartd.service"}

func effectiveSettingsFile() M {
	if v, err := readJSON("/etc/nixus/effective-settings.json", nil); err == nil && obj(v) != nil {
		return obj(v)
	}
	return readObj(machinePath(ROOT, "settings"))
}

func health() M {
	result := M{"checkedAt": int(now()), "release": upgradeMetadata(ROOT), "lastBackupSuccess": nil, "clock": clockStatus(now())}
	services := []any{}
	for _, unit := range healthUnits {
		services = append(services, systemctlShow(unit, "Id,LoadState,ActiveState,SubState,Result,ExecMainStatus"))
	}
	result["services"] = services
	certificates := M{}
	for _, name := range []string{"tls.crt", "ca.crt"} {
		p := filepath.Join(STATE, name)
		if !isFile(p) {
			certificates[name] = M{"present": false}
			continue
		}
		end, _ := run([]string{"openssl", "x509", "-in", p, "-noout", "-enddate"}, nil, 10*time.Second, nil, "")
		soon, _ := run([]string{"openssl", "x509", "-in", p, "-noout", "-checkend", "2592000"}, nil, 10*time.Second, nil, "")
		certificates[name] = M{"present": true, "expires": strings.TrimSpace(string(end.Stdout)), "expiresWithin30Days": soon.Code != 0}
	}
	result["certificates"] = certificates
	pending, _ := readJSON("/var/lib/nixus/restart-pending.json", []any{})
	result["guestsAwaitingRestart"] = len(list(pending))
	var fs syscall.Statfs_t
	if syscall.Statfs("/", &fs) == nil {
		result["rootStorage"] = M{"totalBytes": int64(fs.Blocks) * fs.Frsize, "availableBytes": int64(fs.Bavail) * fs.Frsize}
	} else {
		result["rootStorage"] = nil
	}
	backup := M{"health": projectBackupHealth()}
	if last, ok := num(projectBackupStatus()["lastSuccess"]); ok && last > 0 {
		result["lastBackupSuccess"] = int(last)
	}
	result["backup"] = backup
	return result
}

func q(s string) string { return url.PathEscape(s) }

var commissioningChecks = [][2]string{
	{"clock", "Plausible synchronized host clock at evidence collection"},
	{"management", "Local management endpoints and service health"},
	{"kvm", "Usable KVM API"},
	{"container", "Running unprivileged Incus container"},
	{"install-resume", "Installation or upgrade and interrupted retry"},
	{"management-auth", "Authenticated remote SSH, Cockpit and Incus access"},
	{"reboots", "Healthy management across two deliberate reboots"},
	{"network-recovery", "Actual network loss and confirmation rollback"},
	{"offhost-restore", "Independent off-host restore with verified application data"},
	{"hardware-reconnect", "Configured physical device disconnect/reconnect"},
}
var automaticChecks = map[string]bool{"clock": true, "management": true, "kvm": true, "container": true}
var evidenceStatuses = map[string]bool{"passed": true, "failed": true, "skipped": true, "unsupported": true, "unknown": true}
var environments = map[string]bool{"installed-host": true, "automated-fixture": true, "nested-integration": true}
var contextFields = []string{"revision", "version", "sourceDigest", "inputsDigest", "settingsDigest", "system", "kernel", "incus",
	"hardwareDigest", "scope", "architecture", "hardwareDevices", "mode", "environment"}

const commissioningMaxAge = 30 * 86400

var sha64 = re(`[0-9a-f]{64}`)

func isCheck(name string) bool {
	for _, c := range commissioningChecks {
		if c[0] == name {
			return true
		}
	}
	return false
}

func readText(p string) string {
	raw, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func probeCommand(args ...string) (string, error) {
	res, err := run(args, nil, 15*time.Second, nil, "")
	if err != nil || res.Code != 0 || len(res.Stdout) > 2<<20 {
		return "", Public("Probe unavailable")
	}
	return strings.TrimSpace(string(res.Stdout)), nil
}

func virtScope() string {
	if res, err := run([]string{"systemd-detect-virt", "--container", "--quiet"}, nil, 15*time.Second, nil, ""); err == nil && res.Code == 0 {
		return "container"
	}
	res, err := run([]string{"systemd-detect-virt"}, nil, 5*time.Second, nil, "")
	out := strings.TrimSpace(string(res.Stdout))
	switch {
	case err == nil && res.Code == 1 && out == "none":
		return "physical-host"
	case err == nil && res.Code == 0 && out != "":
		return "virtual-machine"
	}
	return "unknown"
}

func machineArch() string {
	var u syscall.Utsname
	syscall.Uname(&u)
	b := []byte{}
	for _, c := range u.Machine {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

func kernelRelease() string {
	var u syscall.Utsname
	syscall.Uname(&u)
	b := []byte{}
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

var incusVersion = regexp.MustCompile(`(?:Client|Server) version:\s*([0-9][a-zA-Z0-9.+-]*)`)

func commissioningContext(settings M, mode, environment string) M {
	release := upgradeMetadata(ROOT)
	hardware := []any{readText("/etc/machine-id"), machineArch(), readText("/sys/class/dmi/id/sys_vendor"), readText("/sys/class/dmi/id/product_name")}
	for _, directory := range []string{"/sys/class/net", "/sys/class/block"} {
		matches, _ := filepath.Glob(filepath.Join(directory, "*"))
		for _, device := range matches {
			if !exists(filepath.Join(device, "device")) {
				continue
			}
			hardware = append(hardware, []any{filepath.Base(device), readText(filepath.Join(device, "device/vendor")),
				readText(filepath.Join(device, "device/device")), readText(filepath.Join(device, "size"))})
		}
	}
	incus := "unknown"
	if out, err := probeCommand("incus", "--force-local", "version"); err == nil {
		if m := incusVersion.FindAllStringSubmatch(out, -1); len(m) == 2 {
			incus = m[0][1] + "_" + m[1][1]
		}
	}
	revision := str(release["revision"])
	if !fullmatch(sha40, revision) {
		revision = "unknown"
	}
	version := str(release["version"])
	if version == "" {
		version = "unknown"
	}
	system := "unknown"
	if p, err := filepath.EvalSymlinks("/run/current-system"); err == nil {
		system = p
	}
	sourceDigest, _ := digestSource(ROOT)
	return M{"revision": revision, "version": version, "sourceDigest": sourceDigest,
		"inputsDigest": digestJSON(readText(filepath.Join(ROOT, "flake.lock"))), "settingsDigest": digestJSON(settings),
		"system": system, "kernel": kernelRelease(), "incus": incus, "hardwareDigest": digestJSON(hardware), "scope": virtScope(),
		"architecture": machineArch(), "hardwareDevices": isTrue(jget(settings, "hardware", "serialAliases")) || len(obj(jget(settings, "hardware", "serialAliases"))) > 0,
		"mode": mode, "environment": environment}
}

func commissioningBoot() string {
	if v := readText("/proc/sys/kernel/random/boot_id"); v != "" {
		return digestJSON(v)
	}
	return "unknown"
}

var contextValue = re(`[a-zA-Z0-9/_.:+-]{1,256}`)
var fingerprintValue = re(`[0-9a-f]{64}|unknown`)

func validateReport(report M) error {
	if !exactKeys(report, "format", "context", "evidence") || !equalJSON(report["format"], 1) || !isInt(report["format"]) {
		return Public("Unsupported commissioning report")
	}
	ctx := obj(report["context"])
	if !exactKeys(ctx, contextFields...) {
		return Public("Invalid commissioning context")
	}
	if _, ok := ctx["hardwareDevices"].(bool); !ok {
		return Public("Invalid capability")
	}
	for _, k := range contextFields {
		if k != "hardwareDevices" && !fullmatch(contextValue, str(ctx[k])) {
			return Public("Invalid context value")
		}
	}
	scope, mode := str(ctx["scope"]), str(ctx["mode"])
	if (scope != "physical-host" && scope != "virtual-machine" && scope != "container" && scope != "unknown") ||
		(mode != "fresh" && mode != "upgrade") || !environments[str(ctx["environment"])] {
		return Public("Invalid commissioning scope or mode")
	}
	for _, k := range []string{"sourceDigest", "inputsDigest", "settingsDigest", "hardwareDigest"} {
		if !fullmatch(sha64, str(ctx[k])) {
			return Public("Invalid context digest")
		}
	}
	if str(ctx["revision"]) != "unknown" && !fullmatch(sha40, str(ctx["revision"])) {
		return Public("Invalid source revision")
	}
	evidence, ok := report["evidence"].([]any)
	if !ok || len(evidence) > 400 {
		return Public("Too many evidence records; start a new report")
	}
	for _, raw := range evidence {
		item := obj(raw)
		if !exactKeys(item, "check", "status", "type", "contextDigest", "time", "boot", "procedure") {
			return Public("Invalid evidence record")
		}
		for k, v := range item {
			if _, ok := v.(string); k != "time" && !ok {
				return Public("Invalid evidence value")
			}
		}
		check, typ := str(item["check"]), str(item["type"])
		if !isCheck(check) || !evidenceStatuses[str(item["status"])] || (typ != "automated-probe" && typ != "manual-attestation") {
			return Public("Invalid check, status or evidence type")
		}
		if typ == "automated-probe" && !automaticChecks[check] {
			return Public("Manual procedure cannot be an automated probe")
		}
		if typ == "manual-attestation" && automaticChecks[check] {
			return Public("Probe results must be collected, not attested")
		}
		if t, ok := num(item["time"]); !ok || !isInt(item["time"]) || t < 0 {
			return Public("Invalid evidence timestamp")
		}
		if !fullmatch(fingerprintValue, str(item["contextDigest"])) || !fullmatch(fingerprintValue, str(item["boot"])) {
			return Public("Invalid evidence fingerprint")
		}
		want := "probe-v1"
		if typ == "manual-attestation" {
			want = "commissioning-v1"
		}
		if str(item["procedure"]) != want {
			return Public("Unsupported evidence procedure")
		}
	}
	return nil
}

func recordEvidence(report, ctx M, check, status, typ string) error {
	report["context"] = ctx
	procedure := "probe-v1"
	if typ == "manual-attestation" {
		procedure = "commissioning-v1"
	}
	report["evidence"] = append(list(report["evidence"]), M{"check": check, "status": status, "type": typ,
		"contextDigest": digestJSON(ctx), "time": int(now()), "boot": commissioningBoot(), "procedure": procedure})
	return validateReport(report)
}

func collectEvidence(report, ctx, settings M) error {
	probes := []struct {
		name string
		fn   func() (bool, error)
	}{
		{"clock", func() (bool, error) {
			switch str(clockStatus(now())["state"]) {
			case "synchronized":
				return true, nil
			case "invalid-clock":
				return false, nil
			}
			return false, Public("Clock synchronization is not confirmed")
		}},
		{"management", func() (bool, error) {
			result, err := probe(settings)
			if err != nil || !isTrue(result["ok"]) {
				return false, err
			}
			out, err := probeCommand("systemctl", "is-active", "incus.service", "nixus-instances.service", "nixus-management-health.service")
			return err == nil && out == "active\nactive\nactive", err
		}},
		{"kvm", func() (bool, error) {
			f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
			if err != nil {
				return false, err
			}
			defer f.Close()
			v, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), 0xAE00, 0)
			if errno != 0 {
				return false, errno
			}
			return v == 12, nil
		}},
		{"container", func() (bool, error) {
			out, err := probeCommand("incus", "--force-local", "list", "--all-projects", "--format=json")
			if err != nil {
				return false, err
			}
			guests, err := parseJSON([]byte(out))
			if err != nil {
				return false, err
			}
			for _, raw := range list(guests) {
				g := obj(raw)
				config := obj(g["expanded_config"])
				if _, ok := g["expanded_config"]; !ok {
					config = obj(g["config"])
				}
				if str(g["type"]) == "container" && str(g["status"]) == "Running" && str(config["security.privileged"]) != "true" {
					return true, nil
				}
			}
			return false, nil
		}},
	}
	for _, p := range probes {
		ok, err := p.fn()
		status := "failed"
		switch {
		case err != nil && os.IsNotExist(err):
			status = "unsupported"
		case err != nil:
			status = "unknown"
		case ok:
			status = "passed"
		}
		if err := recordEvidence(report, ctx, p.name, status, "automated-probe"); err != nil {
			return err
		}
	}
	return nil
}

func summarizeEvidence(report, current M, revision string) (M, error) {
	if err := validateReport(report); err != nil {
		return nil, err
	}
	at := now()
	ctx := current
	if ctx == nil {
		ctx = obj(report["context"])
	}
	fingerprint := digestJSON(ctx)
	evidence := list(report["evidence"])
	rows := []any{}
	allPassed := true
	for _, c := range commissioningChecks {
		check := c[0]
		required := !(check == "hardware-reconnect" && !isTrue(ctx["hardwareDevices"]))
		var latest M
		for _, e := range evidence {
			if str(obj(e)["check"]) == check {
				latest = obj(e)
			}
		}
		status := "unknown"
		if latest != nil {
			t, _ := num(latest["time"])
			if str(latest["contextDigest"]) != fingerprint || at-t < 0 || at-t > commissioningMaxAge {
				status = "stale"
			} else {
				status = str(latest["status"])
			}
		} else if !required {
			status = "skipped"
		}
		if check == "reboots" && status == "passed" {
			boots := map[string]bool{}
			for _, raw := range evidence {
				e := obj(raw)
				t, _ := num(e["time"])
				if str(e["check"]) == "management" && str(e["status"]) == "passed" && str(e["contextDigest"]) == fingerprint &&
					str(e["boot"]) != "unknown" && at-t >= 0 && at-t <= commissioningMaxAge {
					boots[str(e["boot"])] = true
				}
			}
			if len(boots) < 3 {
				status = "unknown"
			}
		}
		var typ, observed any
		if latest != nil {
			typ, observed = latest["type"], latest["time"]
		}
		rows = append(rows, M{"check": check, "title": c[1], "required": required, "status": status, "evidenceType": typ, "observedAt": observed})
		if required && status != "passed" {
			allPassed = false
		}
	}
	eligible := str(ctx["scope"]) == "physical-host" && str(ctx["environment"]) == "installed-host" && str(ctx["architecture"]) == "x86_64" &&
		str(ctx["revision"]) != "unknown" && str(ctx["system"]) != "unknown" && str(ctx["incus"]) != "unknown" &&
		(revision == "" || str(ctx["revision"]) == revision) && allPassed
	qualification := "unqualified"
	if eligible {
		qualification = "ready-for-review"
	}
	return M{"format": 1, "revision": ctx["revision"], "mode": ctx["mode"], "scope": ctx["scope"], "environment": ctx["environment"],
		"profile": "core", "qualification": qualification, "checks": rows}, nil
}

func loadReport(p string) (M, error) {
	info, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if info.Size() > 2<<20 {
		return nil, Public("Oversized report")
	}
	raw, _ := os.ReadFile(p)
	report, err := parseObject(raw)
	if err != nil {
		return nil, Public("Unsupported commissioning report")
	}
	return report, validateReport(report)
}

func evidenceMatrix(paths []string, revision string) (string, error) {
	if !fullmatch(sha40, revision) {
		return "", Public("Use a full release revision")
	}
	lines := []string{"# Single-host qualification evidence", "", "Source revision: `" + revision + "`.", "",
		"Reports are operator evidence, not a security certification. Ready-for-review still requires release review.", "",
		"| Target fingerprint | Mode | Profile | Scope | Environment | Evidence |", "|---|---|---|---|---|---|"}
	for _, p := range paths {
		report, err := loadReport(p)
		if err != nil {
			return "", err
		}
		summary, err := summarizeEvidence(report, nil, revision)
		if err != nil {
			return "", err
		}
		lines = append(lines, "| "+strings.Join([]string{str(jget(report, "context", "hardwareDigest"))[:12], str(summary["mode"]),
			str(summary["profile"]), str(summary["scope"]), str(summary["environment"]), str(summary["qualification"])}, " | ")+" |")
	}
	if len(paths) == 0 {
		lines = append(lines, "| No submitted evidence | — | — | — | — | unqualified |")
	}
	return strings.Join(lines, "\n") + "\n", nil
}

func commissioningRun(action, mode, environment, check, status string, acknowledge bool) (any, error) {
	if os.Geteuid() != 0 {
		return nil, Public("Use sudo for local commissioning evidence")
	}
	if action == "record" && !acknowledge {
		return nil, Public("Perform the commissioning procedure first, then use --acknowledge to record an operator attestation")
	}
	if action == "record" && (automaticChecks[check] || !isCheck(check) || !evidenceStatuses[status]) {
		return nil, Public("Invalid check, status or evidence type")
	}
	settingsRaw, err := readJSON("/etc/nixus/effective-settings.json", nil)
	settings := obj(settingsRaw)
	if err != nil || settings == nil {
		return nil, Public("Install and activate Nixus before commissioning")
	}
	ctx := commissioningContext(settings, mode, environment)
	directory := filepath.Join(STATE, "commissioning")
	os.MkdirAll(directory, 0o700)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, Public("Commissioning directory must be root-owned, mode 0700")
	}
	release, err := lockFile(filepath.Join(directory, "report.lock"), true)
	if err != nil {
		return nil, err
	}
	defer release()
	p := filepath.Join(directory, environment+"-"+mode+".json")
	if isSymlink(p) {
		return nil, Public("Report cannot be a symlink")
	}
	report := M{"format": 1, "context": ctx, "evidence": []any{}}
	if exists(p) {
		if report, err = loadReport(p); err != nil {
			return nil, err
		}
	}
	switch action {
	case "collect":
		err = collectEvidence(report, ctx, settings)
	case "record":
		err = recordEvidence(report, ctx, check, status, "manual-attestation")
	case "export":
		report["context"] = ctx
		return report, validateReport(report)
	}
	if err != nil {
		return nil, err
	}
	if action == "collect" || action == "record" {
		if err := writeJSON(p, report); err != nil {
			return nil, err
		}
	}
	return summarizeEvidence(report, ctx, "")
}
