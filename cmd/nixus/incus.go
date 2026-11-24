package main

// Local Incus access: the unix-socket API client, the small ownership-aware
// instance reconciler, the source-owned infrastructure drift guard and the
// sanitized guest network inventory. No shell interpolation or deletion.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const OWNER = "user.nixus.managed"
const INITIALIZING = "user.nixus.initializing"
const LAST_APPLIED = "user.nixus.last-applied"
const incusSocket = "/var/lib/incus/unix.socket"
const infrastructureState = "/var/lib/nixus/infrastructure.json"

func incusHTTP(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", incusSocket)
		}}}
}

// incusAPI performs one local API request and returns the decoded payload.
func incusAPI(method, p string, data any, etag string, timeout time.Duration, maxBytes int64) (M, string, int, error) {
	var body io.Reader
	if data != nil {
		raw, _ := json.Marshal(data)
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, "http://incus"+p, body)
	if err != nil {
		return nil, "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if etag != "" {
		req.Header.Set("If-Match", etag)
	}
	resp, err := incusHTTP(timeout).Do(req)
	if err != nil {
		return nil, "", 0, err
	}
	defer resp.Body.Close()
	if maxBytes <= 0 {
		maxBytes = 64 << 20
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, "", resp.StatusCode, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, "", resp.StatusCode, Hidden("Inventory exceeds size limit")
	}
	payload, err := parseObject(raw)
	if err != nil {
		return nil, "", resp.StatusCode, Hidden("Invalid Incus response")
	}
	return payload, resp.Header.Get("ETag"), resp.StatusCode, nil
}

func reconcileAPI(method, p string, data any, etag string) (M, string, error) {
	payload, tag, status, err := incusAPI(method, p, data, etag, 120*time.Second, 0)
	if err != nil {
		return nil, "", err
	}
	if status >= 400 || str(payload["type"]) == "error" {
		return nil, "", Hidden(fmt.Sprintf("Incus API request failed: HTTP %d", status))
	}
	return payload, tag, nil
}

func instancePath(project, name string) string {
	return "/1.0/instances/" + url.PathEscape(name) + "?project=" + url.QueryEscape(project)
}

func readInstance(project, name string) (M, string, error) {
	payload, etag, err := reconcileAPI("GET", instancePath(project, name), nil, "")
	if err != nil {
		return nil, "", err
	}
	if etag == "" {
		return nil, "", Hidden("Incus did not return an ETag; refusing unsafe update")
	}
	return obj(payload["metadata"]), etag, nil
}

func writeInstance(project, name string, data M, etag string) error {
	payload, _, err := reconcileAPI("PUT", instancePath(project, name), data, etag)
	if err != nil {
		return err
	}
	return waitOperation(payload)
}

// waitOperation blocks until an async Incus response's operation finishes,
// directly over the local unix socket without spawning the incus CLI.
func waitOperation(payload M) error {
	if str(payload["type"]) != "async" {
		return nil
	}
	op, err := url.Parse(str(payload["operation"]))
	if err != nil || op.Host != "" || !strings.HasPrefix(op.Path, "/1.0/operations/") {
		return Hidden("Invalid Incus operation path")
	}
	wait := op.Path + "/wait"
	if op.RawQuery != "" {
		wait += "?" + op.RawQuery
	}
	resp, _, status, err := incusAPI("GET", wait, nil, "", 30*time.Minute, 0)
	if err != nil {
		return err
	}
	if status >= 400 || str(resp["type"]) == "error" {
		return Hidden("Incus configuration operation failed")
	}
	md := obj(resp["metadata"])
	if v, _ := num(md["status_code"]); v != 200 {
		return Hidden("Incus configuration operation failed")
	}
	return nil
}

func desiredState(spec M) (M, error) {
	config := cloneM(obj(spec["config"]))
	if config == nil {
		config = M{}
	}
	for k := range config {
		if strings.HasPrefix(k, "volatile.") || k == INITIALIZING || k == LAST_APPLIED {
			return nil, Public("Incus volatile and Nixus state keys are reserved")
		}
	}
	delete(config, OWNER)
	devices := cloneM(obj(spec["devices"]))
	if devices == nil {
		devices = M{}
	}
	profiles, ok := spec["profiles"]
	if !ok {
		profiles = []any{"base"}
	}
	return M{"version": 1, "config": config, "devices": devices, "profiles": clone(profiles)}, nil
}

type missingT struct{}

var missing = missingT{}

func getOr(m M, k string) any {
	if v, ok := m[k]; ok {
		return v
	}
	return missing
}

func mergeFields(current, previous, desired M, location string) (M, error) {
	result := cloneM(current)
	if result == nil {
		result = M{}
	}
	all := map[string]bool{}
	for k := range previous {
		all[k] = true
	}
	for k := range desired {
		all[k] = true
	}
	for k := range all {
		before, wanted, actual := getOr(previous, k), getOr(desired, k), getOr(current, k)
		if before != missing && !sameValue(actual, before) && !sameValue(actual, wanted) {
			return nil, Public("Runtime drift at " + location + "." + k + "; resolve before rebuilding")
		}
		if wanted == missing {
			delete(result, k)
		} else {
			result[k] = clone(wanted)
		}
	}
	return result, nil
}

func sameValue(a, b any) bool {
	if a == missing || b == missing {
		return a == b
	}
	return equalJSON(a, b)
}

func reconcilePlan(current, spec M) (M, error) {
	if str(jget(current, "config", OWNER)) != "true" {
		return nil, Public("Refusing to modify unowned instance " + str(spec["name"]))
	}
	if str(current["type"]) != str(spec["type"]) {
		return nil, Public("Instance type is immutable; migrate explicitly")
	}
	if v, ok := obj(spec["config"])[OWNER]; ok && str(v) != "true" {
		return nil, Public("The Nixus ownership marker cannot be removed by reconciliation")
	}
	desired, err := desiredState(spec)
	if err != nil {
		return nil, err
	}
	old := M{}
	if raw := str(jget(current, "config", LAST_APPLIED)); raw != "" {
		if old, err = parseObject([]byte(raw)); err != nil {
			return nil, Public("Invalid previous Incus ownership metadata")
		}
	}
	if len(old) > 0 {
		if v, _ := num(old["version"]); v != 1 {
			return nil, Public("Unsupported last-applied ownership version")
		}
	}
	if isTrue(spec["manageExistingOnly"]) && len(old) > 0 {
		desired = cloneM(old)
		for k, v := range obj(spec["config"]) {
			obj(desired["config"])[k] = v
		}
		for k, v := range obj(spec["devices"]) {
			obj(desired["devices"])[k] = v
		}
		if p, ok := spec["profiles"]; ok {
			desired["profiles"] = p
		}
	}
	writable := M{}
	for _, k := range []string{"architecture", "config", "devices", "ephemeral", "profiles", "description"} {
		if v, ok := current[k]; ok {
			writable[k] = clone(v)
		}
	}
	result := cloneM(writable)
	if result["config"], err = mergeFields(obj(current["config"]), obj(old["config"]), obj(desired["config"]), "config"); err != nil {
		return nil, err
	}
	devices := cloneM(obj(current["devices"]))
	if devices == nil {
		devices = M{}
	}
	names := map[string]bool{}
	for k := range obj(old["devices"]) {
		names[k] = true
	}
	for k := range obj(desired["devices"]) {
		names[k] = true
	}
	for name := range names {
		previous := obj(obj(old["devices"])[name])
		wanted := obj(obj(desired["devices"])[name])
		if wanted == nil {
			return nil, Public("Device removal requires explicit migration: " + name)
		}
		actual := obj(devices[name])
		if len(previous) > 0 && len(actual) == 0 {
			return nil, Public("Runtime drift: owned device removed: " + name)
		}
		for _, k := range []string{"type", "pool", "source", "path"} {
			a, aok := actual[k]
			w, wok := wanted[k]
			if aok && wok && !equalJSON(a, w) {
				return nil, Public("Device backing change requires explicit migration: " + name + "." + k)
			}
		}
		if devices[name], err = mergeFields(actual, previous, wanted, "devices."+name); err != nil {
			return nil, err
		}
	}
	result["devices"] = devices
	currentProfiles := current["profiles"]
	if currentProfiles == nil {
		currentProfiles = []any{}
	}
	if p, ok := old["profiles"]; ok && !equalJSON(currentProfiles, p) && !equalJSON(currentProfiles, desired["profiles"]) {
		return nil, Public("Runtime drift at profiles")
	}
	result["profiles"] = desired["profiles"]
	obj(result["config"])[LAST_APPLIED] = canonical(desired)
	if equalJSON(result, writable) {
		return nil, nil
	}
	return result, nil
}

var incusIdent = re(`[a-zA-Z0-9][a-zA-Z0-9_.-]*`)

// --- source-owned infrastructure drift guard ------------------------------

type infraObject struct {
	identity, path string
	declaration    M
}

func infraStable(value M) M {
	out := M{}
	for k, v := range value {
		switch k {
		case "config":
			config := M{}
			for ck, cv := range obj(v) {
				if !strings.HasPrefix(ck, "volatile.") {
					config[ck] = cv
				}
			}
			out[k] = config
		case "devices", "driver", "type", "description", "ingress", "egress":
			out[k] = v
		}
	}
	return out
}

func infraObjects(preseed M) []infraObject {
	var out []infraObject
	for _, pair := range [][2]string{{"storage_pools", "storage-pools"}, {"network_acls", "network-acls"}, {"networks", "networks"}, {"projects", "projects"}, {"profiles", "profiles"}} {
		for _, raw := range list(preseed[pair[0]]) {
			item := obj(raw)
			project := "default"
			if p, ok := item["project"]; ok {
				project = str(p)
			}
			p := "/1.0/" + pair[1] + "/" + url.PathEscape(str(item["name"]))
			if pair[0] == "profiles" {
				p += "?project=" + url.QueryEscape(project)
			}
			out = append(out, infraObject{pair[0] + ":" + project + "/" + str(item["name"]), p, infraStable(item)})
		}
	}
	return out
}

func infraConflicts(preseed, previous M, observed map[string]M) []string {
	var result []string
	objects := obj(previous["objects"])
	declarations := obj(previous["declarations"])
	for _, o := range infraObjects(preseed) {
		current, has := observed[o.identity]
		if !has {
			current = nil
		}
		if _, known := objects[o.identity]; !known {
			if current == nil {
				continue
			}
			actual := infraStable(current)
			matches := true
			for key, wanted := range o.declaration {
				if wm, ok := wanted.(M); ok {
					am := obj(actual[key])
					for k, v := range wm {
						if !equalJSON(am[k], v) {
							matches = false
						}
					}
				} else if !equalJSON(actual[key], wanted) {
					matches = false
				}
			}
			if matches {
				continue
			}
		} else {
			actual := infraStable(current)
			old := obj(objects[o.identity])
			if equalJSON(actual, old) {
				continue
			}
			expected := cloneM(old)
			for key, wanted := range o.declaration {
				if wm, ok := wanted.(M); ok {
					target := obj(expected[key])
					if target == nil {
						target = M{}
					}
					for removed := range obj(obj(declarations[o.identity])[key]) {
						if _, still := wm[removed]; !still {
							delete(target, removed)
						}
					}
					for k, v := range wm {
						target[k] = v
					}
					expected[key] = target
				} else {
					expected[key] = wanted
				}
			}
			if equalJSON(actual, expected) {
				continue
			}
		}
		_, known := objects[o.identity]
		if current != nil || known {
			result = append(result, o.identity)
		}
	}
	return result
}

func infraQuery(p string, missingOK bool) (M, error) {
	payload, _, status, err := incusAPI("GET", p, nil, "", 30*time.Second, 0)
	if err != nil {
		return nil, Hidden("Cannot inspect Incus infrastructure: " + err.Error())
	}
	if status == 404 && missingOK {
		return nil, nil
	}
	if status >= 400 || str(payload["type"]) == "error" {
		return nil, Hidden(fmt.Sprintf("Cannot inspect Incus infrastructure: HTTP %d", status))
	}
	return obj(payload["metadata"]), nil
}

func infraCheck(preseed M) error {
	previous := M{"objects": M{}, "declarations": M{}}
	if isFile(infrastructureState) {
		previous = readObj(infrastructureState)
	}
	observed := map[string]M{}
	for _, o := range infraObjects(preseed) {
		v, err := infraQuery(o.path, true)
		if err != nil {
			return err
		}
		if v != nil {
			observed[o.identity] = v
		}
	}
	if drift := infraConflicts(preseed, previous, observed); len(drift) > 0 {
		return Public("Incus drift in source-owned infrastructure: " + drift[0] +
			". Restore the declared object in Incus or review its Nix declaration; refusing to reset native edits.")
	}
	return nil
}

func infraRecord(preseed M) error {
	values := M{"objects": M{}, "declarations": M{}}
	for _, o := range infraObjects(preseed) {
		v, err := infraQuery(o.path, false)
		if err != nil {
			return err
		}
		obj(values["objects"])[o.identity] = infraStable(v)
		obj(values["declarations"])[o.identity] = o.declaration
	}
	return atomic(infrastructureState, jsonFile(values), 0o600, "")
}

// --- guest network inventory ------------------------------------------------

func guestQuery(p string) ([]any, error) {
	raw, err := incusRun([]string{"query", p}, 10*time.Second, 1024)
	if err != nil {
		return nil, err
	}
	if len(raw) > 8<<20 {
		return nil, Public("Incus inventory exceeds the console limit")
	}
	v, err := parseJSON([]byte(raw))
	l, ok := v.([]any)
	if err != nil || !ok || len(l) > 1000 {
		return nil, Public("Incus inventory exceeds the console limit")
	}
	return l, nil
}

func guestAddress(v any) string {
	a, err := netip.ParseAddr(str(v))
	if err != nil || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return ""
	}
	return a.String()
}

func guestAddresses(network M) []string {
	set := map[string]bool{}
	for _, e := range list(network["addresses"]) {
		entry := obj(e)
		if str(entry["scope"]) == "global" {
			if ip := guestAddress(entry["address"]); ip != "" {
				set[ip] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

func hostBridgePorts(root string) map[string]string {
	ports := map[string]string{}
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		master, err := filepath.EvalSymlinks(filepath.Join(root, e.Name(), "master"))
		if err != nil {
			continue
		}
		if isDir(filepath.Join(master, "bridge")) {
			ports[e.Name()] = filepath.Base(master)
		}
	}
	return ports
}

func macvlanBridge(device M, ports map[string]string) string {
	if str(device["type"]) == "nic" && str(device["nictype"]) == "macvlan" && str(device["attached"]) != "false" {
		return ports[str(device["parent"])]
	}
	return ""
}

func nicObservation(device, observed M, reported []string, running bool, ports map[string]string) M {
	if str(device["attached"]) == "false" {
		return M{"linkState": "disabled"}
	}
	result := M{"linkState": "unknown"}
	if bridge := macvlanBridge(device, ports); bridge != "" {
		result["bridgeConflict"] = M{"port": device["parent"], "bridge": bridge}
	}
	if !running {
		result["linkState"] = "stopped"
	} else if observed != nil {
		state := strings.ToLower(str(observed["state"]))
		if state == "up" || state == "down" {
			result["linkState"] = state
		}
		nictype := str(device["nictype"])
		if state == "up" && (nictype == "bridged" || nictype == "macvlan") && str(device["parent"]) != "" && str(device["network"]) == "" {
			v4 := false
			for _, ip := range reported {
				if a, err := netip.ParseAddr(ip); err == nil && a.Is4() {
					v4 = true
				}
			}
			result["lanIPv4Missing"] = !v4
		}
	}
	return result
}

func summarizeGuests(instances, projects []any, at float64, ports map[string]string) M {
	if ports == nil {
		ports = map[string]string{}
	}
	namespaces := map[string]string{}
	for _, p := range projects {
		pm := obj(p)
		ns := "default"
		if str(jget(pm, "config", "features.networks")) == "true" {
			ns = str(pm["name"])
		}
		namespaces[str(pm["name"])] = ns
	}
	guests := []any{}
	owners := map[string]map[string]bool{}
	for _, raw := range instances {
		guest := obj(raw)
		project := "default"
		if p, ok := guest["project"]; ok {
			project = str(p)
		}
		running := str(guest["status"]) == "Running"
		networks := M{}
		if running {
			networks = obj(jget(guest, "state", "network"))
		}
		config := obj(guest["expanded_config"])
		if config == nil {
			config = obj(guest["config"])
		}
		devices := obj(guest["expanded_devices"])
		if devices == nil {
			devices = obj(guest["devices"])
		}
		nics := []any{}
		observedAll := map[string]bool{}
		for _, key := range keys(devices) {
			device := obj(devices[key])
			if str(device["type"]) != "nic" {
				continue
			}
			nicName := key
			if n, ok := device["name"]; ok {
				nicName = str(n)
			}
			observed := obj(networks[nicName])
			mac := str(device["hwaddr"])
			if mac == "" {
				mac = str(config["volatile."+key+".hwaddr"])
			}
			if observed == nil && mac != "" {
				for _, n := range networks {
					if strings.EqualFold(str(obj(n)["hwaddr"]), mac) {
						observed = obj(n)
						break
					}
				}
			}
			attached := str(device["attached"]) != "false"
			reported := []string{}
			if attached {
				reported = guestAddresses(observed)
			}
			reservedSet := map[string]bool{}
			for _, f := range []string{"ipv4.address", "ipv6.address"} {
				if ip := guestAddress(device[f]); ip != "" {
					reservedSet[ip] = true
				}
			}
			var reserved []string
			for ip := range reservedSet {
				reserved = append(reserved, ip)
			}
			sort.Strings(reserved)
			unobserved := false
			if len(reported) > 0 {
				seen := map[string]bool{}
				for _, ip := range reported {
					seen[ip] = true
				}
				for _, ip := range reserved {
					if !seen[ip] {
						unobserved = true
					}
				}
			}
			network := str(device["network"])
			label := network
			if label == "" {
				label = str(device["parent"])
			}
			if label == "" {
				label = "Unmanaged"
			}
			source := "unknown"
			if _, ok := obj(guest["devices"])[key]; ok {
				source = "instance"
			} else if _, ok := guest["devices"]; ok {
				source = "profile"
			}
			nic := M{"name": key, "network": label, "observed": strings2any(reported), "reserved": strings2any(nonNil(reserved)),
				"unobservedReservation": unobserved, "deviceSource": source}
			for k, v := range nicObservation(device, observed, reported, running, ports) {
				nic[k] = v
			}
			nics = append(nics, nic)
			for _, ip := range reported {
				observedAll[ip] = true
			}
			if _, known := namespaces[project]; attached && network != "" && known {
				for _, ip := range append(append([]string{}, reported...), reserved...) {
					identity := namespaces[project] + "\x00" + network + "\x00" + ip
					if owners[identity] == nil {
						owners[identity] = map[string]bool{}
					}
					owners[identity][project+"/"+str(guest["name"])+"/"+key] = true
				}
			}
		}
		observedList := make([]string, 0, len(observedAll))
		for ip := range observedAll {
			observedList = append(observedList, ip)
		}
		sort.Strings(observedList)
		kind, status := str(guest["type"]), str(guest["status"])
		if kind == "" {
			kind = "unknown"
		}
		if status == "" {
			status = "Unknown"
		}
		guests = append(guests, M{"project": project, "name": guest["name"], "type": kind, "status": status,
			"nics": nics, "observed": strings2any(observedList)})
	}
	sort.Slice(guests, func(i, j int) bool {
		a, b := obj(guests[i]), obj(guests[j])
		if str(a["project"]) != str(b["project"]) {
			return str(a["project"]) < str(b["project"])
		}
		return str(a["name"]) < str(b["name"])
	})
	identities := make([]string, 0, len(owners))
	for k := range owners {
		identities = append(identities, k)
	}
	sort.Strings(identities)
	conflicts := []any{}
	for _, identity := range identities {
		members := owners[identity]
		if len(members) < 2 {
			continue
		}
		parts := strings.Split(identity, "\x00")
		var names []string
		for m := range members {
			names = append(names, m)
		}
		sort.Strings(names)
		conflicts = append(conflicts, M{"project": parts[0], "network": parts[1], "address": parts[2], "owners": strings2any(names)})
	}
	if at == 0 {
		at = now()
	}
	return M{"available": true, "checkedAt": int64(at), "guests": guests, "conflicts": conflicts}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func guestNetworkInventory() (M, error) {
	fail := Public("Guest network inventory unavailable; check Incus and refresh.")
	instances, err := guestQuery("/1.0/instances?recursion=2&all-projects=true")
	if err != nil {
		return nil, fail
	}
	projects, err := guestQuery("/1.0/projects?recursion=1")
	if err != nil {
		return nil, fail
	}
	ports := hostBridgePorts("/sys/class/net")
	result := summarizeGuests(instances, projects, 0, ports)
	result["bridgeTopologyAvailable"] = true
	return result, nil
}
