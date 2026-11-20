package main

// Typed settings, read-only host inventory and the shared foundation/network
// preflight validators. No evaluation of user supplied code.

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

var FILESYSTEMS = map[string]bool{"ext4": true, "xfs": true, "btrfs": true, "vfat": true, "exfat": true, "ntfs3": true}
var MOUNT_ROLES = map[string]bool{"data": true, "guests": true, "pool": true, "backup": true}

// command runs argv and hides child diagnostics, which can echo secrets.
func command(argv []string, timeout time.Duration) (string, error) {
	if timeout == 0 {
		timeout = 20 * time.Second
	}
	res, err := run(argv, nil, timeout, nil, "")
	if err != nil || res.Code != 0 {
		return "", Public("Host command failed")
	}
	return string(res.Stdout), nil
}

func readCommandJSON(argv []string, fallback any) any {
	out, err := command(argv, 0)
	if err != nil {
		return fallback
	}
	v, err := parseJSON([]byte(out))
	if err != nil {
		return fallback
	}
	return v
}

func hostInventory() M {
	interfaces := []any{}
	for _, raw := range list(readCommandJSON([]string{"ip", "-j", "-d", "address", "show"}, []any{})) {
		link := obj(raw)
		name := str(link["ifname"])
		if name == "lo" || name == "" {
			continue
		}
		kind := str(jget(link, "linkinfo", "info_kind"))
		if kind == "" {
			kind = "ethernet"
		}
		driver := ""
		if target, err := filepath.EvalSymlinks(filepath.Join("/sys/class/net", name, "device/driver")); err == nil {
			driver = filepath.Base(target)
		}
		addresses := []any{}
		for _, a := range list(link["addr_info"]) {
			addr := obj(a)
			if str(addr["family"]) == "inet" {
				prefix, _ := num(addr["prefixlen"])
				addresses = append(addresses, fmt.Sprintf("%s/%d", str(addr["local"]), int(prefix)))
			}
		}
		interfaces = append(interfaces, M{"name": name, "state": str(link["operstate"]), "kind": kind, "driver": driver,
			"wireless": exists(filepath.Join("/sys/class/net", name, "wireless")), "addresses": addresses})
	}
	disks := obj(readCommandJSON([]string{"lsblk", "--json", "--bytes", "--output",
		"NAME,PATH,TYPE,SIZE,FSTYPE,UUID,LABEL,MOUNTPOINTS,ROTA,TRAN"}, M{"blockdevices": []any{}}))
	cpu, _ := os.ReadFile("/proc/cpuinfo")
	vendor := ""
	if strings.Contains(string(cpu), "AuthenticAMD") {
		vendor = "amd"
	} else if strings.Contains(string(cpu), "GenuineIntel") {
		vendor = "intel"
	}
	arch, _ := command([]string{"uname", "-m"}, 0)
	blocks := list(disks["blockdevices"])
	if blocks == nil {
		blocks = []any{}
	}
	return M{"interfaces": interfaces, "routes": readCommandJSON([]string{"ip", "-j", "-4", "route", "show"}, []any{}),
		"disks": blocks, "cpuVendor": vendor, "architecture": strings.TrimSpace(arch), "kvm": exists("/dev/kvm"),
		"uefi": exists("/sys/firmware/efi"), "serialDevices": serialInventory("/sys/class/tty", "/dev")}
}

func readTrim(p string) string {
	raw, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func serialInventory(root, dev string) []any {
	result := []any{}
	entries, _ := os.ReadDir(root)
	for _, entry := range entries {
		device := filepath.Join(root, entry.Name(), "device")
		resolved, err := filepath.EvalSymlinks(device)
		if err != nil {
			continue
		}
		var chain []string
		for p := resolved; p != "/" && p != "."; p = filepath.Dir(p) {
			chain = append(chain, p)
		}
		usb := ""
		for _, p := range chain {
			if isFile(filepath.Join(p, "idVendor")) && isFile(filepath.Join(p, "idProduct")) {
				usb = p
				break
			}
		}
		if usb == "" {
			continue
		}
		devPath := filepath.Join(dev, entry.Name())
		target, _ := filepath.EvalSymlinks(devPath)
		stable := []any{}
		for _, folder := range []string{"serial/by-id", "nixus"} {
			links, _ := filepath.Glob(filepath.Join(dev, folder, "*"))
			for _, l := range links {
				if r, err := filepath.EvalSymlinks(l); err == nil && r == target {
					stable = append(stable, l)
				}
			}
		}
		driver := ""
		for _, p := range chain {
			if d, err := filepath.EvalSymlinks(filepath.Join(p, "driver")); err == nil {
				driver = filepath.Base(d)
				break
			}
		}
		result = append(result, M{"path": devPath, "vendorId": readTrim(filepath.Join(usb, "idVendor")),
			"productId": readTrim(filepath.Join(usb, "idProduct")), "serial": readTrim(filepath.Join(usb, "serial")),
			"product": readTrim(filepath.Join(usb, "product")), "stablePaths": stable, "driver": driver})
	}
	return result
}

func flattenDisks(devices []any) []M {
	var out []M
	for _, d := range devices {
		m := obj(d)
		if m == nil {
			continue
		}
		out = append(out, m)
		out = append(out, flattenDisks(list(m["children"]))...)
	}
	return out
}

// mergeSettings deep-merges b over a (objects recursively, all else replaced).
func mergeSettings(a, b M) M {
	result := cloneM(a)
	if result == nil {
		result = M{}
	}
	for k, v := range b {
		if vm, ok := v.(M); ok {
			if rm, ok := result[k].(M); ok {
				result[k] = mergeSettings(rm, vm)
				continue
			}
		}
		result[k] = clone(v)
	}
	return result
}

func jsonKind(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return "bool"
	case string:
		return "str"
	case float64:
		if x == float64(int64(x)) {
			return "int"
		}
		return "float"
	case json.Number:
		if _, err := x.Int64(); err == nil {
			return "int"
		}
		return "float"
	case int, int64:
		return "int"
	case []any:
		return "list"
	case M:
		return "dict"
	}
	return fmt.Sprintf("%T", v)
}

func checkShape(value, template any, location string) error {
	if location == "settings.tunnel.ingress" {
		m, ok := value.(M)
		if !ok {
			return Public("Ingress must map hostnames to endpoint strings")
		}
		for _, v := range m {
			if !isStr(v) {
				return Public("Ingress must map hostnames to endpoint strings")
			}
		}
		return nil
	}
	switch t := template.(type) {
	case M:
		m, ok := value.(M)
		if !ok {
			return Public(location + " must be an object")
		}
		for _, k := range keys(m) {
			child, known := t[k]
			if !known {
				return Public("Unknown setting: " + location + "." + k)
			}
			if err := checkShape(m[k], child, location+"."+k); err != nil {
				return err
			}
		}
	case []any:
		if _, ok := value.([]any); !ok {
			return Public(location + " must be a list")
		}
	default:
		if jsonKind(value) != jsonKind(template) {
			return Public(location + " has an invalid type")
		}
	}
	return nil
}

var hostName = re(`[a-zA-Z0-9][a-zA-Z0-9-]{0,62}`)

func parseAddr(v any) (netip.Addr, error) {
	a, err := netip.ParseAddr(str(v))
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, Public("Invalid IP address")
	}
	return a, nil
}

// parseNetwork mirrors ipaddress.ip_network(strict=True).
func parseNetwork(v any) (netip.Prefix, error) {
	s := str(v)
	if !strings.Contains(s, "/") {
		a, err := parseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil || p.Masked() != p {
		return netip.Prefix{}, Public("Invalid network")
	}
	return p, nil
}

func intValue(v any) (int, bool) {
	if jsonKind(v) != "int" {
		return 0, false
	}
	f, _ := num(v)
	return int(f), true
}

func validateBootstrap(settings, host M) error {
	if isTrue(settings["ready"]) || isTrue(jget(settings, "management", "configure")) || !isTrue(jget(settings, "setup", "enable")) {
		return Public("Initial onboarding must preserve networking and keep the portal enabled on an unconfigured host")
	}
	for _, section := range []string{"cockpit", "backup", "tunnel"} {
		if isTrue(jget(settings, section, "enable")) {
			return Public("Initial onboarding cannot activate optional host services or mounts; use the full guarded installer")
		}
	}
	if len(list(settings["mounts"])) > 0 {
		return Public("Initial onboarding cannot activate optional host services or mounts; use the full guarded installer")
	}
	if str(settings["system"]) != str(host["architecture"])+"-linux" || str(settings["cpuVendor"]) != str(host["cpuVendor"]) {
		return Public("Bootstrap inventory does not match this host")
	}
	if !fullmatch(hostName, str(settings["hostName"])) {
		return Public("Use a valid host name")
	}
	management := obj(settings["management"])
	address, err := parseAddr(management["address"])
	if err != nil || !address.Is4() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified() || address.IsMulticast() {
		return Public("Initial onboarding needs a usable IPv4 management address")
	}
	addressed := false
	for _, l := range list(host["interfaces"]) {
		if str(obj(l)["name"]) == str(management["interface"]) && len(list(obj(l)["addresses"])) > 0 {
			addressed = true
		}
	}
	if !addressed {
		return Public("Initial onboarding needs an addressed management interface")
	}
	cidrs := list(management["trustedCIDRs"])
	if len(cidrs) == 0 {
		return Public("Configure trusted IPv4 management sources")
	}
	for _, c := range cidrs {
		if n, err := parseNetwork(c); err != nil || !n.Addr().Is4() {
			return Public("Configure trusted IPv4 management sources")
		}
	}
	port, ok := intValue(jget(settings, "setup", "port"))
	if !ok || port < 1024 || port > 65535 || port == 8080 || port == 8443 || port == 9090 || port == 9091 || port == 9100 {
		return Public("Choose an unused portal management port")
	}
	deadline, ok := intValue(jget(settings, "setup", "confirmationSeconds"))
	if !ok || deadline < 300 || deadline > 1800 {
		return Public("Activation confirmation must allow 5–30 minutes")
	}
	return nil
}

var sshKey = re(`(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh.com) [A-Za-z0-9+/=]+(?: [^\r\n]*)?`)
var incusName = re(`[a-z][a-z0-9-]{0,14}`)
var timeZone = re(`[A-Za-z0-9_+.-]+(?:/[A-Za-z0-9_+.-]+)*`)
var mountName = re(`[a-z][a-z0-9-]{0,31}`)
var mountUUID = re(`[A-Za-z0-9-]{4,80}`)

func validateSettings(candidate, current, host M, requireDevices bool) (M, error) {
	if err := checkShape(candidate, current, "settings"); err != nil {
		return nil, err
	}
	for _, field := range []string{"instances", "secrets", "system", "schemaVersion"} {
		if !equalJSON(candidate[field], current[field]) {
			return nil, Public(field + " is managed in the source repository")
		}
	}
	if !fullmatch(hostName, str(candidate["hostName"])) {
		return nil, Public("Use a valid host name")
	}
	if str(candidate["system"]) != str(host["architecture"])+"-linux" {
		return nil, Public("This installer supports the detected Linux architecture only")
	}
	vendor := str(candidate["cpuVendor"])
	if vendor != str(host["cpuVendor"]) || (vendor != "intel" && vendor != "amd") {
		return nil, Public("CPU vendor must match the detected Intel/AMD host")
	}
	for _, k := range list(candidate["adminKeys"]) {
		s, ok := k.(string)
		if !ok || strings.Contains(s, "\n") || !fullmatch(sshKey, s) {
			return nil, Public("Supply valid administrator SSH public keys")
		}
	}
	bridge := str(jget(candidate, "guests", "bridge"))
	if _, ok := obj(candidate["guests"])["bridge"]; !ok {
		bridge = "incusbr0"
	}
	pool := str(jget(candidate, "storage", "pool"))
	if _, ok := obj(candidate["storage"])["pool"]; !ok {
		pool = "guests"
	}
	for _, value := range []string{bridge, pool} {
		if !fullmatch(incusName, value) {
			return nil, Public("Use a safe Incus bridge/pool name")
		}
	}
	interfaces := map[string]M{}
	for _, i := range list(host["interfaces"]) {
		interfaces[str(obj(i)["name"])] = obj(i)
	}
	var hostArg M
	if requireDevices {
		hostArg = host
	}
	declared, err := validateFoundation(candidate, hostArg)
	if err != nil {
		return nil, err
	}
	m, w := obj(candidate["management"]), obj(jget(candidate, "radios", "wifi"))
	mi := str(m["interface"])
	if requireDevices && interfaces[mi] == nil && !declared[mi] {
		return nil, Public("Management interface was not discovered on this host")
	}
	prefix, ok := intValue(m["prefixLength"])
	if !ok || prefix < 1 || prefix > 30 {
		return nil, Public("Management IPv4 prefix must be between 1 and 30")
	}
	for _, d := range list(m["dns"]) {
		if _, err := parseAddr(d); err != nil {
			return nil, err
		}
	}
	cidrs := list(m["trustedCIDRs"])
	if len(cidrs) == 0 {
		return nil, Public("Configure trusted IPv4 management source networks")
	}
	for _, c := range cidrs {
		if n, err := parseNetwork(c); err != nil || !n.Addr().Is4() {
			return nil, Public("Configure trusted IPv4 management source networks")
		}
	}
	if requireDevices && !isTrue(m["configure"]) {
		want := fmt.Sprintf("%s/%d", str(m["address"]), prefix)
		found := false
		for _, a := range list(interfaces[mi]["addresses"]) {
			if str(a) == want {
				found = true
			}
		}
		if !found {
			return nil, Public("Preserve mode must use an address actually assigned to that interface")
		}
	}
	if isTrue(interfaces[mi]["wireless"]) && !isTrue(w["enable"]) {
		return nil, Public("Wi-Fi cannot be disabled while it is the management interface")
	}
	if isTrue(w["enable"]) {
		if requireDevices && !isTrue(interfaces[str(w["interface"])]["wireless"]) {
			return nil, Public("Select a detected Wi-Fi interface")
		}
		ssid := str(w["ssid"])
		if isTrue(w["manageProfile"]) && (ssid == "" || len(ssid) > 32 || strings.ContainsAny(ssid, "\r\n\x00")) {
			return nil, Public("A managed Wi-Fi profile needs a valid SSID")
		}
		if isTrue(m["configure"]) && mi == str(w["interface"]) && !isTrue(w["manageProfile"]) {
			return nil, Public("Static Wi-Fi addressing requires a managed Wi-Fi profile")
		}
	}
	for _, f := range []struct {
		name         string
		lower, upper int
	}{{"retentionDays", 1, 90}, {"scrapeSeconds", 15, 300}} {
		v, ok := intValue(jget(candidate, "monitoring", f.name))
		if !ok || v < f.lower || v > f.upper {
			return nil, Public("Monitoring %s must be between %d and %d", f.name, f.lower, f.upper)
		}
	}
	zone := str(jget(candidate, "maintenance", "timeZone"))
	if !fullmatch(timeZone, zone) {
		return nil, Public("Invalid time zone")
	}
	if requireDevices && !exists(filepath.Join("/etc/zoneinfo", zone)) && !exists(filepath.Join("/usr/share/zoneinfo", zone)) {
		return nil, Public("Time zone is not installed on this host")
	}
	type listener struct {
		name string
		port any
	}
	listeners := []listener{{"setup", jget(candidate, "setup", "port")}}
	if isTrue(jget(candidate, "cockpit", "enable")) {
		listeners = append(listeners, listener{"Cockpit", jget(candidate, "cockpit", "port")})
	}
	used := map[int]bool{22: true, 53: true, 67: true, 8080: true, 8443: true, 9100: true}
	for _, l := range listeners {
		p, ok := intValue(l.port)
		if !ok || p < 1024 || p > 65535 || used[p] {
			return nil, Public("Choose distinct, unused management ports: " + l.name)
		}
		used[p] = true
	}
	if c, _ := num(jget(candidate, "setup", "confirmationSeconds")); c < 300 || c > 1800 {
		return nil, Public("Activation confirmation must allow 5–30 minutes")
	}
	if !isTrue(jget(candidate, "setup", "enable")) {
		return nil, Public("The setup service cannot disable its own recovery/access path")
	}
	mounts := list(candidate["mounts"])
	uuids, paths, names := map[string]bool{}, map[string]bool{}, map[string]bool{}
	available := map[string][]M{}
	all := flattenDisks(list(host["disks"]))
	for _, d := range all {
		if u := str(d["uuid"]); u != "" {
			available[u] = append(available[u], d)
		}
	}
	var primary, stages []M
	for _, raw := range mounts {
		mount := obj(raw)
		want := []string{"fsType", "name", "path", "readOnly", "required", "role", "uuid"}
		if mount == nil || strings.Join(keys(mount), ",") != strings.Join(want, ",") {
			return nil, Public("Each mount needs name, UUID, path, filesystem, role and boot/read-only flags")
		}
		name, uuid, mpath, fs, role := str(mount["name"]), str(mount["uuid"]), str(mount["path"]), str(mount["fsType"]), str(mount["role"])
		if !fullmatch(mountName, name) {
			return nil, Public("Mount names use lowercase letters, numbers and hyphens")
		}
		if !fullmatch(mountUUID, uuid) {
			return nil, Public("Select a stable filesystem UUID")
		}
		if mpath != "/srv/nixus/"+name {
			return nil, Public("Managed disks mount only at /srv/nixus/<name>")
		}
		if !FILESYSTEMS[fs] || !MOUNT_ROLES[role] {
			return nil, Public("Unsupported filesystem or storage role")
		}
		required, ok1 := mount["required"].(bool)
		readOnly, ok2 := mount["readOnly"].(bool)
		if !ok1 || !ok2 {
			return nil, Public("Mount flags must be boolean")
		}
		if role != "data" && (!required || readOnly || (fs != "ext4" && fs != "xfs" && fs != "btrfs")) {
			return nil, Public("Incus/backup storage requires a writable, required Linux filesystem")
		}
		if uuids[uuid] || paths[mpath] || names[name] {
			return nil, Public("Duplicate filesystem, mount point or pool name")
		}
		uuids[uuid], paths[mpath], names[name] = true, true, true
		if requireDevices {
			matches := available[uuid]
			if len(matches) != 1 {
				return nil, Public("Filesystem UUID must resolve to exactly one detected device")
			}
			disk := matches[0]
			kind := str(disk["fstype"])
			if kind == "ntfs" {
				kind = "ntfs3"
			}
			if kind != fs {
				return nil, Public("Filesystem type differs from the discovered device")
			}
			for _, s := range list(disk["mountpoints"]) {
				if str(s) != "" && str(s) != mpath {
					return nil, Public("Device is already mounted elsewhere; root/boot/system disks cannot be repurposed")
				}
			}
			for _, other := range all {
				if str(other["uuid"]) == uuid {
					continue
				}
				for _, s := range list(other["mountpoints"]) {
					if str(s) == mpath {
						return nil, Public("Mount point is already backed by a different filesystem")
					}
				}
			}
			if isSymlink(mpath) {
				return nil, Public("Mount point cannot be a symlink")
			}
			if entries, err := os.ReadDir(mpath); err == nil && len(entries) > 0 && !isMountPoint(mpath) {
				return nil, Public("Mount point contains files that would be hidden")
			}
		}
		if role == "guests" {
			primary = append(primary, mount)
		}
		if role == "backup" {
			stages = append(stages, mount)
		}
	}
	if len(primary) > 1 || len(stages) > 1 {
		return nil, Public("Choose at most one primary Incus disk and one backup staging disk")
	}
	storage := obj(candidate["storage"])
	if len(primary) == 1 {
		if str(storage["driver"]) != "dir" {
			return nil, Public("Filesystem mounting uses a directory pool; ZFS datasets are configured separately")
		}
		storage["source"] = str(primary[0]["path"]) + "/incus"
	} else if str(storage["driver"]) == "dir" {
		storage["source"] = "/var/lib/incus/storage-pools/" + pool
	}
	backup := obj(candidate["backup"])
	if len(stages) == 1 {
		backup["stagingDirectory"] = str(stages[0]["path"]) + "/exports"
	} else {
		backup["stagingDirectory"] = "/var/lib/nixus/exports"
	}
	if isTrue(backup["enable"]) {
		repo := str(backup["repository"])
		if repo == "" || strings.Contains(repo, "\n") {
			return nil, Public("Provide an independent restic repository")
		}
		if requireDevices {
			if _, err := command([]string{"systemd-analyze", "calendar", "--iterations=1", str(backup["schedule"])}, 10*time.Second); err != nil {
				return nil, err
			}
		}
	}
	tunnel := obj(candidate["tunnel"])
	if isTrue(tunnel["enable"]) {
		ingress := obj(tunnel["ingress"])
		if !fullmatch(re(`[0-9a-fA-F-]{36}`), str(tunnel["uuid"])) || len(ingress) == 0 {
			return nil, Public("Provide the existing tunnel UUID and application hostnames")
		}
		setupPort, _ := intValue(jget(candidate, "setup", "port"))
		cockpitPort, _ := intValue(jget(candidate, "cockpit", "port"))
		blocked := map[int]bool{22: true, 8443: true, 9090: true, 9100: true, 9440: true, 9441: true, 9443: true, setupPort: true, cockpitPort: true}
		for hostname, raw := range ingress {
			target, ok := raw.(string)
			if !fullmatch(re(`[A-Za-z0-9*.-]+`), hostname) || !ok || !(strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")) {
				return nil, Public("Tunnel ingress must map hostnames to HTTP application endpoints")
			}
			origin, err := url.Parse(target)
			port := -1
			if err == nil && origin.Port() != "" {
				port, _ = strconv.Atoi(origin.Port())
			}
			if err != nil || origin.User != nil || origin.Hostname() == "" || blocked[port] {
				return nil, Public("Management endpoints cannot be public tunnel origins")
			}
		}
	}
	candidate["ready"] = true
	if err := validateNetwork(candidate); err != nil {
		return nil, err
	}
	return candidate, nil
}

func isMountPoint(p string) bool {
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	clean := filepath.Clean(p)
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) > 4 && f[4] == clean {
			return true
		}
	}
	return false
}

func differences(old, new M, prefix string) []any {
	all := map[string]bool{}
	for k := range old {
		all[k] = true
	}
	for k := range new {
		all[k] = true
	}
	names := make([]string, 0, len(all))
	for k := range all {
		names = append(names, k)
	}
	sort.Strings(names)
	changes := []any{}
	for _, k := range names {
		before, after := old[k], new[k]
		bm, ok1 := before.(M)
		am, ok2 := after.(M)
		if ok1 && ok2 {
			changes = append(changes, differences(bm, am, prefix+k+".")...)
		} else if !equalJSON(before, after) {
			changes = append(changes, M{"setting": prefix + k, "before": before, "after": after})
		}
	}
	return changes
}

// --- foundation ------------------------------------------------------------

var ifaceName = re(`[A-Za-z0-9_.-]{1,15}`)

func validInterface(v any) bool { s, ok := v.(string); return ok && fullmatch(ifaceName, s) && s != "lo" }

func foundationRecords(values any, fields []string, label string) ([]M, error) {
	l, ok := values.([]any)
	if values == nil {
		l, ok = []any{}, true
	}
	if !ok || len(l) > 64 {
		return nil, Public(label + " must contain at most 64 records")
	}
	sort.Strings(fields)
	var out []M
	for _, item := range l {
		m := obj(item)
		if m == nil || strings.Join(keys(m), ",") != strings.Join(fields, ",") {
			return nil, Public("Invalid " + label + " fields")
		}
		out = append(out, m)
	}
	return out, nil
}

var guestIdentityRe = re(`[A-Za-z0-9][A-Za-z0-9_.-]{0,62}/[A-Za-z0-9][A-Za-z0-9_.-]{0,62}`)

func guestIdentity(v any) error {
	if s, ok := v.(string); !ok || !fullmatch(guestIdentityRe, s) {
		return Public("Use project/guest identities for backup selection")
	}
	return nil
}

func validateFoundation(site, host M) (map[string]bool, error) {
	c := obj(site["connectivity"])
	bridges, err := foundationRecords(c["bridges"], []string{"name", "interfaces"}, "Ethernet bridges")
	if err != nil {
		return nil, err
	}
	vlans, err := foundationRecords(c["vlans"], []string{"name", "interface", "id"}, "VLANs")
	if err != nil {
		return nil, err
	}
	names, ports := map[string]bool{}, map[string]bool{}
	physical := map[string]M{}
	for _, i := range list(host["interfaces"]) {
		physical[str(obj(i)["name"])] = obj(i)
	}
	for _, item := range append(append([]M{}, bridges...), vlans...) {
		n := str(item["name"])
		if !validInterface(item["name"]) || names[n] || strings.HasPrefix(n, "incus") || strings.HasPrefix(n, "veth") || strings.HasPrefix(n, "tap") {
			return nil, Public("Host interface names must be unique and cannot use Incus-reserved names")
		}
		names[n] = true
	}
	vlanNames := map[string]bool{}
	for _, v := range vlans {
		vlanNames[str(v["name"])] = true
	}
	ethernet := func(name string) bool {
		p := physical[name]
		kind := str(p["kind"])
		if _, ok := p["kind"]; !ok {
			kind = "ethernet"
		}
		return p != nil && !isTrue(p["wireless"]) && kind == "ethernet"
	}
	pairs := map[string]bool{}
	for _, v := range vlans {
		parent := str(v["interface"])
		if !validInterface(v["interface"]) || names[parent] {
			return nil, Public("VLAN parents must be physical Ethernet interfaces")
		}
		id, ok := intValue(v["id"])
		if !ok || id < 1 || id > 4094 {
			return nil, Public("VLAN ID must be between 1 and 4094")
		}
		if host != nil && !ethernet(parent) {
			return nil, Public("Select a discovered Ethernet VLAN parent")
		}
		pairs[fmt.Sprintf("%s/%d", parent, id)] = true
	}
	if len(pairs) != len(vlans) {
		return nil, Public("Duplicate VLAN parent/tag")
	}
	for _, b := range bridges {
		members := list(b["interfaces"])
		if len(members) == 0 {
			return nil, Public("A LAN bridge requires at least one Ethernet/VLAN port")
		}
		for _, raw := range members {
			port := str(raw)
			if !validInterface(raw) || ports[port] || (names[port] && !vlanNames[port]) {
				return nil, Public("An interface can belong to only one bridge; bridge nesting is unsupported")
			}
			if host != nil && !vlanNames[port] && !ethernet(port) {
				return nil, Public("Only discovered Ethernet interfaces or declared VLANs can be bridged")
			}
			ports[port] = true
		}
	}
	m := obj(site["management"])
	mi := str(m["interface"])
	if ports[mi] {
		return nil, Public("Move management addressing onto the bridge before enslaving its interface")
	}
	if len(names) > 0 && names[mi] && !isTrue(m["configure"]) {
		return nil, Public("A declared management bridge/VLAN needs explicit addressing")
	}
	if host != nil {
		for name := range names {
			if p, ok := physical[name]; ok {
				expected := "bridge"
				if vlanNames[name] {
					expected = "vlan"
				}
				if actual := str(p["kind"]); actual != "" && actual != expected {
					return nil, Public("Declared host interface conflicts with discovered hardware: " + name)
				}
			}
		}
		bridgeNames := map[string]bool{}
		for _, b := range bridges {
			bridgeNames[str(b["name"])] = true
		}
		for port := range ports {
			if len(list(physical[port]["addresses"])) > 0 && (!bridgeNames[mi] || !isTrue(m["configure"])) {
				return nil, Public("Review management addressing before moving an addressed Ethernet port into a bridge")
			}
		}
	}
	guestsRaw, has := c["guestInterfaces"]
	guests := []any{"incusbr0"}
	if has {
		guests = list(guestsRaw)
	}
	bridge := "incusbr0"
	if b, ok := obj(site["guests"])["bridge"]; ok {
		bridge = str(b)
	}
	seen, hasBridge := map[string]bool{}, false
	if (has && guestsRaw != nil && list(guestsRaw) == nil) || len(guests) > 64 {
		return nil, Public("Register distinct private guest bridges, including the Nixus bridge")
	}
	for _, g := range guests {
		if !validInterface(g) || seen[str(g)] {
			return nil, Public("Register distinct private guest bridges, including the Nixus bridge")
		}
		seen[str(g)] = true
		if str(g) == bridge {
			hasBridge = true
		}
	}
	if !hasBridge {
		return nil, Public("Register distinct private guest bridges, including the Nixus bridge")
	}
	for _, g := range guests {
		n := str(g)
		if n == mi || names[n] || ports[n] {
			return nil, Public("Guest firewall interfaces must be separate from host Ethernet/LAN interfaces")
		}
		if host != nil {
			if p, ok := physical[n]; ok && str(p["kind"]) != "bridge" && p["kind"] != nil {
				return nil, Public("Guest firewall integration accepts bridges only")
			}
		}
	}
	for _, raw := range list(c["preservedIncusBridges"]) {
		n := str(raw)
		if !validInterface(raw) || n == mi || seen[n] || names[n] || ports[n] {
			return nil, Public("Preserved Incus bridges must be separate private bridges")
		}
		if host != nil && str(physical[n]["kind"]) != "bridge" {
			return nil, Public("Preserved Incus bridge is absent or is not a bridge")
		}
	}
	rules, err := foundationRecords(c["privateAccess"], []string{"cidr", "protocol", "ports"}, "private access rules")
	if err != nil {
		return nil, err
	}
	for _, rule := range rules {
		network, err := parseNetwork(rule["cidr"])
		if err != nil {
			return nil, err
		}
		proto := str(rule["protocol"])
		if !network.Addr().Is4() || (proto != "tcp" && proto != "udp") {
			return nil, Public("Private access rules require IPv4 and TCP/UDP")
		}
		ps := list(rule["ports"])
		if len(ps) == 0 {
			return nil, Public("Private access ports must be between 1 and 65535")
		}
		for _, p := range ps {
			if v, ok := intValue(p); !ok || v < 1 || v > 65535 {
				return nil, Public("Private access ports must be between 1 and 65535")
			}
		}
	}
	aliases, err := foundationRecords(jget(site, "hardware", "serialAliases"), []string{"name", "vendorId", "productId", "serial"}, "serial aliases")
	if err != nil {
		return nil, err
	}
	identities, aliasNames := map[string]bool{}, map[string]bool{}
	for _, a := range aliases {
		for _, v := range a {
			if !isStr(v) {
				return nil, Public("Select an exact USB identity and a safe stable alias name")
			}
		}
		if !fullmatch(mountName, str(a["name"])) || !fullmatch(re(`[0-9a-fA-F]{4}`), str(a["vendorId"])) ||
			!fullmatch(re(`[0-9a-fA-F]{4}`), str(a["productId"])) || !fullmatch(re(`[A-Za-z0-9_.:+-]{1,128}`), str(a["serial"])) {
			return nil, Public("Select an exact USB identity and a safe stable alias name")
		}
		identity := strings.ToLower(str(a["vendorId"])) + "/" + strings.ToLower(str(a["productId"])) + "/" + str(a["serial"])
		if identities[identity] || aliasNames[str(a["name"])] {
			return nil, Public("Duplicate serial alias identity/name")
		}
		identities[identity], aliasNames[str(a["name"])] = true, true
	}
	backup := obj(site["backup"])
	for _, g := range list(backup["groups"]) {
		members, ok := g.([]any)
		if !ok || len(members) == 0 {
			return nil, Public("Backup consistency groups must be nonempty lists")
		}
		for _, member := range members {
			if err := guestIdentity(member); err != nil {
				return nil, err
			}
		}
	}
	for _, member := range list(backup["exclude"]) {
		if err := guestIdentity(member); err != nil {
			return nil, err
		}
	}
	reserve := any(1024)
	if v, ok := backup["reserveMiB"]; ok {
		reserve = v
	}
	if r, ok := intValue(reserve); !ok || r < 100 || r > 1048576 {
		return nil, Public("Backup staging reserve must be 100–1048576 MiB")
	}
	schedule := any("*-*-* 03:00:00")
	if v, ok := backup["schedule"]; ok {
		schedule = v
	}
	if s, ok := schedule.(string); !ok || s == "" || len(s) > 128 || strings.ContainsAny(s, "\r\n\x00") {
		return nil, Public("Use a single-line systemd calendar schedule")
	}
	return names, nil
}

// --- network preflight -----------------------------------------------------

func addrInt(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func broadcast(p netip.Prefix) netip.Addr {
	n := addrInt(p.Masked().Addr()) | (1<<(32-p.Bits()) - 1)
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

func validateNetwork(site M) error {
	if _, err := validateFoundation(site, nil); err != nil {
		return err
	}
	m, g := obj(site["management"]), obj(site["guests"])
	if !fullmatch(re(`[a-zA-Z0-9_.:-]{1,15}`), str(m["interface"])) {
		return Public("Invalid or missing management interface")
	}
	prefix, _ := intValue(m["prefixLength"])
	mgmtAddr, err := parseAddr(m["address"])
	if err != nil {
		return err
	}
	management := netip.PrefixFrom(mgmtAddr, prefix)
	subnet, err := parseNetwork(g["cidr"])
	if err != nil {
		return err
	}
	bridge, err := netip.ParsePrefix(str(g["gatewayCIDR"]))
	if err != nil {
		return Public("Invalid bridge address")
	}
	if !mgmtAddr.Is4() || !subnet.Addr().Is4() || !bridge.Addr().Is4() {
		return Public("The default topology requires explicit IPv4 inventory")
	}
	if management.Masked().Overlaps(subnet) {
		return Public("Guest subnet overlaps the host management subnet")
	}
	if bridge.Masked() != subnet || bridge.Addr() == subnet.Addr() || bridge.Addr() == broadcast(subnet) {
		return Public("Bridge must have a usable address inside the guest subnet")
	}
	lowS, highS, _ := strings.Cut(str(g["dhcpRange"]), "-")
	low, err1 := netip.ParseAddr(lowS)
	high, err2 := netip.ParseAddr(highS)
	if err1 != nil || err2 != nil || !subnet.Contains(low) || !subnet.Contains(high) || addrInt(low) > addrInt(high) {
		return Public("Invalid DHCP range")
	}
	inRange := func(a netip.Addr) bool { return addrInt(low) <= addrInt(a) && addrInt(a) <= addrInt(high) }
	for _, a := range []netip.Addr{bridge.Addr(), subnet.Addr(), broadcast(subnet)} {
		if inRange(a) {
			return Public("DHCP range overlaps a reserved address")
		}
	}
	reservations := map[netip.Addr]bool{bridge.Addr(): true}
	identities := map[string]bool{}
	bridgeName := "incusbr0"
	if b, ok := g["bridge"]; ok {
		bridgeName = str(b)
	}
	for _, raw := range list(site["instances"]) {
		instance := obj(raw)
		identity := str(instance["project"]) + "/" + str(instance["name"])
		if identities[identity] {
			return Public("Duplicate declared instance name/project")
		}
		identities[identity] = true
		for _, d := range obj(instance["devices"]) {
			device := obj(d)
			if str(device["network"]) != bridgeName || str(device["ipv4.address"]) == "" {
				continue
			}
			address, err := parseAddr(device["ipv4.address"])
			if err != nil {
				return err
			}
			if !subnet.Contains(address) || reservations[address] || address == subnet.Addr() || address == broadcast(subnet) || inRange(address) {
				return Public("Guest reservation conflicts with another address or DHCP range")
			}
			reservations[address] = true
		}
	}
	for _, c := range list(m["trustedCIDRs"]) {
		if _, err := parseNetwork(c); err != nil {
			return err
		}
	}
	if isTrue(m["configure"]) {
		gw, err := parseAddr(m["gateway"])
		if err != nil || !management.Masked().Contains(gw) {
			return Public("Management gateway is outside the configured subnet")
		}
		if len(list(m["dns"])) == 0 {
			return Public("Explicit management DNS servers are required")
		}
	}
	storage := obj(site["storage"])
	switch str(storage["driver"]) {
	case "zfs":
		if !isTrue(storage["confirmedExistingZfsDataset"]) || !fullmatch(re(`[0-9a-fA-F]{8}`), str(storage["hostId"])) {
			return Public("ZFS needs explicit confirmation and a unique 8-digit hostId")
		}
		if !fullmatch(re(`[a-zA-Z][a-zA-Z0-9_.:-]*(/[a-zA-Z0-9_.:-]+)+`), str(storage["source"])) {
			return Public("ZFS source must name an existing child dataset, never a disk or pool root")
		}
	case "dir":
		source := str(storage["source"])
		ok := strings.HasPrefix(source, "/var/lib/incus/storage-pools/")
		for _, raw := range list(site["mounts"]) {
			mt := obj(raw)
			if str(mt["role"]) == "guests" && source == str(mt["path"])+"/incus" {
				ok = true
			}
		}
		if !ok {
			return Public("Directory storage must live in the dedicated Incus storage-pools tree")
		}
	default:
		return Public("Unsupported storage driver")
	}
	return nil
}
