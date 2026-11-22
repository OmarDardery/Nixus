package main

// Installer: versioned intent, direct conversion through the guarded host
// transaction, one-command updates and local-console network repair.

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const installRepository = "https://github.com/OmarDardery/Nixus.git"

var installTarget = "/var/lib/nixus/config"

const originalNixos = "/etc/nixos"
const activeStatuses = "building ready applying awaiting-confirmation rolling-back"

func isActiveStatus(s string) bool {
	return s != "" && strings.Contains(" "+activeStatuses+" ", " "+s+" ")
}

var stdin = bufio.NewReader(os.Stdin)

func prompt(message string) string {
	fmt.Print(message)
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return ""
	}
	return strings.TrimRight(line, "\r\n")
}

func askYes(message string) bool {
	v := strings.ToLower(strings.TrimSpace(prompt(message + " [y/N] ")))
	return v == "y" || v == "yes"
}

func isTerminal() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func hostRun(args ...string) ([]byte, error) {
	out, err := check(args, nil, 2*time.Hour)
	if err != nil {
		return nil, Public("Installer host command failed")
	}
	return out, nil
}

// --- intent -------------------------------------------------------------------

var intentQuestions = [][]string{
	{"workloads", "Workloads [containers/compose/both]", "containers", "compose", "both"},
	{"access", "Access [lan/private/public]", "lan", "private", "public"},
	{"network", "Guest connectivity [nat/lan/vlan]", "nat", "lan", "vlan"},
	{"laptop", "Enable always-on laptop lid policy? [y/N]", "yes", "no"},
	{"monitoring", "Collect basic host metrics? [Y/n]", "yes", "no"},
}

func intentDefaults() M {
	return M{"version": 1, "workloads": "both", "access": "lan", "network": "nat", "laptop": false, "monitoring": true, "backup": false, "guestSubnet": nil}
}

var privateBlocks = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16")}

func privateSlash24(v string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(v)
	if err != nil || !p.Addr().Is4() || p.Bits() != 24 || p.Masked() != p {
		return netip.Prefix{}, false
	}
	for _, b := range privateBlocks {
		if b.Contains(p.Addr()) {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

func normalizeIntent(raw M) (M, error) {
	known := map[string]bool{"version": true, "workloads": true, "access": true, "network": true, "laptop": true, "monitoring": true, "backup": true, "guestSubnet": true}
	legacy := map[string]bool{"adguard": true, "klipper": true, "aiostreams": true}
	if raw == nil {
		return nil, Public("Installer answers must be an object with documented keys only")
	}
	result := intentDefaults()
	for k, v := range raw {
		switch {
		case known[k]:
			result[k] = v
		case legacy[k]:
			if _, ok := v.(bool); !ok {
				return nil, Public("Deprecated workload flags must be booleans")
			}
		default:
			return nil, Public("Installer answers must be an object with documented keys only")
		}
	}
	if !isInt(result["version"]) || !equalJSON(result["version"], 1) {
		return nil, Public("Unsupported installer answers version")
	}
	for _, q := range intentQuestions[:3] {
		ok := false
		for _, c := range q[2:] {
			ok = ok || str(result[q[0]]) == c
		}
		if !ok {
			return nil, Public(q[0] + " must be one of: " + strings.Join(q[2:], ", "))
		}
	}
	for _, f := range []string{"laptop", "monitoring", "backup"} {
		if _, ok := result[f].(bool); !ok {
			return nil, Public(f + " must be true or false")
		}
	}
	if s := result["guestSubnet"]; s != nil {
		p, ok := privateSlash24(str(s))
		if !ok {
			return nil, Public("guestSubnet must be an unused RFC1918 IPv4 /24")
		}
		result["guestSubnet"] = p.String()
	}
	return result, nil
}

func loadIntent(p string) (M, error) {
	info, err := os.Lstat(p)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16384 {
		return nil, Public("Answer file must be a small, regular JSON file")
	}
	raw, _ := os.ReadFile(p)
	m, err := parseObject(raw)
	if err != nil {
		return nil, Public("Answer file must be a small, regular JSON file")
	}
	return normalizeIntent(m)
}

func interview(existing M, onAnswer func(M)) (M, error) {
	values, err := normalizeIntent(existing)
	if err != nil {
		return nil, err
	}
	fmt.Println("Nixus configuration interview. Enter keeps the recommendation.")
	for _, q := range intentQuestions {
		original := values[q[0]]
		_, isBool := original.(bool)
		def := str(original)
		if isBool {
			def = "no"
			if original == true {
				def = "yes"
			}
		}
		var value string
		for {
			value = strings.ToLower(strings.TrimSpace(prompt(q[1] + " (default: " + def + "): ")))
			if value == "" {
				value = def
			}
			if value == "y" {
				value = "yes"
			}
			if value == "n" {
				value = "no"
			}
			ok := false
			for _, c := range q[2:] {
				ok = ok || c == value
			}
			if ok {
				break
			}
			fmt.Println("Choose one of: " + strings.Join(q[2:], ", "))
		}
		if isBool {
			values[q[0]] = value == "yes"
		} else {
			values[q[0]] = value
		}
		if onAnswer != nil {
			n, _ := normalizeIntent(values)
			onAnswer(n)
		}
	}
	return normalizeIntent(values)
}

func guestNetwork(routes []any, requested string) (M, error) {
	var occupied []netip.Prefix
	for _, r := range routes {
		dst := str(obj(r)["dst"])
		if dst == "" || dst == "default" {
			continue
		}
		if !strings.Contains(dst, "/") {
			dst += "/32"
		}
		if p, err := netip.ParsePrefix(dst); err == nil {
			occupied = append(occupied, p.Masked())
		}
	}
	choices := []string{"10.90.90.0/24", "10.77.0.0/24", "10.78.0.0/24", "172.30.77.0/24", "192.168.240.0/24"}
	if requested != "" {
		choices = []string{requested}
	}
	for _, c := range choices {
		net, ok := privateSlash24(c)
		if !ok {
			return nil, Public("Guest network must be a private IPv4 /24")
		}
		clash := false
		for _, o := range occupied {
			clash = clash || o.Overlaps(net)
		}
		if clash {
			continue
		}
		prefix := net.Addr().String()
		prefix = prefix[:strings.LastIndex(prefix, ".")]
		return M{"cidr": net.String(), "gatewayCIDR": prefix + ".1/24", "dhcpRange": prefix + ".100-" + prefix + ".199"}, nil
	}
	return nil, Public("No non-overlapping guest subnet; select an unused --guest-subnet")
}

func intentPlan(answers, host, settings M, remote bool) (M, error) {
	a, err := normalizeIntent(answers)
	if err != nil {
		return nil, err
	}
	m := obj(settings["management"])
	prefix, _ := intValue(m["prefixLength"])
	mgmt, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", str(m["address"]), prefix))
	if err != nil {
		return nil, Public("Invalid management address")
	}
	mgmt = mgmt.Masked()
	wireless := false
	for _, i := range list(host["interfaces"]) {
		if str(obj(i)["name"]) == str(m["interface"]) && isTrue(obj(i)["wireless"]) {
			wireless = true
		}
	}
	network := str(a["network"])
	if network != "nat" && wireless {
		return nil, Public("Wi-Fi uplinks cannot be enslaved to an Ethernet bridge/VLAN. Use NAT and configure LAN access separately")
	}
	if network != "nat" && remote {
		return nil, Public("LAN bridge/VLAN changes require local-console review; use NAT for remote installation")
	}
	deferred := network != "nat"
	if s := str(a["guestSubnet"]); s != "" {
		selected, _ := netip.ParsePrefix(s)
		if selected.Overlaps(mgmt) {
			return nil, Public("Guest subnet overlaps management LAN")
		}
		for _, r := range list(host["routes"]) {
			dst := str(obj(r)["dst"])
			if dst == "" || dst == "default" {
				dst = "0.0.0.0/0"
			} else if !strings.Contains(dst, "/") {
				dst += "/32"
			}
			occupied, err := netip.ParsePrefix(dst)
			if err != nil {
				continue
			}
			if selected.Overlaps(occupied.Masked()) && !(isTrue(settings["ready"]) && str(jget(settings, "guests", "cidr")) == selected.String()) {
				return nil, Public("Guest subnet overlaps an existing route: " + occupied.Masked().String())
			}
		}
	}
	cidr := str(jget(settings, "guests", "cidr"))
	if !isTrue(settings["ready"]) {
		g, err := guestNetwork(list(host["routes"]), str(a["guestSubnet"]))
		if err != nil {
			return nil, err
		}
		cidr = str(g["cidr"])
	}
	var pending []any
	if deferred {
		pending = append(pending, "Review an existing Ethernet bridge/VLAN and switch configuration in Connectivity; no host NIC is modified by this installer")
	}
	pending = append(pending, "Create and manage workload-agnostic Incus guests using Incus UI or reviewed helper scripts; configure persistent storage and resource limits separately")
	if w := str(a["workloads"]); w == "compose" || w == "both" {
		pending = append(pending, "Use Incus OCI and a qualified Incus Compose project after setup; verify data persistence and an independent restore")
	}
	pending = append(pending, "For guests needing physical USB/serial devices, inspect stable device IDs and explicitly review Incus passthrough; do not assume a particular peripheral",
		"For LAN-facing services such as DNS, validate stable guest reachability and firewall rules before changing router or client settings")
	switch str(a["access"]) {
	case "private":
		pending = append(pending, "Enable private access (Tailscale) under Settings → Network; verify private SSH without publishing management dashboards")
	case "public":
		pending = append(pending, "Run cloudflared as an app for public ingress; publish only app origins, never SSH/Incus/Cockpit/Nixus")
	}
	pending = append(pending, "Set up backups on the Backups page and test a restore before trusting app data")
	if isTrue(a["monitoring"]) {
		pending = append(pending, "Host metrics collection is enabled; notification delivery and retention require separate confirmation")
	}
	pending = append(pending, "Run commissioning after initial install and two reboots; verify DHCP, SSH, Incus, and all real workloads")
	reasons := []any{"Existing management addressing, host uplink, users and disks are preserved", "Private Incus NAT is the safe initial guest topology",
		"Cockpit and Incus are the host management tools", "No secrets, router DNS settings or community scripts are applied automatically"}
	if deferred {
		reasons[1] = "Requested LAN networking is deferred for guarded local-console review; initial guest topology stays NAT"
	} else {
		reasons = append(reasons, "NAT guests do not automatically expose services to LAN clients; review port forwarding, routing or a separate LAN network as needed")
	}
	return M{"version": 1, "answers": a, "laptop": a["laptop"], "monitoring": a["monitoring"], "guestSubnet": a["guestSubnet"],
		"reasons": reasons, "pending": pending, "networkRequiresReview": deferred, "estimatedAppMemoryMiB": 0,
		"managementAddress": m["address"], "guestCidr": cidr}, nil
}

func intentPreview(p M) {
	onOff := func(v any, yes, no string) string {
		if isTrue(v) {
			return yes
		}
		return no
	}
	fmt.Println("\nNixus proposed configuration (review before activation)")
	fmt.Println("  Host metrics: " + onOff(p["monitoring"], "enabled", "disabled"))
	fmt.Println("  Laptop policy: " + onOff(p["laptop"], "always-on", "standard server"))
	fmt.Println("  Guest network: private NAT " + str(p["guestCidr"]) + " (existing host LAN unchanged)")
	fmt.Println("  Management: " + str(p["managementAddress"]) + " (preserved)")
	for _, r := range list(p["reasons"]) {
		fmt.Println("  Why: " + str(r))
	}
	fmt.Println("External/manual steps (NOT performed by installer):")
	for _, t := range list(p["pending"]) {
		fmt.Println("  - " + str(t))
	}
}

// --- workflow ----------------------------------------------------------------------

func remoteSession() bool {
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" {
		return true
	}
	pid := os.Getpid()
	for i := 0; i < 64; i++ {
		proc := filepath.Join("/proc", strconv.Itoa(pid))
		comm := readText(filepath.Join(proc, "comm"))
		if strings.HasPrefix(comm, "sshd") || strings.HasPrefix(comm, "cockpit-") {
			return true
		}
		parent := 0
		for _, line := range strings.Split(readText(filepath.Join(proc, "status")), "\n") {
			if strings.HasPrefix(line, "PPid:") {
				parent, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
			}
		}
		if parent <= 1 || parent == pid {
			break
		}
		pid = parent
	}
	return false
}

func platformHashes(root string) (map[string]string, error) {
	files, err := sourceFiles(root)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, f := range files {
		if platformPath(f.name) {
			out[f.name], _ = fileSHA256(f.path)
		}
	}
	return out, nil
}

func finishInterruptedRecovery(m *Manager, record M) (M, error) {
	pending := readObj(filepath.Join(STATE, "pending.json"))
	if str(record["status"]) != "failed" || str(pending["id"]) != str(record["id"]) {
		return record, nil
	}
	fmt.Println("Completing interrupted activation recovery: " + str(record["id"]))
	err := locked(false, func() error {
		dir, err := m.jobPath(str(record["id"]))
		if err != nil {
			return err
		}
		if workerRollback(dir, "installer retry after interrupted activation") != nil {
			return Public("Previous activation and recovery did not complete; inspect the host recovery state before retrying")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return m.job(str(record["id"]))
}

func incomingFiles(root string) ([]sourceFile, error) {
	if lexists(filepath.Join(root, ".git")) || isFile(filepath.Join(root, ".nixus-files.json")) {
		return sourceFiles(root)
	}
	var files []sourceFile
	names := map[string]bool{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || p == root {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if d.Type()&os.ModeSymlink != 0 {
			return Public("Bundled platform source cannot contain symlinks: " + rel)
		}
		if d.Type().IsRegular() && platformPath(rel) {
			files = append(files, sourceFile{rel, p})
			names[rel] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !names["flake.nix"] || !names["flake.lock"] || !names["go.mod"] {
		return nil, Public("Bundled source does not contain a complete Nixus platform")
	}
	return files, nil
}

// stageUpdate never overwrites platform edits; machine files stay protected.
func stageUpdate(root, incoming, stage, baseline string) (bool, []string, error) {
	if err := snapshot(stage, root); err != nil {
		return false, nil, err
	}
	if incoming == "" {
		return false, nil, nil
	}
	current, err := platformHashes(root)
	if err != nil {
		return false, nil, err
	}
	known := map[string]string{}
	for k, v := range readObj(baseline) {
		known[k] = str(v)
	}
	if len(known) == 0 {
		if out, err := check([]string{"git", "-C", root, "ls-tree", "-r", "--name-only", "HEAD"}, nil, 30*time.Second); err == nil {
			for _, name := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				if name == "" || !platformPath(name) {
					continue
				}
				data, err := check([]string{"git", "-C", root, "show", "HEAD:" + name}, nil, 30*time.Second)
				if err != nil {
					return false, nil, Public("Cannot read the platform baseline")
				}
				known[name] = sha256hex(data)
			}
		}
	}
	if len(known) == 0 {
		return false, nil, Public("Cannot establish the platform baseline; retry with --no-update and inspect the managed source")
	}
	edits := map[string]bool{}
	for name := range known {
		if current[name] != known[name] {
			edits[name] = true
		}
	}
	for name := range current {
		if current[name] != known[name] {
			edits[name] = true
		}
	}
	files, err := incomingFiles(incoming)
	if err != nil {
		return false, nil, err
	}
	desired := map[string]string{}
	for _, f := range files {
		if platformPath(f.name) {
			desired[f.name] = f.path
		}
	}
	for name := range desired {
		if _, ok := current[name]; !ok && lexists(filepath.Join(root, name)) {
			edits[name] = true
		}
	}
	if len(edits) > 0 {
		return false, sortedKeys(edits), nil
	}
	for name := range current {
		if _, ok := desired[name]; !ok {
			os.Remove(filepath.Join(stage, name))
		}
	}
	for name, p := range desired {
		data, err := os.ReadFile(p)
		if err != nil {
			return false, nil, err
		}
		info, _ := os.Stat(p)
		if err := atomic(filepath.Join(stage, name), data, info.Mode().Perm(), ""); err != nil {
			return false, nil, err
		}
	}
	staged, err := sourceFiles(stage)
	if err != nil {
		return false, nil, err
	}
	all := map[string]bool{}
	for _, f := range staged {
		if !platformPath(f.name) {
			all[f.name] = true
		}
	}
	for n := range desired {
		all[n] = true
	}
	delete(all, ".nixus-files.json")
	return true, nil, writeJSON(filepath.Join(stage, ".nixus-files.json"), strings2any(sortedKeys(all)))
}

func incusAdoptionInventory() (M, error) {
	query := func(p string) (any, error) {
		out, err := check([]string{"incus", "--force-local", "query", p}, nil, 30*time.Second)
		if err != nil {
			return nil, Public("Incus inventory query failed")
		}
		return parseJSON(out)
	}
	server, err := query("/1.0")
	if err != nil {
		return nil, err
	}
	if isTrue(jget(obj(server), "environment", "server_clustered")) {
		return nil, Public("Clustered Incus needs a separate migration plan; no changes made")
	}
	data := M{"server": server}
	for key, p := range map[string]string{"projects": "/1.0/projects?recursion=1", "networks": "/1.0/networks?recursion=1",
		"pools": "/1.0/storage-pools?recursion=1", "instances": "/1.0/instances?recursion=1&all-projects=true"} {
		if data[key], err = query(p); err != nil {
			return nil, err
		}
	}
	profiles, volumes := M{}, M{}
	for _, p := range list(data["projects"]) {
		name := str(obj(p)["name"])
		if profiles[name], err = query("/1.0/profiles?recursion=1&project=" + q(name)); err != nil {
			return nil, err
		}
	}
	for _, p := range list(data["pools"]) {
		name := str(obj(p)["name"])
		if volumes[name], err = query("/1.0/storage-pools/" + q(name) + "/volumes?recursion=1&all-projects=true"); err != nil {
			return nil, err
		}
	}
	data["profiles"], data["volumes"] = profiles, volumes
	return data, nil
}

func adoptionSettings(settings, data M) error {
	occupied := map[string]bool{}
	for _, p := range list(data["projects"]) {
		if str(obj(p)["name"]) == "lab" {
			return Public("Existing project lab conflicts with the Nixus namespace. Use the existing Nixus checkout to resume, or migrate that project explicitly; no changes made")
		}
	}
	for _, k := range []string{"networks", "pools"} {
		for _, i := range list(data[k]) {
			occupied[str(obj(i)["name"])] = true
		}
	}
	available := func(prefix string) string {
		if !occupied[prefix] {
			return prefix
		}
		for i := 1; i < 100; i++ {
			if n := prefix + strconv.Itoa(i); !occupied[n] {
				return n
			}
		}
		return prefix
	}
	guests, storage, connectivity := obj(settings["guests"]), obj(settings["storage"]), obj(settings["connectivity"])
	guests["bridge"] = available("nixusbr")
	storage["pool"] = available("nixus-guests")
	storage["source"] = "/var/lib/incus/storage-pools/" + str(storage["pool"])
	connectivity["guestInterfaces"] = []any{guests["bridge"]}
	preserved := []any{}
	for _, n := range list(data["networks"]) {
		nm := obj(n)
		if isTrue(nm["managed"]) && str(nm["type"]) == "bridge" {
			preserved = append(preserved, nm["name"])
		}
	}
	connectivity["preservedIncusBridges"] = preserved
	return nil
}

var incusIdentity = re(`[A-Za-z0-9][A-Za-z0-9_.-]*`)

func adoptionBackup(data M, directory string) error {
	os.MkdirAll(directory, 0o700)
	if err := writeJSON(filepath.Join(directory, "inventory.json"), data); err != nil {
		return err
	}
	for _, raw := range list(data["instances"]) {
		instance := obj(raw)
		project, name := str(instance["project"]), str(instance["name"])
		if project == "" {
			project = "default"
		}
		if !fullmatch(incusIdentity, project) || !fullmatch(incusIdentity, name) {
			return Public("Unsafe Incus identity in adoption inventory")
		}
		output := filepath.Join(directory, project, name+".tar.gz")
		os.MkdirAll(filepath.Dir(output), 0o700)
		temporary := filepath.Join(directory, project, name+".tar.partial")
		os.Remove(temporary)
		if _, err := check([]string{"incus", "--force-local", "export", name, temporary, "--project", project, "--compression", "gzip"}, nil, 2*time.Hour); err != nil {
			return Public("Incus export failed for " + project + "/" + name)
		}
		if info, err := os.Stat(temporary); err != nil || info.Size() == 0 {
			return Public("Incus export produced no backup for " + project + "/" + name)
		}
		os.Chmod(temporary, 0o600)
		if err := os.Rename(temporary, output); err != nil {
			return err
		}
		atomicString(output+".complete", strconv.FormatFloat(now(), 'f', -1, 64), 0o600)
	}
	for pool, vols := range obj(data["volumes"]) {
		for _, raw := range list(vols) {
			volume := obj(raw)
			if str(volume["type"]) != "custom" {
				continue
			}
			project, name := str(volume["project"]), str(volume["name"])
			if project == "" {
				project = "default"
			}
			if !fullmatch(incusIdentity, pool) || !fullmatch(incusIdentity, project) || !fullmatch(incusIdentity, name) {
				return Public("Unsafe custom volume identity")
			}
			output := filepath.Join(directory, "volumes", pool, project, name+".tar.gz")
			os.MkdirAll(filepath.Dir(output), 0o700)
			temporary := filepath.Join(filepath.Dir(output), name+".tar.partial")
			os.Remove(temporary)
			if _, err := check([]string{"incus", "--force-local", "storage", "volume", "export", pool, name, temporary,
				"--project", project, "--compression", "gzip"}, nil, 2*time.Hour); err != nil {
				return Public("Custom volume export failed: " + pool + "/" + name)
			}
			if info, err := os.Stat(temporary); err != nil || info.Size() == 0 {
				return Public("Custom volume export produced no backup: " + pool + "/" + name)
			}
			os.Chmod(temporary, 0o600)
			if err := os.Rename(temporary, output); err != nil {
				return err
			}
		}
	}
	return writeJSON(filepath.Join(directory, "complete.json"), M{"completedAt": now(), "guests": len(list(data["instances"]))})
}

// --- direct conversion ---------------------------------------------------------------

const directPrincipal = "root-direct-install"
const wizardPrincipal = "root-wizard-install"

func directPrepare(settings, overview, host M, keyFiles []string, subnet string, previousGuests M, remote bool, passwordLogin *bool) (M, error) {
	candidate := cloneM(settings)
	keySet := map[string]bool{}
	for _, k := range list(candidate["adminKeys"]) {
		keySet[str(k)] = true
	}
	for _, k := range list(overview["adminKeys"]) {
		keySet[str(k)] = true
	}
	for _, p := range keyFiles {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, Public("Unable to read SSH public key file")
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if l := strings.TrimSpace(line); l != "" && !strings.HasPrefix(line, "#") {
				keySet[l] = true
			}
		}
	}
	candidate["adminKeys"] = strings2any(sortedKeys(keySet))
	access := obj(candidate["access"])
	if access == nil {
		access = M{}
		candidate["access"] = access
	}
	login := true
	if passwordLogin != nil {
		login = *passwordLogin
	} else if v, ok := access["sshPasswordLogin"].(bool); ok {
		login = v
	}
	access["sshPasswordLogin"] = login
	if remote && len(keySet) == 0 && !login {
		return nil, Public("Remote installation needs your client SSH public key (--ssh-key laptop.pub), or explicitly retain password login with --ssh-password-login. Local console installation needs neither.")
	}
	if len(list(overview["wpaProfiles"])) > 0 && isTrue(jget(candidate, "radios", "wifi", "enable")) {
		return nil, Public("Direct switch cannot migrate legacy wpa_supplicant credentials; use Ethernet or the setup wizard")
	}
	guests := obj(candidate["guests"])
	if previousGuests != nil {
		if subnet != "" && subnet != str(previousGuests["cidr"]) {
			return nil, Public("A partially initialized Incus network cannot change on resume")
		}
		for k, v := range cloneM(previousGuests) {
			guests[k] = v
		}
	} else {
		network, err := guestNetwork(list(host["routes"]), subnet)
		if err != nil {
			return nil, err
		}
		for k, v := range network {
			guests[k] = v
		}
	}
	if !isTrue(settings["ready"]) {
		obj(candidate["cockpit"])["enable"] = true
		obj(candidate["maintenance"])["laptopMode"] = true
		obj(candidate["management"])["configure"] = false
	}
	return validateSettings(candidate, settings, host, false)
}

func waitFor(m *Manager, id string, statuses ...string) (M, error) {
	deadline := time.Now().Add(3 * time.Hour)
	dir, err := m.jobPath(id)
	if err != nil {
		return nil, err
	}
	logPath := filepath.Join(dir, "build.log")
	var position int64
	for time.Now().Before(deadline) {
		if f, err := os.Open(logPath); err == nil {
			f.Seek(position, 0)
			buf := make([]byte, 1<<20)
			n, _ := f.Read(buf)
			position += int64(n)
			f.Close()
			if n > 0 {
				fmt.Print(publicProgress(string(buf[:n])))
			}
		}
		m.status()
		record, err := m.job(id)
		if err != nil {
			return nil, err
		}
		s := str(record["status"])
		for _, want := range statuses {
			if s == want {
				return record, nil
			}
		}
		if s == "failed" || s == "rolled-back" || s == "cancelled" {
			return nil, Public("Direct conversion failed; inspect transaction status and log: " + logPath)
		}
		time.Sleep(time.Second)
	}
	return nil, Public("Conversion timed out; inspect " + logPath + " and the transaction status before retrying")
}

func directActivate(m *Manager, candidate, effective M, staged, expected string) (M, error) {
	if effective == nil {
		effective = candidate
	}
	if isTrue(jget(effective, "cockpit", "enable")) && isTrue(jget(effective, "cockpit", "managePassword")) && !isTrue(jget(effective, "secrets", "enable")) {
		if err := ensureOperatorPassword(); err != nil {
			return nil, err
		}
	}
	reviewed, err := m.review(candidate, ReviewOptions{Secrets: M{}, Principal: directPrincipal, StagedSource: staged, ExpectedDigest: expected})
	if err != nil {
		return nil, err
	}
	id := str(reviewed["id"])
	fmt.Println("Building hypervisor; transaction " + id)
	if _, err := waitFor(m, id, "ready"); err != nil {
		return nil, err
	}
	fmt.Println("Switching to the built hypervisor generation.")
	if _, err := m.apply(id); err != nil {
		return nil, err
	}
	record, err := waitFor(m, id, "awaiting-confirmation")
	if err != nil {
		return nil, err
	}
	pendingAccess(id, record)
	return record, nil
}

func wizardActivate(m *Manager, staged, expected string) (M, error) {
	reviewed, err := m.review(M{}, ReviewOptions{Principal: wizardPrincipal, HostRole: "bootstrap", StagedSource: staged, ExpectedDigest: expected})
	if err != nil {
		return nil, err
	}
	id := str(reviewed["id"])
	fmt.Println("Building initial onboarding; transaction " + id)
	if _, err := waitFor(m, id, "ready"); err != nil {
		return nil, err
	}
	if _, err := m.apply(id); err != nil {
		return nil, err
	}
	record, err := waitFor(m, id, "awaiting-confirmation")
	if err != nil {
		return nil, err
	}
	pendingAccess(id, record)
	return record, nil
}

func directResume(m *Manager, record M, principal string) (M, error) {
	if str(record["principal"]) != principal {
		return nil, Public("Another configuration transaction is active; finish it in its original entrypoint or the portal")
	}
	id := str(record["id"])
	var err error
	switch str(record["status"]) {
	case "rolling-back":
		return waitFor(m, id, "rolled-back")
	case "building":
		if record, err = waitFor(m, id, "ready"); err != nil {
			return nil, err
		}
	}
	switch str(record["status"]) {
	case "ready":
		if _, err := m.apply(id); err != nil {
			return nil, err
		}
		fallthrough
	case "applying":
		if record, err = waitFor(m, id, "awaiting-confirmation"); err != nil {
			return nil, err
		}
	}
	if str(record["status"]) == "awaiting-confirmation" {
		settings := obj(record["effectiveSettings"])
		if settings == nil {
			settings = obj(record["settings"])
		}
		if _, err := waitReady(settings, 0); err != nil {
			return nil, err
		}
		pendingAccess(id, record)
	}
	return record, nil
}

// --- install ----------------------------------------------------------------------------

func chooseNetwork(iface, address string) (string, string, int, string, error) {
	out, err := hostRun("ip", "-j", "-4", "route", "show", "default")
	if err != nil {
		return "", "", 0, "", err
	}
	routesAny, _ := parseJSON(out)
	routes := list(routesAny)
	if iface == "" {
		sort.SliceStable(routes, func(i, j int) bool {
			a, _ := num(obj(routes[i])["metric"])
			b, _ := num(obj(routes[j])["metric"])
			return a < b
		})
		if len(routes) == 0 {
			return "", "", 0, "", Public("No default IPv4 route; pass --interface for the management interface")
		}
		iface = str(obj(routes[0])["dev"])
	}
	out, err = hostRun("ip", "-j", "-4", "address", "show", "dev", iface)
	if err != nil {
		return "", "", 0, "", err
	}
	links, _ := parseJSON(out)
	var assigned []M
	for _, l := range list(links) {
		for _, a := range list(obj(l)["addr_info"]) {
			am := obj(a)
			if str(am["scope"]) == "global" && (address == "" || str(am["local"]) == address) {
				assigned = append(assigned, am)
			}
		}
	}
	if len(assigned) == 0 {
		return "", "", 0, "", Public("The selected management interface must already have a usable IPv4 address")
	}
	gateway := ""
	for _, r := range routes {
		if str(obj(r)["dev"]) == iface && gateway == "" {
			gateway = str(obj(r)["gateway"])
		}
	}
	prefix, _ := intValue(assigned[0]["prefixlen"])
	return iface, str(assigned[0]["local"]), prefix, gateway, nil
}

func copyNixModules(source, target string) error {
	if !isFile(filepath.Join(source, "configuration.nix")) || !isFile(filepath.Join(source, "hardware-configuration.nix")) {
		return Public("/etc/nixos must contain configuration.nix and hardware-configuration.nix")
	}
	return filepath.WalkDir(source, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".nix") {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return Public("Resolve configuration symlinks before conversion: " + p)
		}
		rel, _ := filepath.Rel(source, p)
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		dest := filepath.Join(target, rel)
		os.MkdirAll(filepath.Dir(dest), 0o755)
		return os.WriteFile(dest, data, 0o644)
	})
}

func copyTree(source, target string, symlinks bool) error {
	return filepath.WalkDir(source, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(source, p)
		dest := filepath.Join(target, rel)
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			if !symlinks {
				return Public("Unexpected symlink in source: " + rel)
			}
			link, _ := os.Readlink(p)
			return os.Symlink(link, dest)
		case info.IsDir():
			return os.MkdirAll(dest, info.Mode().Perm()|0o700)
		default:
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(dest, data, info.Mode().Perm())
		}
	})
}

func copyEmbeddedCheckout(source, target, repository, revision string) error {
	if !isFile(filepath.Join(source, "flake.nix")) || !isFile(filepath.Join(source, "flake.lock")) {
		return Public("Bundled checkout needs flake.nix and flake.lock")
	}
	if lexists(filepath.Join(source, ".git")) {
		if _, err := hostRun("git", "clone", "--no-hardlinks", source, target); err != nil {
			return err
		}
		_, err := hostRun("git", "-C", target, "remote", "set-url", "origin", repository)
		return err
	}
	if err := copyTree(source, target, false); err != nil {
		return err
	}
	if fullmatch(sha40, revision) {
		writeJSON(filepath.Join(target, "platform-release.json"), M{"version": platformVersion(source), "revision": revision, "repository": repository})
	}
	for _, args := range [][]string{{"init", "-q", "-b", "nixus-source"}, {"add", "."},
		{"-c", "user.name=Nixus installer", "-c", "user.email=installer@nixus.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "Initialize bundled Nixus source"},
		{"remote", "add", "origin", repository}} {
		if _, err := hostRun(append([]string{"git", "-C", target}, args...)...); err != nil {
			return err
		}
	}
	return nil
}

func nixEval(root, attribute string) (M, error) {
	out, err := hostRun("nix", "--extra-experimental-features", "nix-command flakes", "eval", "--json", "path:"+root+"#"+attribute)
	if err != nil {
		return nil, err
	}
	return parseObject(out)
}

func validateKeys(keys []any) error {
	f, err := os.CreateTemp("", "nixus-key-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	f.Close()
	for _, k := range keys {
		os.WriteFile(f.Name(), []byte(str(k)+"\n"), 0o600)
		if _, err := hostRun("ssh-keygen", "-l", "-f", f.Name()); err != nil {
			return Public("Invalid SSH public key")
		}
	}
	return nil
}

func validateKVM(vendor string) error {
	module := "kvm_intel"
	if vendor == "amd" {
		module = "kvm_amd"
	}
	if _, err := hostRun("modprobe", module); err != nil {
		return err
	}
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return Public("Hardware virtualization is unavailable; enable it in firmware")
	}
	defer f.Close()
	v, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), 0xAE00, 0)
	if errno != 0 || v != 12 {
		return Public("Hardware virtualization is unavailable; enable it in firmware")
	}
	return nil
}

func publishEtc() error {
	backup := "/etc/nixos.pre-nixus"
	if isSymlink(originalNixos) && resolvedOr(originalNixos) == resolvedOr(installTarget) {
		return nil
	}
	if lexists(originalNixos) {
		if lexists(backup) {
			return Public("Both /etc/nixos and /etc/nixos.pre-nixus exist; inspect them before linking the managed config")
		}
		if err := os.Rename(originalNixos, backup); err != nil {
			return err
		}
		os.Chmod(backup, 0o700)
	}
	return os.Symlink(installTarget, originalNixos)
}

func installSummary(settings, record M) {
	address, _ := managementAddress(settings)
	if !isTrue(jget(settings, "management", "configure")) {
		fmt.Println("Preserving current addressing: " + address + ". DHCP is retained; no static address was assigned.")
	}
	fmt.Printf("Nixus: https://%s:%v\n", address, jget(settings, "setup", "port"))
	fmt.Println("Next: open that address and sign in with your Linux account (one with sudo), then finish setup there.")
	if isTrue(settings["ready"]) {
		fmt.Println("Incus: https://" + address + ":8443 (create/import a browser certificate from the Nixus portal)")
		if isTrue(jget(settings, "cockpit", "enable")) {
			fmt.Printf("Cockpit: https://%s:%v (existing non-root Linux account/password)\n", address, jget(settings, "cockpit", "port"))
			if isTrue(jget(settings, "cockpit", "managePassword")) {
				fmt.Println("Set a persistent managed Linux operator password in the portal under Host > Services, then review and activate it.")
			} else {
				fmt.Println("Linux operator recovery: use an authorized host terminal and sudo passwd operator.")
			}
		}
		fmt.Println("All enabled management endpoints passed health checks. No disks were formatted.")
		if isTrue(record["rebootRequired"]) {
			fmt.Println("Reboot to use the new kernel; then run sudo nixus doctor.")
		}
	}
	out, _ := hostRun("openssl", "x509", "-in", filepath.Join(STATE, "ca.crt"), "-noout", "-fingerprint", "-sha256")
	fmt.Println("Local management CA: " + strings.TrimSpace(string(out)))
	if len(list(settings["adminKeys"])) == 0 {
		fmt.Println("No administrator key enrolled. Local console access remains available.")
		fmt.Println("Enroll your laptop PUBLIC key later: sudo nixus enroll-key /path/to/laptop.pub")
	}
	if isTrue(jget(settings, "access", "sshPasswordLogin")) {
		fmt.Println("SSH password login: enabled for existing non-root accounts")
	} else {
		fmt.Println("SSH password login: disabled")
	}
	fmt.Println("Later rebuilds: sudo nixos-rebuild switch --flake path:/etc/nixos#hypervisor")
	fmt.Println("Diagnostics: sudo nixus doctor")
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

type installArgs struct {
	checkout, repo, ref, iface, address, guestSubnet, answers, workloads, accessMode, guestNetwork string
	trusted, sshKeys                                                                               multiFlag
	wizard, adopt, noUpdate, interactive, planOnly, laptop, noMonitoring, noPasswordLogin          bool
}

func memTotalKiB() int {
	for _, line := range strings.Split(readText("/proc/meminfo"), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			if f := strings.Fields(line); len(f) > 1 {
				v, _ := strconv.Atoi(f[1])
				return v
			}
		}
	}
	return 0
}

func installMain(argv []string) int {
	syscall.Umask(0o077)
	fs := flag.NewFlagSet("nixus-install", flag.ContinueOnError)
	var a installArgs
	fs.StringVar(&a.checkout, "checkout", "", "Reviewed source supplied by the Nix launcher")
	fs.StringVar(&a.repo, "repo", installRepository, "")
	fs.StringVar(&a.ref, "ref", "main", "")
	fs.StringVar(&a.iface, "interface", "", "")
	fs.StringVar(&a.address, "address", "", "An IPv4 address already assigned to the selected interface")
	fs.Var(&a.trusted, "trusted-cidr", "")
	fs.Bool("resume", false, "Compatibility flag; retries resume automatically")
	fs.Bool("switch", true, "Install the full stack (default)")
	fs.BoolVar(&a.wizard, "wizard", false, "Only bootstrap the optional web wizard")
	fs.Var(&a.sshKeys, "ssh-key", "Client public key file, never a private key")
	fs.Bool("ssh-password-login", true, "")
	fs.BoolVar(&a.noPasswordLogin, "no-ssh-password-login", false, "")
	fs.StringVar(&a.guestSubnet, "guest-subnet", "", "Unused private IPv4 /24")
	fs.BoolVar(&a.adopt, "adopt-incus", false, "")
	fs.BoolVar(&a.noUpdate, "no-update", false, "")
	fs.BoolVar(&a.interactive, "interactive", false, "")
	fs.Bool("non-interactive", false, "")
	fs.StringVar(&a.answers, "answers", "", "")
	fs.BoolVar(&a.planOnly, "plan-only", false, "")
	fs.StringVar(&a.workloads, "workloads", "", "")
	fs.StringVar(&a.accessMode, "access-mode", "", "")
	fs.StringVar(&a.guestNetwork, "guest-network", "", "")
	fs.BoolVar(&a.laptop, "laptop-mode", false, "")
	fs.BoolVar(&a.noMonitoring, "no-monitoring", false, "")
	if err := fs.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	release, err := lockFile("/run/lock/nixus-install.lock", false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Another Nixus installer is already running")
		return 1
	}
	defer release()
	if err := installRun(a); err != nil {
		var usage usageError
		if errors.As(err, &usage) {
			fmt.Fprintln(os.Stderr, "nixus-install: "+string(usage))
			return 2
		}
		fmt.Fprintln(os.Stderr, "\nINSTALLATION FAILED: "+publicError(err))
		if writeJSON(filepath.Join(STATE, "installation-failure.json"), M{"error": "Installation did not complete", "time": now()}) == nil {
			fmt.Fprintln(os.Stderr, "Failure report: "+filepath.Join(STATE, "installation-failure.json"))
			fmt.Fprintln(os.Stderr, "Retry the same install command; completed work is detected automatically.")
			fmt.Fprintln(os.Stderr, "Diagnostics: sudo nixus doctor (once host tools are installed).")
		}
		return 1
	}
	return 0
}

type usageError string

func (u usageError) Error() string { return string(u) }

func installRun(a installArgs) error {
	switchMode := !a.wizard
	if os.Geteuid() != 0 || !exists("/etc/NIXOS") {
		return usageError("Run as root on an installed NixOS system")
	}
	if machineArch() != "x86_64" {
		return usageError("This release supports Intel/AMD x86_64 NixOS hosts")
	}
	remote := remoteSession()
	terminal := isTerminal()
	if a.interactive && !terminal {
		return usageError("--interactive requires a terminal; use --answers for unattended provisioning")
	}
	selectedFlags := a.workloads != "" || a.accessMode != "" || a.guestNetwork != "" || a.laptop || a.noMonitoring || a.guestSubnet != ""
	if a.planOnly && !terminal && a.answers == "" && !selectedFlags {
		return usageError("--plan-only without a terminal requires --answers or explicit CLI selections")
	}
	if a.answers != "" && a.interactive {
		return usageError("Choose either --answers or --interactive, not both")
	}
	if !switchMode && (a.interactive || a.answers != "" || a.planOnly || selectedFlags) {
		return usageError("--wizard bootstraps only the web UI; use --switch for a reviewed home-server plan")
	}
	existing := exists(installTarget)
	if existing && !isFile(machinePath(installTarget, "installation")) {
		return usageError("Existing checkout has no intact installation inventory; inspect it before proceeding (no configuration changed)")
	}
	manager := NewManager(installTarget, "")
	if existing {
		status, err := manager.status()
		if err != nil {
			return err
		}
		current := obj(status["job"])
		if current == nil {
			current = M{}
		}
		if a.planOnly && (isActiveStatus(str(current["status"])) || len(readObj(filepath.Join(STATE, "pending.json"))) > 0) {
			return usageError("A transaction or recovery is active; --plan-only will not resume or mutate it")
		}
		if current, err = finishInterruptedRecovery(manager, current); err != nil {
			return err
		}
		if isActiveStatus(str(current["status"])) {
			bootstrapJob := str(current["hostRole"]) == "bootstrap"
			if bootstrapJob && switchMode {
				return usageError("An initial wizard transaction is active; rerun with --wizard or finish it in the portal")
			}
			if !bootstrapJob && !switchMode {
				return usageError("A full installation transaction is active; rerun without --wizard to resume it")
			}
			// A candidate that was never applied may have been built from an older
			// copy of Nixus (an earlier attempt). Discard it and stage this
			// command's source instead; only resume once activation has begun.
			if !bootstrapJob && (str(current["status"]) == "building" || str(current["status"]) == "ready") && a.checkout != "" && !a.noUpdate {
				fmt.Println("Discarding unapplied candidate " + str(current["id"]) + " from an earlier attempt; staging this version.")
				if _, err := manager.cancel(str(current["id"])); err != nil {
					return err
				}
				current = nil
			}
		}
		if current != nil && isActiveStatus(str(current["status"])) {
			bootstrapJob := str(current["hostRole"]) == "bootstrap"
			fmt.Println("Resuming transaction " + str(current["id"]))
			principal := directPrincipal
			if bootstrapJob {
				if str(current["principal"]) != wizardPrincipal {
					return Public("Another transaction is active; finish it in its original entrypoint")
				}
				principal = wizardPrincipal
			}
			resumed, err := directResume(manager, current, principal)
			if err != nil {
				return err
			}
			if str(resumed["status"]) != "rolled-back" {
				settings, err := manager.effectiveSettings(nil)
				if err != nil {
					return err
				}
				if err := publishEtc(); err != nil {
					return err
				}
				installSummary(settings, resumed)
				return nil
			}
		}
		if !switchMode && (isTrue(status["setupComplete"]) || isTrue(jget(status, "effectiveSettings", "ready"))) {
			return usageError("--wizard is for initial onboarding only; this host is already configured. Use the console or #update. Forgot your password? Reset it with passwd at the console.")
		}
	}
	iface, address, prefix, gateway, err := chooseNetwork(a.iface, a.address)
	if err != nil {
		return err
	}
	trusted := []string(a.trusted)
	if len(trusted) == 0 {
		p, _ := netip.ParsePrefix(fmt.Sprintf("%s/%d", address, prefix))
		trusted = []string{p.Masked().String()}
	}
	if conn := os.Getenv("SSH_CONNECTION"); conn != "" {
		client, err := netip.ParseAddr(strings.Fields(conn)[0])
		if err != nil || !client.Is4() {
			return usageError("Use the local console for an IPv6-only SSH session")
		}
		set := map[string]bool{client.String() + "/32": true}
		for _, t := range trusted {
			set[t] = true
		}
		trusted = sortedKeys(set)
	}
	addr, _ := netip.ParseAddr(address)
	covered := false
	for _, t := range trusted {
		p, err := netip.ParsePrefix(t)
		if err != nil || !p.Addr().Is4() || p.Masked() != p {
			return usageError("Use trusted IPv4 CIDRs for this release")
		}
		covered = covered || p.Contains(addr)
	}
	if !covered {
		trusted = append(trusted, address+"/32")
	}
	host := hostInventory()
	host["memoryKiB"] = memTotalKiB()
	if v := str(host["cpuVendor"]); v != "intel" && v != "amd" {
		return usageError("CPU vendor could not be identified safely")
	}
	var adoption M
	if !existing && exists("/var/lib/incus/database") {
		if adoption, err = incusAdoptionInventory(); err != nil {
			return err
		}
		fmt.Printf("Existing Incus: %d guests. Adoption creates separate resources and backs up existing guests.\n", len(list(adoption["instances"])))
		if !a.adopt && !a.planOnly && (!terminal || !askYes("Back up and adopt this Incus host?")) {
			return usageError("Adoption was not selected; no changes made. Use --adopt-incus after reviewing existing guests.")
		}
		if a.planOnly {
			fmt.Println("Plan only: existing Incus adoption would require --adopt-incus and a complete independent backup.")
		}
	}
	temporary, err := os.MkdirTemp("", "nixus-plan-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	stage := filepath.Join(temporary, "config")
	var sourceDigest string
	var defaults M
	if existing {
		if sourceDigest, err = digestSource(installTarget); err != nil {
			return err
		}
		incoming := a.checkout
		if a.noUpdate {
			incoming = ""
		}
		_, edits, err := stageUpdate(installTarget, incoming, stage, filepath.Join(STATE, "platform-baseline.json"))
		if err != nil {
			return err
		}
		if len(edits) > 0 {
			fmt.Println("Preserving local platform edits; source update skipped: " + strings.Join(edits, ", "))
		}
		if defaults, err = readSettings(stage); err != nil {
			return err
		}
	} else {
		if !isDir(resolvedOr(originalNixos)) || !isFile(filepath.Join(originalNixos, "configuration.nix")) || !isFile(filepath.Join(originalNixos, "hardware-configuration.nix")) {
			return usageError("A conventional /etc/nixos installation with both configuration files is required")
		}
		if lexists("/etc/nixos.pre-nixus") {
			return usageError("/etc/nixos.pre-nixus already exists; inspect it before conversion")
		}
		if a.checkout != "" {
			if err := copyEmbeddedCheckout(resolvedOr(a.checkout), stage, a.repo, a.ref); err != nil {
				return err
			}
		} else if _, err := hostRun("git", "clone", "--single-branch", "--branch", a.ref, a.repo, stage); err != nil {
			return err
		}
		writeJSON(filepath.Join(stage, "machine/format.json"), M{"version": 1})
		if err := copyNixModules(resolvedOr(originalNixos), machinePath(stage, "installed")); err != nil {
			return err
		}
		if defaults, err = nixEval(stage, "nixusDefaults"); err != nil {
			return err
		}
		hostname, _ := os.Hostname()
		defaults["system"], defaults["cpuVendor"], defaults["hostName"] = "x86_64-linux", host["cpuVendor"], strings.SplitN(hostname, ".", 2)[0]
		obj(defaults["setup"])["enable"] = true
		keyFile := str(jget(defaults, "secrets", "ageKeyFile"))
		if !a.planOnly {
			if _, err := ensureIdentity(keyFile); err != nil {
				return err
			}
			if _, err := hostSecretsInitialize(stage, keyFile); err != nil {
				return err
			}
		}
		obj(defaults["secrets"])["enable"], obj(defaults["secrets"])["hostFile"] = true, hostSecretsRelative
		wireless := exists(filepath.Join("/sys/class/net", iface, "wireless"))
		wifi := obj(jget(defaults, "radios", "wifi"))
		wifi["enable"], wifi["interface"] = wireless, ""
		if wireless {
			wifi["interface"] = iface
		}
		if zone := resolvedOr("/etc/localtime"); strings.Contains(zone, "/zoneinfo/") {
			obj(defaults["maintenance"])["timeZone"] = strings.SplitN(zone, "/zoneinfo/", 2)[1]
		}
	}
	if !isTrue(jget(defaults, "management", "configure")) {
		mgmt := obj(defaults["management"])
		mgmt["interface"], mgmt["address"], mgmt["prefixLength"], mgmt["gateway"], mgmt["trustedCIDRs"] = iface, address, prefix, gateway, strings2any(trusted)
	}
	if adoption != nil {
		if err := adoptionSettings(defaults, adoption); err != nil {
			return err
		}
	}
	flags := M{}
	for k, v := range map[string]string{"workloads": a.workloads, "access": a.accessMode, "network": a.guestNetwork, "guestSubnet": a.guestSubnet} {
		if v != "" {
			flags[k] = v
		}
	}
	if a.laptop {
		flags["laptop"] = true
	}
	if a.noMonitoring {
		flags["monitoring"] = false
	}
	var proposal M
	if a.answers != "" || a.interactive || len(flags) > 0 || a.planOnly {
		draft := filepath.Join(STATE, "installer-intent-draft.json")
		chosen := intentDefaults()
		if a.answers != "" {
			if chosen, err = loadIntent(a.answers); err != nil {
				return err
			}
		}
		if existing && isTrue(defaults["ready"]) && a.answers == "" {
			chosen["laptop"], chosen["monitoring"] = jget(defaults, "maintenance", "laptopMode"), jget(defaults, "monitoring", "collection")
		}
		if a.interactive {
			if isFile(draft) && !a.planOnly {
				if n, err := normalizeIntent(readObj(draft)); err == nil {
					chosen = n
					fmt.Println("Resuming previous non-secret installer interview draft.")
				}
			}
			if chosen, err = interview(chosen, func(v M) {
				if !a.planOnly {
					writeJSON(draft, v)
				}
			}); err != nil {
				return err
			}
		}
		for k, v := range flags {
			chosen[k] = v
		}
		if chosen, err = normalizeIntent(chosen); err != nil {
			return err
		}
		if proposal, err = intentPlan(chosen, host, defaults, remote); err != nil {
			return err
		}
		intentPreview(proposal)
		if a.planOnly {
			fmt.Println("Plan only: no source, network, guest, or system changes were made.")
			return nil
		}
		if a.interactive && !askYes("Apply this reviewed plan using the guarded Nixus installer?") {
			fmt.Println("Cancelled before publishing any configuration.")
			return nil
		}
	}
	if err := writeJSON(machinePath(stage, "settings"), defaults); err != nil {
		return err
	}
	overview, err := nixEval(stage, "nixusOverview")
	if err != nil {
		return err
	}
	for _, home := range []string{"/root", filepath.Join("/home", os.Getenv("SUDO_USER"))} {
		raw, err := os.ReadFile(filepath.Join(home, ".ssh/authorized_keys"))
		if err != nil {
			continue
		}
		keys := list(overview["adminKeys"])
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "ssh-ed25519 ") || strings.HasPrefix(line, "ssh-rsa ") || strings.HasPrefix(line, "ecdsa-sha2-") {
				keys = append(keys, strings.TrimSpace(line))
			}
		}
		overview["adminKeys"] = keys
	}
	installation := readObj(machinePath(stage, "installation"))
	prior := M{}
	if existing {
		if id := str(readObj(filepath.Join(STATE, "active.json"))["id"]); id != "" {
			prior = readObj(filepath.Join(STATE, "jobs", id, "job.json"))
		}
	}
	var previousGuests M
	if isTrue(defaults["ready"]) {
		previousGuests = obj(defaults["guests"])
	} else if prior["previousSystem"] != nil {
		previousGuests = obj(jget(prior, "settings", "guests"))
	}
	var candidate, effective M
	if switchMode {
		subnet := a.guestSubnet
		if proposal != nil {
			subnet = str(proposal["guestSubnet"])
		}
		login := !a.noPasswordLogin
		if candidate, err = directPrepare(defaults, overview, host, a.sshKeys, subnet, previousGuests, remote, &login); err != nil {
			return err
		}
		if proposal != nil {
			obj(candidate["maintenance"])["laptopMode"] = proposal["laptop"]
			obj(candidate["monitoring"])["collection"] = proposal["monitoring"]
			if candidate, err = validateSettings(candidate, defaults, host, false); err != nil {
				return err
			}
		}
		if err := validateKeys(list(candidate["adminKeys"])); err != nil {
			return err
		}
		if err := validateKVM(str(candidate["cpuVendor"])); err != nil {
			return err
		}
		if len(cockpitAccounts()) == 0 {
			obj(candidate["cockpit"])["managePassword"] = true
			fmt.Println("No usable local administrator password was found; a stable operator login will be provisioned for SSH and Cockpit.")
		}
		writeJSON(machinePath(stage, "settings"), candidate)
		if effective, err = nixEval(stage, "nixusSettings"); err != nil {
			return err
		}
		writeJSON(machinePath(stage, "settings"), defaults)
		if err := validateKeys(list(effective["adminKeys"])); err != nil {
			return err
		}
		if remote && len(list(effective["adminKeys"])) == 0 && !isTrue(jget(effective, "access", "sshPasswordLogin")) {
			return Public("File-owned SSH settings remove remote login access; enroll a client key before activation")
		}
		if isTrue(jget(effective, "cockpit", "enable")) && len(cockpitAccounts()) == 0 && !isTrue(jget(effective, "cockpit", "managePassword")) {
			return Public("File-owned Cockpit settings require an existing usable Linux password or managePassword=true")
		}
		if isTrue(jget(effective, "access", "sshPasswordLogin")) {
			fmt.Println("SSH policy after activation: password login retained for existing non-root accounts")
		} else {
			fmt.Println("SSH policy after activation: password login disabled; keys/console remain available")
		}
	}
	installation["interface"], installation["trustedCIDRs"], installation["legacyWpaProfiles"] = iface, strings2any(trusted), overview["wpaProfiles"]
	if proposal != nil {
		installation["intent"], installation["pendingTasks"] = proposal["answers"], proposal["pending"]
	}
	if !existing {
		installation["installedAt"], installation["originalSystem"], installation["repository"], installation["ref"] = now(), resolvedOr("/run/current-system"), a.repo, a.ref
	}
	if err := writeJSON(machinePath(stage, "installation"), installation); err != nil {
		return err
	}
	if adoption != nil {
		destination := filepath.Join(STATE, "incus-adoption", strconv.FormatInt(time.Now().UnixNano(), 10))
		if err := adoptionBackup(adoption, destination); err != nil {
			return err
		}
		fmt.Println("Incus backups: " + destination)
	}
	os.MkdirAll(STATE, 0o700)
	if !existing {
		originalBackup := filepath.Join(STATE, "original-config")
		if !lexists(originalBackup) {
			if err := copyTree(resolvedOr(originalNixos), originalBackup, true); err != nil {
				return err
			}
			os.Chmod(originalBackup, 0o700)
		}
		os.MkdirAll(filepath.Dir(installTarget), 0o700)
		publishing := filepath.Join(filepath.Dir(installTarget), ".config-installing")
		os.RemoveAll(publishing)
		if err := copyTree(stage, publishing, true); err != nil {
			return err
		}
		os.Chmod(publishing, 0o700)
		if err := os.Rename(publishing, installTarget); err != nil {
			return err
		}
		if _, err := hostRun("nix-store", "--add-root", filepath.Join(STATE, "original-system"), "--indirect", "--realise", str(installation["originalSystem"])); err != nil {
			return err
		}
		hashes, err := platformHashes(installTarget)
		if err != nil {
			return err
		}
		baseline := M{}
		for k, v := range hashes {
			baseline[k] = v
		}
		writeJSON(filepath.Join(STATE, "platform-baseline.json"), baseline)
	} else {
		if d, _ := digestSource(installTarget); d != sourceDigest {
			return Public("Source changed during planning; retry to preserve the latest local changes")
		}
		if switchMode {
			writeJSON(machinePath(stage, "settings"), candidate)
		}
	}
	if pin := filepath.Join(STATE, "original-system"); !lexists(pin) && str(installation["originalSystem"]) != "" {
		if _, err := hostRun("nix-store", "--add-root", pin, "--indirect", "--realise", str(installation["originalSystem"])); err != nil {
			return err
		}
	}
	if switchMode && existing && str(prior["status"]) == "confirmed" {
		current, _ := manager.settings()
		stageDigest, _ := digestSource(stage)
		if equalJSON(candidate, current) && stageDigest == str(prior["candidateDigest"]) {
			settings, err := manager.effectiveSettings(nil)
			if err != nil {
				return err
			}
			if _, err := waitReady(settings, 0); err != nil {
				return err
			}
			if err := publishEtc(); err != nil {
				return err
			}
			installSummary(settings, prior)
			return nil
		}
	}
	if !exists(filepath.Join(STATE, "tls.key")) {
		if err := issueTLS(address, str(defaults["hostName"])); err != nil {
			return err
		}
	}
	staged, expected := "", ""
	if existing {
		staged, expected = stage, sourceDigest
	}
	var record M
	if switchMode {
		record, err = directActivate(manager, candidate, effective, staged, expected)
	} else {
		record, err = wizardActivate(manager, staged, expected)
	}
	if err != nil {
		return err
	}
	settings, err := manager.effectiveSettings(nil)
	if err != nil {
		return err
	}
	prepareStateAccess(false)
	if err := publishEtc(); err != nil {
		return err
	}
	installSummary(settings, record)
	if proposal != nil {
		for _, t := range list(proposal["pending"]) {
			fmt.Println("Pending commissioning: " + str(t))
		}
		os.Remove(filepath.Join(STATE, "installer-intent-draft.json"))
	}
	return nil
}

// --- update -------------------------------------------------------------------------------

const updatePrincipal = "root-update-command"

func alreadyCurrent(m *Manager, state M, revision string) bool {
	if str(jget(state, "release", "revision")) != revision {
		return false
	}
	id := str(jget(state, "lastConfirmed", "id"))
	if id == "" || str(state["currentSystem"]) == "" {
		return false
	}
	confirmed, err := m.job(id)
	digest, _ := digestSource(m.root)
	dir, _ := m.jobPath(id)
	return err == nil && str(confirmed["status"]) == "confirmed" && str(confirmed["candidateDigest"]) == digest &&
		resolvedOr(filepath.Join(dir, "system")) == str(state["currentSystem"])
}

func managementChange(settings M, iface string, saved M) (M, error) {
	current := obj(settings["management"])
	var link M
	for _, l := range list(hostInventory()["interfaces"]) {
		if str(obj(l)["name"]) == iface {
			link = obj(l)
		}
	}
	var addresses []netip.Prefix
	for _, raw := range list(link["addresses"]) {
		p, err := netip.ParsePrefix(str(raw))
		if err == nil && p.Addr().Is4() && !p.Addr().IsLoopback() && !p.Addr().IsLinkLocalUnicast() && !p.Addr().IsUnspecified() && !p.Addr().IsMulticast() {
			addresses = append(addresses, p)
		}
	}
	var selected *netip.Prefix
	for i := range addresses {
		if addresses[i].Addr().String() == str(current["address"]) {
			selected = &addresses[i]
		}
	}
	if selected == nil {
		if len(addresses) != 1 {
			return nil, Public("Selected interface needs one unambiguous usable IPv4 address")
		}
		selected = &addresses[0]
	}
	inside := false
	for _, c := range list(current["trustedCIDRs"]) {
		if p, err := netip.ParsePrefix(str(c)); err == nil && p.Contains(selected.Addr()) {
			inside = true
		}
	}
	if !inside {
		return nil, Public("Selected address is outside existing trusted management networks; review access policy first")
	}
	values := M{"interface": iface, "address": selected.Addr().String(), "prefixLength": selected.Bits()}
	matches, persisted := true, true
	for k, v := range values {
		matches = matches && equalJSON(current[k], v)
		if saved != nil {
			persisted = persisted && equalJSON(jget(saved, "management", k), v)
		}
	}
	if matches && persisted {
		return M{}, nil
	}
	return M{"management": values}, nil
}

func updateRun(m *Manager, iface string, repair *NetworkRepair) error {
	state, err := m.status()
	if err != nil {
		return err
	}
	record := obj(state["job"])
	if record == nil {
		record = M{}
	}
	if isActiveStatus(str(record["status"])) {
		if str(record["principal"]) != updatePrincipal || !fullmatch(sha40, str(record["platformRevision"])) {
			return Public("Another configuration transaction is active; finish it in the host console first")
		}
		if iface != "" && str(jget(record, "settings", "management", "interface")) != iface {
			return Public("Requested interface differs from the existing reviewed update; finish or cancel that update first")
		}
		fmt.Println("Resuming update to " + str(record["platformRevision"]))
	} else {
		if state["pending"] != nil && len(obj(state["pending"])) > 0 {
			return Public("Activation recovery is pending; resolve it in the host console first")
		}
		if !isTrue(state["setupComplete"]) {
			return Public("Finish initial Nixus setup before running #update")
		}
		changes := M{}
		if iface != "" {
			effective, err := m.effectiveSettings(nil)
			if err != nil {
				return err
			}
			saved, _ := m.settings()
			if changes, err = managementChange(effective, iface, saved); err != nil {
				return err
			}
		}
		revision, err := mainRevision()
		if err != nil {
			return err
		}
		fmt.Println("Nixus main: " + revision)
		if len(changes) == 0 && repair == nil && alreadyCurrent(m, state, revision) {
			fmt.Println("Platform source and active system are already current.")
			if isTrue(state["rebootRequired"]) {
				fmt.Println("A kernel reboot is pending; reboot separately when ready.")
			}
			return nil
		}
		if len(changes) > 0 {
			fmt.Println("Management selection: " + canonicalSpaced(changes["management"]))
		}
		opts := ReviewOptions{Revision: revision, Principal: updatePrincipal}
		if repair != nil {
			opts.Modules = obj(repair.record["modules"])
		}
		reviewed, err := m.review(changes, opts)
		if err != nil {
			return err
		}
		if repair != nil {
			repair.record["job"] = reviewed["id"]
			repair.save("reviewing")
		}
		fmt.Println("Building update; transaction " + str(reviewed["id"]))
		if record, err = m.job(str(reviewed["id"])); err != nil {
			return err
		}
	}
	id := str(record["id"])
	switch str(record["status"]) {
	case "rolling-back":
		waitFor(m, id, "rolled-back")
		return Public("Previous update rolled back; rerun #update to try again")
	case "building":
		if record, err = waitFor(m, id, "ready"); err != nil {
			return err
		}
	}
	switch str(record["status"]) {
	case "ready":
		if iface != "" {
			expected, effective := obj(jget(record, "settings", "management")), obj(jget(record, "effectiveSettings", "management"))
			bad := str(expected["interface"]) != iface
			for _, k := range []string{"interface", "address", "prefixLength"} {
				bad = bad || !equalJSON(effective[k], expected[k])
			}
			if bad {
				return Public("Built management selection differs from the request; review source-owned Nix overrides before activation")
			}
		}
		if repair != nil {
			if err := repair.verify(record); err != nil {
				return err
			}
		}
		plan := obj(record["impactPlan"])
		if plan == nil || plan["blocked"] != false {
			return Public("Update has an unavailable or blocked impact plan; inspect Changes in the host console")
		}
		fmt.Println("Proposed effects:")
		if migration := obj(record["settingsMigration"]); migration != nil && !equalJSON(migration["from"], migration["to"]) {
			fmt.Printf("  Settings schema migration: %v → %v; previous settings/source remain available for rollback.\n", migration["from"], migration["to"])
		}
		for _, c := range list(plan["changes"]) {
			msg := str(obj(c)["message"])
			if msg == "" {
				msg = "Review change"
			}
			fmt.Println("  " + msg)
		}
		fmt.Printf("Platform files changed: %d. Full review and dry-activation output: host console → Changes.\n", len(list(record["platformChanges"])))
		fmt.Println("Source code, pinned packages and services may change. Machine settings/modules are retained.")
		if !askYes("Activate this built update?") {
			m.cancel(id)
			return Public("Update cancelled before activation")
		}
		if _, err := m.apply(id); err != nil {
			return err
		}
		fallthrough
	case "applying":
		if record, err = waitFor(m, id, "awaiting-confirmation"); err != nil {
			return err
		}
	}
	if str(record["status"]) != "awaiting-confirmation" {
		return Public("Unexpected update state; inspect the host console")
	}
	err = func() error {
		if repair != nil {
			if err := repair.nativeIdentity(); err != nil {
				return err
			}
		}
		settings := obj(record["effectiveSettings"])
		if settings == nil {
			if settings, err = m.effectiveSettings(nil); err != nil {
				return err
			}
		}
		report, err := waitReady(settings, 0)
		if err != nil {
			return err
		}
		for _, c := range list(report["checks"]) {
			cm := obj(c)
			if n := str(cm["name"]); (n == "Nixus" || n == "Incus UI" || n == "Cockpit") && isTrue(cm["ok"]) {
				fmt.Println(n + ": " + str(cm["url"]))
			}
		}
		pendingAccess(id, record)
		return nil
	}()
	if err != nil {
		if j, jerr := m.job(id); jerr == nil && str(j["status"]) == "awaiting-confirmation" {
			if _, rerr := m.rollback(id); rerr == nil {
				waitFor(m, id, "rolled-back")
			} else {
				fmt.Fprintln(os.Stderr, "Rollback needs attention; inspect the host console before retrying.")
			}
		}
		return err
	}
	fmt.Println("Nixus update activated but NOT confirmed; a new management session must confirm before the rollback deadline.")
	if s, err := m.status(); err == nil && isTrue(s["rebootRequired"]) {
		fmt.Println("A kernel reboot is pending; reboot separately when ready.")
	}
	return nil
}

func updateMain(argv []string) int {
	syscall.Umask(0o027)
	fs := flag.NewFlagSet("nixus-update", flag.ContinueOnError)
	iface := fs.String("interface", "", "Use this already-addressed management interface through the reviewed update")
	repairNetwork := fs.Bool("repair-network", false, "At the local console, recover existing Ethernet/bridge connections before the guarded update")
	if err := fs.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	err := func() error {
		if os.Geteuid() != 0 || !isFile("/etc/NIXOS") {
			return Public("Run on the installed NixOS host with administrator privileges")
		}
		if !isFile(filepath.Join(ROOT, "flake.nix")) || !isFile(machinePath(ROOT, "settings")) {
			return Public("No installed Nixus configuration found; use #install for initial installation")
		}
		if !isTerminal() {
			return Public("#update requires an interactive terminal for activation and access confirmation")
		}
		m := NewManager("", "")
		if !*repairNetwork {
			return updateRun(m, *iface, nil)
		}
		repair := &NetworkRepair{manager: m, path: filepath.Join(m.state, "network-repair.json")}
		success := false
		defer func() {
			if ferr := repair.finish(success); ferr != nil {
				fmt.Fprintln(os.Stderr, publicError(ferr))
			}
		}()
		selected, err := repair.prepare(*iface)
		if err != nil {
			return err
		}
		if err := updateRun(m, selected, repair); err != nil {
			return err
		}
		success = true
		return nil
	}()
	if err != nil {
		fmt.Fprintln(os.Stderr, publicError(err))
		fmt.Fprintln(os.Stderr, "Update stopped; inspect host status before retrying. Unconfirmed activation retains automatic rollback.")
		return 1
	}
	return 0
}

// --- network repair ----------------------------------------------------------------------------

const repairModule = "nixus-network-autoconnect.nix"
const incusDatabase = "/var/lib/incus/database/local.db"
const repairDropin = "/run/systemd/system/nixus-management-identity.service.d/90-nixus-network-repair.conf"
const nmFields = "connection.uuid,connection.id,connection.type,connection.interface-name,connection.controller,connection.autoconnect"
const nmProjection = `c: builtins.mapAttrs (name: p: {
  id = p.connection.id or name;
  interface = p.connection."interface-name" or "";
  auto = p.connection.autoconnect or true;
}) c.networking.networkmanager.ensureProfiles.profiles`

var uuidRe = re(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
var nmIfaceName = re(`[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}`)
var profileName = re(`[A-Za-z0-9_.-]+`)

func repairRun(timeout time.Duration, args ...string) (string, error) {
	res, err := run(args, nil, timeout, append(os.Environ(), "LC_ALL=C"), "")
	if err != nil || res.Code != 0 {
		return "", Public("Network recovery command failed: " + args[0])
	}
	return string(res.Stdout), nil
}

func nmProfiles() ([]M, error) {
	deadline := time.Now().Add(30 * time.Second)
	out, err := repairRun(10*time.Second, "nmcli", "--get-values", "UUID", "connection", "show")
	if err != nil {
		return nil, err
	}
	ids := strings.Fields(out)
	if len(ids) > 128 {
		return nil, Public("Management recovery profile limit exceeded; review networking manually")
	}
	var result []M
	for _, id := range ids {
		if !fullmatch(uuidRe, id) || strings.ToLower(id) != id {
			return nil, Public("Invalid NetworkManager profile identity")
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, Public("Management profile observation exceeded its deadline")
		}
		if remaining > 5*time.Second {
			remaining = 5 * time.Second
		}
		out, err := repairRun(remaining, "nmcli", "--escape", "no", "--get-values", nmFields, "connection", "show", "uuid", id)
		if err != nil {
			return nil, err
		}
		values := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
		bad := len(values) != 6 || values[0] != id || (values[5] != "yes" && values[5] != "no")
		for _, v := range values {
			if cleanText(v) != v {
				bad = true
			}
		}
		if bad {
			return nil, Public("Ambiguous NetworkManager profile metadata; no profile was changed")
		}
		result = append(result, M{"uuid": values[0], "id": values[1], "type": values[2], "interface": values[3], "controller": values[4], "auto": values[5]})
	}
	return result, nil
}

func selectManagement(settings M, links []any, connections []M, requested string) (string, []M, error) {
	origin := requested
	if origin == "" {
		origin = str(jget(settings, "management", "interface"))
	}
	byName := map[string]M{}
	for _, l := range links {
		byName[str(obj(l)["ifname"])] = obj(l)
	}
	name := origin
	if master := str(byName[name]["master"]); master != "" {
		name = master
	}
	matchesRef := func(ref string, p M) bool {
		return ref == str(p["uuid"]) || ref == str(p["id"]) || ref == str(p["interface"])
	}
	var bound []M
	for _, p := range connections {
		if str(p["interface"]) == name {
			bound = append(bound, p)
		}
	}
	if len(bound) == 1 && str(bound[0]["controller"]) != "" {
		parent := str(bound[0]["controller"])
		var bridges []M
		for _, p := range connections {
			if str(p["type"]) == "bridge" && matchesRef(parent, p) {
				bridges = append(bridges, p)
			}
		}
		if len(bridges) != 1 {
			return "", nil, Public("Saved management port has an ambiguous bridge controller")
		}
		name = str(bridges[0]["interface"])
	}
	if !fullmatch(nmIfaceName, name) {
		return "", nil, Public("Invalid management interface")
	}
	if name == str(jget(settings, "guests", "bridge")) {
		return "", nil, Public("A guest network cannot become the management connection")
	}
	for _, g := range list(jget(settings, "connectivity", "guestInterfaces")) {
		if str(g) == name {
			return "", nil, Public("A guest network cannot become the management connection")
		}
	}
	var controllers []M
	for _, p := range connections {
		if t := str(p["type"]); str(p["interface"]) == name && (t == "bridge" || t == "802-3-ethernet") {
			controllers = append(controllers, p)
		}
	}
	if len(controllers) != 1 {
		return "", nil, Public("Repair requires one existing, interface-bound Ethernet/bridge profile; use --interface if needed")
	}
	controller := controllers[0]
	selected := []M{controller}
	if str(controller["type"]) == "bridge" {
		same := 0
		for _, p := range connections {
			if str(p["id"]) == str(controller["id"]) {
				same++
			}
		}
		if same != 1 {
			return "", nil, Public("Duplicate bridge profile names require manual review")
		}
		var ports []M
		for _, p := range connections {
			if c := str(p["controller"]); c != "" && (c == name || c == str(controller["uuid"]) || c == str(controller["id"])) {
				ports = append(ports, p)
			}
		}
		if len(ports) == 0 {
			return "", nil, Public("Management bridge needs existing Ethernet port profiles and connected hardware")
		}
		originIsPort := false
		for _, port := range ports {
			if _, ok := byName[str(port["interface"])]; str(port["type"]) != "802-3-ethernet" || !ok {
				return "", nil, Public("Management bridge needs existing Ethernet port profiles and connected hardware")
			}
			var targets []M
			for _, p := range connections {
				if str(p["type"]) == "bridge" && matchesRef(str(port["controller"]), p) {
					targets = append(targets, p)
				}
			}
			if len(targets) != 1 || str(targets[0]["uuid"]) != str(controller["uuid"]) {
				return "", nil, Public("Saved bridge port controller is ambiguous")
			}
			originIsPort = originIsPort || str(port["interface"]) == origin
		}
		selected = append(selected, ports...)
		if origin != name && !originIsPort {
			return "", nil, Public("Live bridge membership differs from saved management profiles")
		}
	}
	if isTrue(jget(settings, "management", "configure")) {
		return "", nil, Public("This recovery preserves existing networking; managed static networking needs a reviewed configuration change")
	}
	return name, selected, nil
}

func declaredProfiles(root string) (M, error) {
	out, err := repairRun(120*time.Second, "nix", "--extra-experimental-features", "nix-command flakes", "eval", "--json",
		"path:"+root+"#nixosConfigurations.hypervisor.config", "--apply", nmProjection)
	if err != nil {
		return nil, err
	}
	return parseObject([]byte(out))
}

func autoTrue(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true" || x == "yes"
	case float64:
		return x == 1
	}
	return false
}

func repairModules(root string, selected []M) (M, []any, error) {
	declared, err := declaredProfiles(root)
	if err != nil {
		return nil, nil, err
	}
	var names []string
	for name, raw := range declared {
		v := obj(raw)
		for _, p := range selected {
			if str(v["id"]) == str(p["id"]) && str(v["interface"]) == str(p["interface"]) && !autoTrue(v["auto"]) {
				names = append(names, name)
				break
			}
		}
	}
	if len(names) == 0 {
		return M{}, []any{}, nil
	}
	sort.Strings(names)
	for _, n := range names {
		if !fullmatch(profileName, n) {
			return nil, nil, Public("Unusual declarative profile names require manual review")
		}
	}
	if exists(filepath.Join(machinePath(root, "modules"), repairModule)) {
		return nil, nil, Public("The autoconnect recovery module already exists; review its overrides before retrying")
	}
	content := "# Nixus recovery: autoconnect existing management profiles only.\n{ lib, ... }: {\n  networking.networkmanager.ensureProfiles.profiles = lib.genAttrs\n" +
		"    (builtins.fromJSON " + canonical(canonicalSpaced(strings2any(names))) + ")\n    (_: { connection.autoconnect = lib.mkOverride 90 true; });\n}\n"
	return M{repairModule: content}, strings2any(names), nil
}

func checkProfiles(selected []any, observed []M) error {
	current := map[string]M{}
	for _, p := range observed {
		current[str(p["uuid"])] = p
	}
	for _, raw := range selected {
		p := obj(raw)
		c := current[str(p["uuid"])]
		for _, k := range []string{"id", "type", "interface", "controller"} {
			if c == nil || str(c[k]) != str(p[k]) {
				return Public("A saved management profile changed identity; refusing repair")
			}
		}
	}
	return nil
}

func repairDropinContent(settingsPath string) (string, error) {
	envBin, ip, openssl := lookPath("env"), lookPath("ip"), lookPath("openssl")
	if envBin == "" || ip == "" || openssl == "" {
		return "", Public("Recovery runtime needs env, ip and openssl")
	}
	toolPath := filepath.Dir(resolvedOr(ip)) + ":" + filepath.Dir(resolvedOr(openssl))
	args := []string{envBin, "PATH=" + toolPath, adminLauncher(), "admin", "network-identity", settingsPath}
	quoted := make([]string, len(args))
	for i, a := range args {
		if strings.ContainsAny(a, "%\n") {
			return "", Public("Unsupported recovery runtime path")
		}
		quoted[i] = canonical(a)
	}
	return "[Service]\nExecStart=\nExecStart=" + strings.Join(quoted, " ") + "\n", nil
}

func activateProfiles(selected []any) error {
	for _, raw := range selected {
		p := obj(raw)
		active, err := repairRun(5*time.Second, "nmcli", "--get-values", "UUID", "connection", "show", "--active")
		if err != nil {
			return err
		}
		if !strings.Contains("\n"+active, "\n"+str(p["uuid"])+"\n") {
			wait := "30"
			if str(p["type"]) == "bridge" {
				wait = "0"
			}
			if _, err := repairRun(40*time.Second, "nmcli", "--wait", wait, "connection", "up", "uuid", str(p["uuid"])); err != nil {
				return err
			}
		}
	}
	deadline := time.Now().Add(60 * time.Second)
	device := str(obj(selected[0])["interface"])
	for {
		out, _ := repairRun(5*time.Second, "nmcli", "--get-values", "GENERAL.STATE", "device", "show", device)
		state := strings.TrimSpace(out)
		number := strings.SplitN(state, " ", 2)[0]
		if number == "100" {
			return nil
		}
		if _, err := strconv.Atoi(number); err != nil || number == "120" || time.Now().After(deadline) {
			return Public("Management connection did not become ready: " + state)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func startIncus() error {
	res, _ := run([]string{"systemctl", "show", "incus-startup.service", "--property=LoadState", "--value"}, nil, 30*time.Second, nil, "")
	observed := strings.TrimSpace(string(res.Stdout))
	if observed != "loaded" && observed != "not-found" {
		return Public("Incus shutdown hook needs review: " + observed)
	}
	units := []string{"incus.service"}
	if observed == "loaded" {
		units = append(units, "incus-startup.service")
	}
	if _, err := repairRun(30*time.Second, append([]string{"systemctl", "reset-failed"}, units...)...); err != nil {
		return err
	}
	_, err := repairRun(150*time.Second, append([]string{"systemctl", "start"}, units...)...)
	return err
}

type NetworkRepair struct {
	manager *Manager
	path    string
	record  M
}

func (r *NetworkRepair) save(phase string) {
	r.record["phase"] = phase
	writeJSON(r.path, r.record)
}

func (r *NetworkRepair) prepare(iface string) (string, error) {
	if remoteSession() {
		return "", Public("--repair-network requires the local host console")
	}
	return lockedValue(false, func() (string, error) {
		if err := checkIdle(r.manager.state, ""); err != nil {
			return "", err
		}
		state, err := r.manager.status()
		if err != nil {
			return "", err
		}
		raw, err := readJSON(r.path, M{})
		record, ok := raw.(M)
		if err != nil || !ok {
			return "", Public("Invalid network recovery checkpoint")
		}
		phases := map[string]bool{"prepared": true, "reviewing": true, "activating": true, "needs-attention": true, "completed": true, "cancelled": true}
		if len(record) > 0 && (!equalJSON(record["format"], 1) || !phases[str(record["phase"])]) {
			return "", Public("Unknown network recovery checkpoint; inspect it before retrying")
		}
		job := obj(state["job"])
		if job == nil {
			job = M{}
		}
		if len(obj(state["pending"])) > 0 || isActiveStatus(str(job["status"])) {
			expected := []any{}
			for _, name := range keys(obj(record["modules"])) {
				expected = append(expected, M{"path": name, "before": nil, "after": obj(record["modules"])[name]})
			}
			matching := record["management"] != nil && str(job["principal"]) == updatePrincipal &&
				equalJSON(jget(job, "settings", "management"), record["management"]) && equalJSON(job["moduleChanges"], expected)
			if len(record) > 0 && record["job"] == nil && matching {
				record["job"] = job["id"]
				writeJSON(r.path, record)
			}
			if len(record) == 0 || str(job["id"]) != str(record["job"]) || str(job["principal"]) != updatePrincipal {
				return "", Public("Finish the pending activation before repairing management networking")
			}
		}
		if info, err := os.Stat(incusDatabase); !isTrue(state["setupComplete"]) || err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return "", Public("Recovery requires an installed host and its existing Incus database; use #install for installation")
		}
		switch str(record["phase"]) {
		case "prepared", "reviewing", "activating", "needs-attention":
			if iface != "" && iface != str(record["interface"]) {
				return "", Public("Resume the repair with its original interface")
			}
			r.record = record
			fmt.Println("Resuming management repair on " + str(record["interface"]))
		default:
			settings, err := r.manager.effectiveSettings(nil)
			if err != nil {
				return "", err
			}
			out, err := repairRun(30*time.Second, "ip", "-j", "-d", "address", "show")
			if err != nil {
				return "", err
			}
			links, _ := parseJSON([]byte(out))
			observed, err := nmProfiles()
			if err != nil {
				return "", err
			}
			name, selected, err := selectManagement(settings, list(links), observed, iface)
			if err != nil {
				return "", err
			}
			fmt.Println("Repair existing management connection on " + name + "; enable autoconnect on:")
			for _, p := range selected {
				fmt.Println("  " + str(p["id"]) + " [" + str(p["uuid"]) + "]")
			}
			fmt.Println("No address assignment, new profile or firewall change. Incus may autostart its existing guests.")
			if !askYes("Enable these saved connections and review the normal guarded update?") {
				return "", Public("Repair cancelled before changes")
			}
			override, err := repairDropinContent(filepath.Join(r.manager.state, "network-repair-settings.json"))
			if err != nil {
				return "", err
			}
			digest, err := digestSource(r.manager.root)
			if err != nil {
				return "", err
			}
			profiles := []any{}
			for _, p := range selected {
				profiles = append(profiles, p)
			}
			r.record = M{"format": 1, "interface": name, "profiles": profiles, "modules": nil, "declared": []any{}, "job": nil,
				"identityOverride": override, "sourceDigest": digest}
			if err := pinWorkerRuntime(r.manager.state); err != nil {
				return "", err
			}
			r.save("prepared")
		}
		if !equalJSON(r.record["format"], 1) || !isStr(r.record["identityOverride"]) {
			return "", Public("Unsupported network repair checkpoint")
		}
		if r.record["job"] == nil {
			if d, _ := digestSource(r.manager.root); d != str(r.record["sourceDigest"]) {
				return "", Public("Source changed since the recovery checkpoint; review it before retrying")
			}
		}
		observed, err := nmProfiles()
		if err != nil {
			return "", err
		}
		if err := checkProfiles(list(r.record["profiles"]), observed); err != nil {
			return "", err
		}
		for _, p := range list(r.record["profiles"]) {
			if _, err := repairRun(30*time.Second, "nmcli", "connection", "modify", "uuid", str(obj(p)["uuid"]), "connection.autoconnect", "yes"); err != nil {
				return "", err
			}
		}
		if err := activateProfiles(list(r.record["profiles"])); err != nil {
			return "", err
		}
		effective, err := r.manager.effectiveSettings(nil)
		if err != nil {
			return "", err
		}
		changes, err := managementChange(effective, str(r.record["interface"]), nil)
		if err != nil {
			return "", err
		}
		settings := cloneM(effective)
		for k, v := range obj(changes["management"]) {
			obj(settings["management"])[k] = v
		}
		r.record["management"] = settings["management"]
		if r.record["modules"] == nil {
			selected := []M{}
			for _, p := range list(r.record["profiles"]) {
				selected = append(selected, obj(p))
			}
			modules, declared, err := repairModules(r.manager.root, selected)
			if err != nil {
				return "", err
			}
			r.record["modules"], r.record["declared"] = modules, declared
			r.save("prepared")
		}
		writeJSON(filepath.Join(r.manager.state, "network-repair-settings.json"), settings)
		if current, err := os.ReadFile(repairDropin); err == nil && string(current) != str(r.record["identityOverride"]) {
			return "", Public("Another runtime identity override needs manual review")
		}
		if err := atomic(repairDropin, []byte(str(r.record["identityOverride"])), 0o644, ""); err != nil {
			return "", err
		}
		if _, err := repairRun(30*time.Second, "systemctl", "daemon-reload"); err != nil {
			return "", err
		}
		if _, err := identityRefresh(settings); err != nil {
			return "", err
		}
		repairRun(30*time.Second, "systemctl", "reset-failed", "nixus-management-identity.service")
		if _, err := repairRun(150*time.Second, "systemctl", "start", "nixus-management-identity.service"); err != nil {
			return "", err
		}
		if err := startIncus(); err != nil {
			return "", err
		}
		r.save("reviewing")
		return str(r.record["interface"]), nil
	})
}

func (r *NetworkRepair) verify(job M) error {
	expected := []any{}
	for _, name := range keys(obj(r.record["modules"])) {
		expected = append(expected, M{"path": name, "before": nil, "after": obj(r.record["modules"])[name]})
	}
	if !equalJSON(job["moduleChanges"], expected) {
		return Public("Reviewed recovery modules differ from the checkpoint")
	}
	dir, err := r.manager.jobPath(str(job["id"]))
	if err != nil {
		return err
	}
	values, err := declaredProfiles(filepath.Join(dir, "source"))
	if err != nil {
		return err
	}
	for _, name := range list(r.record["declared"]) {
		if !autoTrue(jget(values, str(name), "auto")) {
			return Public("A source override prevents persistent autoconnect; refusing activation")
		}
	}
	r.save("activating")
	return nil
}

func (r *NetworkRepair) validateLive() error {
	observed, err := nmProfiles()
	if err != nil {
		return err
	}
	if err := checkProfiles(list(r.record["profiles"]), observed); err != nil {
		return err
	}
	current := map[string]M{}
	for _, p := range observed {
		current[str(p["uuid"])] = p
	}
	for _, p := range list(r.record["profiles"]) {
		if str(current[str(obj(p)["uuid"])]["auto"]) != "yes" {
			return Public("A management profile has autoconnect disabled after activation")
		}
	}
	return nil
}

func (r *NetworkRepair) nativeIdentity() error {
	names := []string{"incus.service", "incus-startup.service", "incus-preseed.service", "nixus-instances.service",
		"nixus-admin-backend.service", "nixus-ui.service", "nginx.service", "cockpit.service"}
	res, _ := run(append([]string{"systemctl", "show", "--property=Id,ActiveState"}, names...), nil, 30*time.Second, nil, "")
	observed := string(res.Stdout)
	if !strings.Contains(observed, "Id=incus.service\n") && !strings.HasSuffix(observed, "Id=incus.service") {
		return Public("Cannot observe Incus service dependencies before restoring identity")
	}
	var active []string
	for _, block := range strings.Split(strings.TrimSpace(observed), "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				fields[k] = v
			}
		}
		for _, n := range names {
			if fields["Id"] == n && fields["ActiveState"] == "active" {
				active = append(active, n)
			}
		}
	}
	if raw, err := os.ReadFile(repairDropin); err == nil {
		if string(raw) != str(r.record["identityOverride"]) {
			return Public("Runtime identity override changed; inspect it before continuing")
		}
		durableUnlink(repairDropin)
		if _, err := repairRun(30*time.Second, "systemctl", "daemon-reload"); err != nil {
			return err
		}
	}
	repairRun(30*time.Second, "systemctl", "reset-failed", "nixus-management-identity.service")
	if _, err := repairRun(150*time.Second, "systemctl", "restart", "nixus-management-identity.service"); err != nil {
		return err
	}
	if len(active) > 0 {
		if _, err := repairRun(180*time.Second, append([]string{"systemctl", "start"}, active...)...); err != nil {
			return err
		}
	}
	if err := startIncus(); err != nil {
		return err
	}
	return r.validateLive()
}

func (r *NetworkRepair) finish(success bool) error {
	state, err := r.manager.status()
	if err == nil && (len(obj(state["pending"])) > 0 || isActiveStatus(str(jget(state, "job", "status")))) {
		return nil
	}
	if r.record == nil {
		return nil
	}
	var errs []string
	if exists(repairDropin) && r.nativeIdentity() != nil {
		errs = append(errs, "Runtime identity restoration failed")
	}
	if success {
		if r.validateLive() != nil {
			errs = append(errs, "Live management validation failed")
		}
	} else if observed, err := nmProfiles(); err != nil || checkProfiles(list(r.record["profiles"]), observed) != nil {
		errs = append(errs, "Saved network profiles need review")
	} else {
		for _, p := range list(r.record["profiles"]) {
			pm := obj(p)
			if _, err := repairRun(30*time.Second, "nmcli", "connection", "modify", "uuid", str(pm["uuid"]), "connection.autoconnect", str(pm["auto"])); err != nil {
				errs = append(errs, "Saved connection policy could not be restored")
			}
		}
	}
	switch {
	case len(errs) > 0:
		r.save("needs-attention")
	case success:
		r.save("completed")
	default:
		r.save("cancelled")
	}
	if len(errs) > 0 {
		message := "Recovery needs attention: " + strings.Join(errs, "; ") + "; checkpoint: " + r.path
		if success {
			return Public(message)
		}
		fmt.Fprintln(os.Stderr, message)
	}
	return nil
}

// networkIdentityMain is the transient ExecStart override used during repair.
func networkIdentityMain(args []string) int {
	if len(args) != 1 || os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "This helper is invoked by #update --repair-network")
		return 1
	}
	if _, err := identityRefresh(readObj(args[0])); err != nil {
		fmt.Fprintln(os.Stderr, publicError(err))
		return 1
	}
	return 0
}

var _ = exec.Command
