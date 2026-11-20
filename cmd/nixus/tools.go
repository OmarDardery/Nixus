package main

// Small host tools: console status, the authenticated Incus CLI wrapper,
// failure webhooks, local data-disk preparation and release evidence.

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log/syslog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

// --- console status -------------------------------------------------------------

func cleanText(v string) string {
	var b strings.Builder
	for _, r := range v {
		if unicode.IsPrint(r) {
			b.WriteRune(r)
		}
	}
	s := []rune(b.String())
	if len(s) > 160 {
		s = s[:160]
	}
	return string(s)
}

func usableIPv4(v string) bool {
	ip := net.ParseIP(v)
	return ip != nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() && !ip.IsMulticast()
}

func quickOutput(args ...string) string {
	res, _ := run(args, nil, time.Second, nil, "")
	return string(res.Stdout)
}

func unitStates(names []string) map[string]map[string]string {
	result := map[string]map[string]string{}
	out := quickOutput(append([]string{"systemctl", "show", "--no-pager", "--property=Id,LoadState,ActiveState,Result,ExecMainExitTimestamp"}, names...)...)
	for _, block := range strings.Split(strings.TrimSpace(out), "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				fields[k] = v
			}
		}
		if fields["Id"] != "" {
			result[fields["Id"]] = fields
		}
	}
	return result
}

func consoleLines(settings M, links []any, units map[string]map[string]string, current, def, kernel, booted string) []string {
	var out []string
	management := obj(settings["management"])
	iface := str(management["interface"])
	var link M
	for _, l := range links {
		if str(obj(l)["ifname"]) == iface {
			link = obj(l)
		}
	}
	var addresses []string
	for _, a := range list(link["addr_info"]) {
		am := obj(a)
		if str(am["family"]) == "inet" && str(am["scope"]) == "global" && usableIPv4(str(am["local"])) {
			addresses = append(addresses, str(am["local"]))
		}
	}
	address := ""
	for _, a := range addresses {
		if a == str(management["address"]) {
			address = a
		}
	}
	if address == "" && !isTrue(management["configure"]) && len(addresses) == 1 {
		address = addresses[0]
	}
	if address != "" {
		out = append(out, "Management: "+cleanText(iface)+"  "+address)
		for _, s := range [][2]string{{"setup", "Nixus"}, {"cockpit", "Cockpit"}} {
			option := obj(settings[s[0]])
			if port, ok := intValue(option["port"]); isTrue(option["enable"]) && ok && isInt(option["port"]) {
				out = append(out, fmt.Sprintf("%s: https://%s:%d", s[1], address, port))
			}
		}
		if isTrue(settings["ready"]) {
			out = append(out, "Incus: https://"+address+":8443")
		}
	} else {
		name := iface
		if name == "" {
			name = "not configured"
		}
		out = append(out, "Management: "+cleanText(name)+" — no unambiguous configured IPv4 address")
		if m := str(link["master"]); m != "" {
			out = append(out, "Address belongs on bridge "+cleanText(m)+"; review management interface")
		}
	}
	var states []string
	for _, l := range [][2]string{{"incus.service", "Incus"}, {"nixus-ui.service", "Web"}, {"nginx.service", "Proxy"}} {
		unit := units[l[0]]
		state := "unavailable"
		if unit["LoadState"] == "loaded" {
			state = unit["ActiveState"]
			if state == "" {
				state = "unknown"
			}
		}
		states = append(states, l[1]+"="+cleanText(state))
	}
	out = append(out, "Services: "+strings.Join(states, "  "))
	if isTrue(jget(settings, "backup", "enable")) {
		backup := units["restic-backups-nixus.service"]
		if ts := backup["ExecMainExitTimestamp"]; ts != "" && backup["LoadState"] == "loaded" {
			result := backup["Result"]
			if result == "" {
				result = "unknown"
			}
			out = append(out, "Backup last run: "+cleanText(ts)+"  result="+cleanText(result))
		} else {
			out = append(out, "Backup: configured; no recorded run available")
		}
		out = append(out, "Restore verification: not checked by this summary")
	} else {
		out = append(out, "Backups: disabled")
	}
	switch {
	case current != "" && def != "" && current == def:
		out = append(out, "Boot: current configuration is the boot default")
	case current != "" && def != "":
		out = append(out, "Boot: current configuration differs from boot default (test/unconfirmed)")
	default:
		out = append(out, "Boot: unknown")
	}
	if kernel != "" && booted != "" && kernel != booted {
		out = append(out, "Reboot: a different kernel is running")
	}
	return append(out, "Check endpoints: sudo nixus doctor | Update: nixus-update")
}

func resolvedTarget(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return ""
}

func consoleStatusMain() int {
	raw, err := os.ReadFile("/etc/nixus/effective-settings.json")
	settings, perr := parseObject(raw)
	if err != nil || perr != nil {
		fmt.Println("Nixus: configuration unavailable; run sudo nixus doctor")
		return 0
	}
	linksAny, _ := parseJSON([]byte(quickOutput("ip", "-j", "address", "show")))
	names := []string{"incus.service", "nixus-ui.service", "nginx.service"}
	if isTrue(jget(settings, "backup", "enable")) {
		names = append(names, "restic-backups-nixus.service")
	}
	for _, line := range consoleLines(settings, list(linksAny), unitStates(names), resolvedTarget("/run/current-system"),
		resolvedTarget("/nix/var/nix/profiles/system"), resolvedTarget("/run/current-system/kernel"), resolvedTarget("/run/booted-system/kernel")) {
		fmt.Println(line)
	}
	return 0
}

// --- homelab CLI wrapper ------------------------------------------------------------

var guestName = re(`[A-Za-z0-9][A-Za-z0-9_.-]*`)

func homelabExecute(argv []string, action, target string, logger *syslog.Writer) int {
	start := time.Now()
	if logger != nil {
		logger.Notice(fmt.Sprintf("nixus begin uid=%d action=%s target=%s", os.Getuid(), action, target))
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	code := 0
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		} else {
			code = 127
		}
	}
	if logger != nil {
		logger.Notice(fmt.Sprintf("nixus end action=%s target=%s exit=%d elapsed=%.2fs", action, target, code, time.Since(start).Seconds()))
	}
	return code
}

func homelabMain(args []string) int {
	fail := func(msg string) int { fmt.Fprintln(os.Stderr, msg); return 2 }
	logger, _ := syslog.New(syslog.LOG_NOTICE|syslog.LOG_AUTHPRIV, "nixus")
	config := os.Getenv("HOMELAB_CONFIG")
	if config == "" {
		config = "/etc/nixus/client.json"
	}
	cfg := readObj(config)
	remote, project := str(cfg["remote"]), str(cfg["project"])
	if remote == "" {
		remote = "local"
	}
	if project == "" {
		project = "lab"
	}
	for len(args) > 0 && strings.HasPrefix(args[0], "--") {
		if len(args) < 2 {
			return fail("missing option value")
		}
		switch args[0] {
		case "--remote":
			remote = args[1]
		case "--project":
			project = args[1]
		default:
			return fail("unknown option " + args[0])
		}
		args = args[2:]
	}
	if !fullmatch(guestName, remote) || !fullmatch(guestName, project) {
		return fail("Use a guest/project name, or its configured numeric alias")
	}
	if len(args) == 0 {
		return fail("usage: nixus [--remote R] [--project P] {list,doctor,install-plan,commissioning,enroll-key,exec,exec-many,restart,backup,action} ...")
	}
	action, rest := args[0], args[1:]
	switch action {
	case "doctor", "enroll-key", "commissioning", "install-plan":
		if os.Geteuid() != 0 {
			return fail("Run this host administration command with sudo")
		}
		command := append([]string{"nixus-admin", action}, rest...)
		return homelabExecute(command, action, "host", logger)
	case "list":
		return homelabExecute([]string{"incus", "--project", project, "list", remote + ":"}, "list", project, logger)
	case "exec", "exec-many", "restart", "backup", "action":
	default:
		return fail("unknown action " + action)
	}
	if len(rest) == 0 {
		return fail(action + " requires a target")
	}
	targets := []string{rest[0]}
	if action == "exec-many" {
		targets = strings.Split(rest[0], ",")
	}
	command := rest[1:]
	if len(command) > 0 && command[0] == "--" {
		command = command[1:]
	}
	prefix := []string{"incus", "--project", project}
	failed := 0
	for _, target := range targets {
		if alias, ok := obj(cfg["aliases"])[target]; ok {
			target = fmt.Sprint(alias)
		}
		if !fullmatch(guestName, target) {
			return fail("Use a guest/project name, or its configured numeric alias")
		}
		full := remote + ":" + target
		var argv []string
		switch action {
		case "exec", "exec-many", "action":
			cmd := command
			if action == "action" {
				actions := map[string][]string{"health": {"systemctl", "is-system-running"}, "disk": {"df", "-h"},
					"services": {"systemctl", "list-units", "--type=service", "--no-pager"}}
				if len(cmd) != 1 || actions[cmd[0]] == nil {
					return fail("predefined actions: health, disk, services")
				}
				cmd = actions[cmd[0]]
			}
			if action == "exec-many" && len(cmd) == 0 {
				return fail("exec-many requires a command")
			}
			if len(cmd) == 0 {
				cmd = []string{"/bin/sh"}
			}
			argv = append(append(append([]string{}, prefix...), "exec", full, "--"), cmd...)
		case "restart":
			argv = append(append([]string{}, prefix...), "restart", full, "--timeout", "120")
		case "backup":
			dest := str(cfg["exportDirectory"])
			if dest == "" {
				dest = "."
			}
			os.MkdirAll(dest, 0o700)
			filename := filepath.Join(dest, fmt.Sprintf("%s-%s-%d.tar.gz", project, target, time.Now().UnixNano()))
			argv = append(append([]string{}, prefix...), "export", full, filename, "--compression", "gzip")
		}
		if len(targets) > 1 {
			fmt.Printf("== %s ==\n", target)
		}
		if code := homelabExecute(argv, action, target, logger); failed == 0 {
			failed = code
		}
	}
	return failed
}

// --- failure webhook ------------------------------------------------------------------

var unitIdentity = re(`[a-zA-Z0-9_.@:-]{1,180}`)

func notifySend(unit, credential string) error {
	if !fullmatch(unitIdentity, unit) {
		return Public("Invalid service identity")
	}
	raw, err := os.ReadFile(credential)
	if err != nil {
		return err
	}
	target := strings.TrimSpace(string(raw))
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
		return Public("Use an HTTPS webhook URL without userinfo")
	}
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return Public("Webhook redirects are refused")
	}}
	resp, err := client.Post(target, "application/json", bytes.NewReader([]byte(canonicalSpaced(M{"service": unit, "status": "failed"}))))
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Public("Webhook refused the notification")
	}
	return nil
}

func notifyMain(args []string) int {
	if len(args) != 1 || notifySend(args[0], filepath.Join(os.Getenv("CREDENTIALS_DIRECTORY"), "webhook")) != nil {
		fmt.Fprintln(os.Stderr, "Notification failed. Check the destination and runtime credential; URL and response are withheld.")
		return 1
	}
	return 0
}

// --- data disks ----------------------------------------------------------------------------

func blockDisks() ([]any, error) {
	out, err := check([]string{"lsblk", "--json", "--bytes", "--paths", "--output",
		"PATH,TYPE,SIZE,MODEL,SERIAL,WWN,RO,RM,MOUNTPOINTS,MAJ:MIN,PARTLABEL,FSTYPE"}, nil, 20*time.Second)
	if err != nil {
		return nil, err
	}
	data, err := parseObject(out)
	if err != nil {
		return nil, err
	}
	poolDevices, poolKnown := map[string]bool{}, false
	if zpool := lookPath("zpool"); zpool != "" {
		if res, err := run([]string{zpool, "status", "-P"}, nil, 10*time.Second, nil, ""); err == nil {
			text := string(res.Stdout) + string(res.Stderr)
			poolKnown = res.Code == 0 || strings.Contains(strings.ToLower(text), "no pools available")
			for _, w := range strings.Fields(string(res.Stdout)) {
				if strings.HasPrefix(w, "/dev/") {
					poolDevices[resolvedOr(w)] = true
				}
			}
		}
	}
	disks := list(data["blockdevices"])
	for _, raw := range disks {
		disk := obj(raw)
		busy := false
		for _, n := range walkDevice(disk) {
			t := str(n["type"])
			if (t != "disk" && t != "part") || poolDevices[resolvedOr(str(n["path"]))] || (str(n["fstype"]) == "zfs_member" && !poolKnown) {
				busy = true
			}
			holders, _ := os.ReadDir(filepath.Join("/sys/class/block", filepath.Base(str(n["path"])), "holders"))
			if len(holders) > 0 {
				busy = true
			}
		}
		disk["busy"] = busy
		disk["byId"] = nil
		self := resolvedOr(str(disk["path"]))
		for _, dir := range []string{"/dev/disk/by-id", "/dev/disk/by-path"} {
			links, _ := filepath.Glob(filepath.Join(dir, "*"))
			for _, l := range links {
				if r, err := filepath.EvalSymlinks(l); err == nil && r == self && disk["byId"] == nil {
					disk["byId"] = l
				}
			}
		}
	}
	return disks, nil
}

func resolvedOr(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

func walkDevice(d M) []M {
	out := []M{d}
	for _, c := range list(d["children"]) {
		out = append(out, walkDevice(obj(c))...)
	}
	return out
}

func diskIdentity(d M) M {
	out := M{}
	for _, k := range []string{"path", "size", "serial", "wwn", "maj:min", "model", "byId"} {
		out[k] = d[k]
	}
	return out
}

var devicePath = re(`/dev/[a-zA-Z0-9_./-]+`)

func diskEligible(d M, minimum int64) bool {
	size, _ := num(d["size"])
	if str(d["type"]) != "disk" || isTrue(d["ro"]) || isTrue(d["busy"]) || int64(size) < minimum || !fullmatch(devicePath, str(d["path"])) {
		return false
	}
	for _, n := range walkDevice(d) {
		for _, m := range list(n["mountpoints"]) {
			if m != nil && str(m) != "" {
				return false
			}
		}
	}
	return true
}

var diskModule = re(`[a-z][a-z0-9-]{0,31}`)
var fsUUID = re(`[0-9a-fA-F-]{16,80}`)

// diskPrepare is local-console only: it erases an explicitly confirmed disk.
func diskPrepare() error {
	info, _ := os.Stdin.Stat()
	if os.Geteuid() != 0 || !exists("/etc/NIXOS") || info.Mode()&os.ModeCharDevice == 0 {
		return Public("Use a local root/SSH terminal on the NixOS host")
	}
	in := bufio.NewReader(os.Stdin)
	ask := func(prompt string) string {
		fmt.Print(prompt)
		line, _ := in.ReadString('\n')
		return strings.TrimRight(line, "\r\n")
	}
	all, err := blockDisks()
	if err != nil {
		return err
	}
	var candidates []M
	for _, d := range all {
		if diskEligible(obj(d), 1<<30) {
			candidates = append(candidates, obj(d))
		}
	}
	for i, c := range candidates {
		fmt.Printf("%d. %s\n", i+1, canonicalSpaced(diskIdentity(c)))
	}
	if len(candidates) == 0 {
		return Public("No unmounted, writable, inactive whole data disk of at least 1 GiB")
	}
	index, ok := intValue(strings.TrimSpace(ask("Data disk number (the entire selected disk will be erased): ")))
	if !ok || index < 1 || index > len(candidates) {
		return Public("Invalid disk number")
	}
	selected := candidates[index-1]
	name := strings.TrimSpace(ask("Module/pool name: "))
	if !fullmatch(diskModule, name) {
		return Public("Use a lowercase disk name")
	}
	role := strings.TrimSpace(ask("Role: data or pool [data]: "))
	if role == "" {
		role = "data"
	}
	if role != "data" && role != "pool" {
		return Public("Choose data or pool")
	}
	size, _ := num(selected["size"])
	phrase := fmt.Sprintf("ERASE %s %d", str(selected["path"]), int64(size))
	fmt.Println(string(jsonFile(M{"disk": diskIdentity(selected), "filesystem": "ext4", "module": name, "role": role})))
	if ask("Type exactly '"+phrase+"': ") != phrase {
		return Public("Erase confirmation did not match; no disk changes made")
	}
	return locked(false, func() error {
		release, err := lockFile(incusLock, false)
		if err != nil {
			return err
		}
		defer release()
		if err := checkConfigIdle(STATE); err != nil {
			return err
		}
		active := str(readObj(filepath.Join(STATE, "active.json"))["id"])
		if active != "" && str(readObj(filepath.Join(STATE, "jobs", active, "job.json"))["status"]) == "ready" {
			return Public("Discard or finish the reviewed configuration before preparing a disk")
		}
		again, err := blockDisks()
		if err != nil {
			return err
		}
		var current M
		for _, d := range again {
			if str(obj(d)["path"]) == str(selected["path"]) {
				current = obj(d)
			}
		}
		if current == nil || !diskEligible(current, 1<<30) || !equalJSON(diskIdentity(current), diskIdentity(selected)) {
			return Public("Disk identity or use changed; review it again")
		}
		device := str(current["path"])
		audit("disk-prepare-approved", M{"device": device, "diskName": name, "role": role})
		for _, argv := range [][]string{{"wipefs", "--all", "--", device}, {"parted", "--script", "--", device, "mklabel", "gpt"},
			{"parted", "--script", "--", device, "mkpart", "NIXUS_DATA", "ext4", "1MiB", "100%"}, {"udevadm", "settle", "--timeout=30"}} {
			if _, err := check(argv, nil, 5*time.Minute); err != nil {
				return Public("Disk preparation step failed; inspect the selected disk")
			}
		}
		refreshed, err := blockDisks()
		if err != nil {
			return err
		}
		partition := ""
		for _, d := range refreshed {
			if equalJSON(diskIdentity(obj(d)), diskIdentity(current)) {
				for _, n := range walkDevice(obj(d)) {
					if str(n["type"]) == "part" && str(n["partlabel"]) == "NIXUS_DATA" {
						partition = str(n["path"])
					}
				}
			}
		}
		if partition == "" {
			return Public("Prepared partition not found; inspect the selected disk")
		}
		label := name
		if len(label) > 8 {
			label = label[:8]
		}
		if _, err := check([]string{"mkfs.ext4", "-F", "-L", "nixus-" + label, partition}, nil, 30*time.Minute); err != nil {
			return Public("Filesystem creation failed; inspect the selected disk")
		}
		out, _ := check([]string{"blkid", "-s", "UUID", "-o", "value", "--", partition}, nil, 30*time.Second)
		uuid := strings.TrimSpace(string(out))
		if !fullmatch(fsUUID, uuid) {
			return Public("Filesystem UUID discovery failed; inspect the selected disk")
		}
		module := "{ ... }: { nixus.storage.disks." + name + " = { uuid = " + canonical(uuid) + "; fsType = \"ext4\"; role = " + canonical(role) + "; }; }\n"
		proposal := filepath.Join(STATE, "proposals", name+".nix")
		if err := atomicString(proposal, module, 0o600); err != nil {
			return err
		}
		audit("disk-prepared", M{"device": device, "diskName": name, "uuid": uuid, "role": role})
		fmt.Println("Filesystem prepared. No host configuration has been activated.")
		fmt.Println("Review with: sudo nixus-admin config review --module disks/" + name + ".nix=" + proposal)
		fmt.Println("Inspect status, apply the reviewed transaction, verify access/storage, then confirm it.")
		return nil
	})
}

// --- release evidence ------------------------------------------------------------------------

var releaseWorkflows = map[string]string{"validate": "validate.yml", "installer": "installer.yml", "portal": "portal-entry.yml", "website": "pages.yml"}
var betaVersion = re(`[0-9]+\.[0-9]+\.[0-9]+-beta\.[0-9]+`)

func physicalReports(paths []string, revision, version, inputs string) (M, error) {
	hardware, modes := map[string]bool{}, map[string]bool{}
	for _, p := range paths {
		report, err := loadReport(p)
		if err != nil {
			return nil, err
		}
		summary, err := summarizeEvidence(report, nil, revision)
		if err != nil {
			return nil, err
		}
		ctx := obj(report["context"])
		if str(summary["qualification"]) != "ready-for-review" || str(summary["profile"]) != "core" ||
			str(ctx["version"]) != version || str(ctx["inputsDigest"]) != inputs {
			return nil, Public("Require current physical fresh/upgrade evidence for this exact source, version and inputs")
		}
		hardware[str(ctx["hardwareDigest"])] = true
		modes[str(ctx["mode"])] = true
	}
	if len(hardware) != 1 || len(modes) != 2 || !modes["fresh"] || !modes["upgrade"] {
		return nil, Public("Require fresh and upgrade reports on the same reference hardware")
	}
	return M{"hardwareDigest": sortedKeys(hardware)[0], "modes": []any{"fresh", "upgrade"},
		"evidence": "operator reports with automated probes and manual attestations; not independent certification"}, nil
}

func ciRun(key string, runRecord M, jobs []any, revision, repository string) (string, error) {
	event := str(runRecord["event"])
	if str(runRecord["head_sha"]) != revision || str(runRecord["conclusion"]) != "success" || str(runRecord["status"]) != "completed" ||
		str(runRecord["path"]) != ".github/workflows/"+releaseWorkflows[key] || (event != "push" && event != "workflow_dispatch") ||
		str(jget(runRecord, "repository", "full_name")) != repository {
		return "", Public("Required CI run is incomplete, failed, wrong-scope or on another revision: " + key)
	}
	if len(jobs) == 0 {
		return "", Public("Required CI run has no jobs: " + key)
	}
	observed := map[string]bool{}
	for _, raw := range jobs {
		job := obj(raw)
		if str(job["status"]) != "completed" || str(job["conclusion"]) != "success" {
			return "", Public("A required CI job did not pass: " + key)
		}
		if len(list(job["steps"])) == 0 {
			return "", Public("Required CI job has no step evidence: " + key)
		}
		for _, s := range list(job["steps"]) {
			step := obj(s)
			if key == "validate" && str(step["name"]) == "Check release tag version" && str(step["conclusion"]) == "skipped" {
				continue
			}
			if str(step["status"]) != "completed" || str(step["conclusion"]) != "success" {
				return "", Public("A required CI step failed or was skipped: " + key)
			}
			observed[str(step["name"])] = true
		}
	}
	if key == "website" && !observed["Deploy to GitHub Pages"] {
		return "", Public("Website validation alone is not successful Pages publication")
	}
	return str(runRecord["html_url"]), nil
}

func recoveryEvidence(restored M, revision, inputs string) (float64, error) {
	verified, ok1 := num(restored["verifiedAt"])
	created, ok2 := num(restored["backupCreated"])
	duration, ok3 := num(restored["durationSeconds"])
	if !equalJSON(restored["format"], 1) || str(restored["evidenceType"]) != "operator-attestation" || str(restored["phase"]) != "complete" ||
		str(restored["restore"]) != "operator-attested" || jget(restored, "coverage", "complete") != true ||
		str(restored["sourceRevision"]) != revision || str(restored["sourceInputsDigest"]) != inputs ||
		!ok1 || now()-verified < 0 || now()-verified > commissioningMaxAge || !ok2 || created < 0 || created > verified || !ok3 || duration < 0 {
		return 0, Public("Require current full-coverage recovery evidence for this source/inputs with recorded duration")
	}
	return duration, nil
}

func ghJSON(args ...string) (any, error) {
	out, err := check(append([]string{"gh", "api"}, args...), nil, 60*time.Second)
	if err != nil {
		return nil, err
	}
	return parseJSON(out)
}

func releasePrepare(tag, evidence, runs, repository, output string) error {
	raw, err := os.ReadFile("VERSION")
	if err != nil {
		return err
	}
	version := strings.TrimSpace(string(raw))
	if !fullmatch(betaVersion, version) || tag != "v"+version {
		return Public("A beta tag must exactly match VERSION; stable/RC publication is not qualified by this workflow")
	}
	head, err := check([]string{"git", "rev-parse", "HEAD"}, nil, 30*time.Second)
	if err != nil {
		return err
	}
	tagged, err := check([]string{"git", "rev-parse", tag + "^{commit}"}, nil, 30*time.Second)
	if err != nil {
		return err
	}
	revision := strings.TrimSpace(string(head))
	if revision != strings.TrimSpace(string(tagged)) {
		return Public("Checked-out source does not match the release tag")
	}
	inputs := digestJSON(readText("flake.lock"))
	reports := []string{filepath.Join(evidence, "fresh.json"), filepath.Join(evidence, "upgrade.json")}
	qualification, err := physicalReports(reports, revision, version, inputs)
	if err != nil {
		return err
	}
	restoredRaw, err := os.ReadFile(filepath.Join(evidence, "recovery.json"))
	if err != nil {
		return err
	}
	restored, err := parseObject(restoredRaw)
	if err != nil {
		return err
	}
	duration, err := recoveryEvidence(restored, revision, inputs)
	if err != nil {
		return err
	}
	runIDs, err := parseObject([]byte(runs))
	if err != nil || len(runIDs) != len(releaseWorkflows) {
		return Public("Supply one positive run ID for each required workflow")
	}
	links := M{}
	for key := range releaseWorkflows {
		id, ok := intValue(runIDs[key])
		if !ok || !isInt(runIDs[key]) || id <= 0 {
			return Public("Supply one positive run ID for each required workflow")
		}
		runRecord, err := ghJSON(fmt.Sprintf("repos/%s/actions/runs/%d", repository, id))
		if err != nil {
			return err
		}
		pages, err := ghJSON("--paginate", "--slurp", fmt.Sprintf("repos/%s/actions/runs/%d/jobs?per_page=100", repository, id))
		if err != nil {
			return err
		}
		var jobs []any
		for _, page := range list(pages) {
			jobs = append(jobs, list(obj(page)["jobs"])...)
		}
		link, err := ciRun(key, obj(runRecord), jobs, revision, repository)
		if err != nil {
			return err
		}
		links[key] = link
	}
	if lexists(output) {
		return Public("Release output must not already exist")
	}
	if err := os.MkdirAll(output, 0o700); err != nil {
		return err
	}
	archive := filepath.Join(output, "nixus-"+version+".tar.gz")
	if _, err := check([]string{"git", "archive", "--format=tar.gz", "--prefix=nixus-" + version + "/", "--output=" + archive, revision}, nil, 5*time.Minute); err != nil {
		return err
	}
	manifest := M{"format": 1, "version": version, "revision": revision, "inputsDigest": inputs, "created": int(now()),
		"qualification": qualification, "ci": links, "recoveryDurationSeconds": duration,
		"limits": "Single-host beta, x86_64; two-reboot minimum. Ten reboots/fourteen days remain reported targets. No clustering/HA or universal hardware/application coverage."}
	os.WriteFile(filepath.Join(output, "manifest.json"), jsonFile(manifest), 0o644)
	matrix, err := evidenceMatrix(reports, revision)
	if err != nil {
		return err
	}
	os.WriteFile(filepath.Join(output, "qualification.md"), []byte(matrix), 0o644)
	limitations, err := os.ReadFile(filepath.Join(evidence, "limitations.md"))
	if err != nil || len(limitations) > 64*1024 || strings.TrimSpace(string(limitations)) == "" {
		return Public("Supply reviewed compatibility, backup/restore limitations, measured reboot count and operation duration")
	}
	os.WriteFile(filepath.Join(output, "LIMITATIONS.md"), limitations, 0o644)
	entries, _ := os.ReadDir(output)
	var sums strings.Builder
	for _, e := range entries {
		if e.Type().IsRegular() {
			d, _ := fileSHA256(filepath.Join(output, e.Name()))
			sums.WriteString(d + "  " + e.Name() + "\n")
		}
	}
	return os.WriteFile(filepath.Join(output, "SHA256SUMS"), []byte(sums.String()), 0o644)
}
