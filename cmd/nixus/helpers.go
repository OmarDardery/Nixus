package main

// Packaged upstream Incus wizard runner. No browser execution or Proxmox emulation.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	helperBase    = envPath("NIXUS_HELPER_METADATA", filepath.Join(SOURCE, "helpers"))
	helperEngine  = envPath("NIXUS_HELPER_ENGINE", "/nonexistent")
	helperScripts = envPath("NIXUS_HELPER_SCRIPTS", "/nonexistent")
	helperState   = "/var/lib/nixus/helpers"
	helperName    = re(`[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}`)
)

func helperPins() M { return readObj(filepath.Join(helperBase, "sources.json")) }

func helperCatalog() []any {
	known := readObj(filepath.Join(helperBase, "compatibility.json"))
	matches, _ := filepath.Glob(filepath.Join(helperScripts, "ct", "*.sh"))
	out := []any{}
	for _, p := range matches {
		id := strings.TrimSuffix(filepath.Base(p), ".sh")
		if isSymlink(p) || !fullmatch(helperName, id) {
			continue
		}
		k := obj(known[id])
		title, status, notes := str(k["title"]), str(k["status"]), str(k["notes"])
		if title == "" {
			title = id
		}
		if status == "" {
			status = "upstream-supported"
		}
		if notes == "" {
			notes = "Not qualified on Nixus."
		}
		out = append(out, M{"id": id, "title": title, "status": status, "notes": notes, "verifiedOnNixus": str(k["status"]) == "verified"})
	}
	return out
}

func helperCommand(args []string, env []string) (string, error) {
	res, err := run(args, nil, 30*time.Second, env, "")
	if err != nil {
		return "", Public("Command failed: " + args[0])
	}
	if res.Code != 0 {
		msg := strings.TrimSpace(string(res.Stderr))
		if len(msg) > 2000 {
			msg = msg[len(msg)-2000:]
		}
		if msg == "" {
			msg = "Command failed: " + args[0]
		}
		return "", Public(msg)
	}
	return string(res.Stdout), nil
}

func helperEnvironment(project, directory string) ([]string, error) {
	if !fullmatch(helperName, project) {
		return nil, Public("Use a local Incus project name")
	}
	config := filepath.Join(directory, "incus")
	os.Mkdir(config, 0o700)
	os.WriteFile(filepath.Join(config, "config.yml"), []byte("default-remote: local\nremotes:\n  local:\n    addr: unix://\n    project: "+project+
		"\n  images:\n    addr: https://images.linuxcontainers.org\n    protocol: simplestreams\n    public: true\n"), 0o600)
	pins := helperPins()
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		skip := false
		for _, p := range []string{"COMMUNITY_SCRIPTS_", "_CS_", "_INCUS_", "LXC_PLATFORM", "INCUS_"} {
			if strings.HasPrefix(k, p) {
				skip = true
			}
		}
		if !skip && k != "LC_ALL" {
			env = append(env, kv)
		}
	}
	raw := func(name string) string {
		return "https://raw.githubusercontent.com/" + str(jget(pins, name, "repository")) + "/" + str(jget(pins, name, "revision"))
	}
	return append(env, "INCUS_CONF="+config, "INCUS_PROJECT="+project, "LXC_PLATFORM=incus",
		"COMMUNITY_SCRIPTS_CORE_DIR="+helperEngine, "COMMUNITY_SCRIPTS_ROOT="+helperScripts,
		"COMMUNITY_SCRIPTS_CORE_URL="+raw("core"), "COMMUNITY_SCRIPTS_URL="+raw("scripts"),
		"COMMUNITY_SCRIPTS_STATE_DIR="+helperState, "LC_ALL=C"), nil
}

func helperDoctor(project, directory string) ([]string, M, error) {
	if !isFile(filepath.Join(helperEngine, "core/build.func")) || !isDir(filepath.Join(helperScripts, "ct")) {
		return nil, nil, Public("Use the Nix-packaged runner: pinned engine/scripts are missing")
	}
	var missing []string
	for _, n := range []string{"bash", "incus", "curl", "jq", "whiptail", "awk", "sed", "tar", "xz", "hostname"} {
		if lookPath(n) == "" {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return nil, nil, Public("Missing packaged dependencies: " + strings.Join(missing, ", "))
	}
	env, err := helperEnvironment(project, directory)
	if err != nil {
		return nil, nil, err
	}
	query := func(args ...string) (any, error) {
		out, err := helperCommand(args, env)
		if err != nil {
			return nil, err
		}
		return parseJSON([]byte(out))
	}
	info, err := query("incus", "--force-local", "query", "/1.0")
	if err != nil {
		return nil, nil, err
	}
	if _, err := helperCommand([]string{"incus", "--force-local", "project", "show", project}, env); err != nil {
		return nil, nil, err
	}
	pools, err := query("incus", "--force-local", "storage", "list", "--format=json")
	if err != nil {
		return nil, nil, err
	}
	if len(list(pools)) == 0 {
		return nil, nil, Public("Create/select an Incus storage pool before provisioning")
	}
	networks, err := query("incus", "--force-local", "network", "list", "--format=json")
	if err != nil {
		return nil, nil, err
	}
	candidates := []any{}
	for _, n := range list(networks) {
		if t := str(obj(n)["type"]); t == "bridge" || t == "ovn" || t == "macvlan" {
			candidates = append(candidates, obj(n)["name"])
		}
	}
	if len(candidates) == 0 {
		return nil, nil, Public("Prepare a guest network in Incus or a host Ethernet bridge first")
	}
	for _, argv := range [][]string{{"incus", "remote", "get-url", "images"}, {"incus", "image", "info", "images:debian/13"}} {
		if _, err := helperCommand(argv, env); err != nil {
			return nil, nil, err
		}
	}
	for _, pin := range helperPins() {
		p := obj(pin)
		if _, err := helperCommand([]string{"curl", "--fail", "--silent", "--show-error", "--head", "--max-time", "15",
			"https://raw.githubusercontent.com/" + str(p["repository"]) + "/" + str(p["revision"]) + "/README.md"}, env); err != nil {
			return nil, nil, err
		}
	}
	capacity := []any{}
	roomy := false
	for _, raw := range list(pools) {
		name := str(obj(raw)["name"])
		res, err := query("incus", "--force-local", "query", "/1.0/storage-pools/"+name+"/resources")
		if err != nil {
			return nil, nil, err
		}
		total, _ := num(jget(obj(res), "space", "total"))
		used, _ := num(jget(obj(res), "space", "used"))
		free := int64(total - used)
		roomy = roomy || free > 1<<30
		capacity = append(capacity, M{"name": name, "freeBytes": free})
	}
	if !roomy {
		return nil, nil, Public("No pool reports at least 1 GiB free; inspect Incus pool capacity")
	}
	return env, M{"project": project, "serverVersion": jget(obj(info), "environment", "server_version"), "pools": capacity,
		"networks": candidates, "sources": helperPins()}, nil
}

func helperInstances(env []string) (M, error) {
	out, err := helperCommand([]string{"incus", "--force-local", "list", "--format=json"}, env)
	if err != nil {
		return nil, err
	}
	items, err := parseJSON([]byte(out))
	if err != nil {
		return nil, err
	}
	result := M{}
	for _, i := range list(items) {
		result[str(obj(i)["name"])] = i
	}
	return result, nil
}

func observedVersions(guests M, env []string) M {
	checks := map[string][]string{"adguard": {"/opt/AdGuardHome/AdGuardHome", "--version"}, "vaultwarden": {"/opt/vaultwarden/bin/vaultwarden", "--version"}}
	result := M{}
	for name, guest := range guests {
		entry := M{"imageOS": jget(obj(guest), "config", "image.os"), "imageRelease": jget(obj(guest), "config", "image.release")}
		for app, args := range checks {
			if strings.HasPrefix(name, app) {
				if out, err := helperCommand(append([]string{"incus", "--force-local", "exec", name, "--"}, args...), env); err == nil {
					v := strings.TrimSpace(out)
					if len(v) > 500 {
						v = v[:500]
					}
					entry["applicationVersion"] = v
				}
			}
		}
		result[name] = entry
	}
	return result
}

func helpersMain(args []string) int {
	syscall.Umask(0o077)
	fail := func(err error) int { fmt.Fprintln(os.Stderr, publicError(err)); return 1 }
	project, action, script := "lab", "", ""
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--project" && i+1 < len(args):
			project = args[i+1]
			i++
		case action == "":
			action = args[i]
		case script == "":
			script = args[i]
		}
	}
	switch action {
	case "list":
		fmt.Print(string(jsonFile(M{"sources": helperPins(), "scripts": helperCatalog()})))
		return 0
	case "doctor", "run":
	default:
		fmt.Fprintln(os.Stderr, "usage: nixus-helpers {list,doctor,run} [script] [--project P]")
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "Run doctor/run with sudo on the Incus host")
		return 2
	}
	if action == "run" {
		known := false
		for _, item := range helperCatalog() {
			known = known || str(obj(item)["id"]) == script
		}
		if !fullmatch(helperName, script) || !known {
			fmt.Fprintln(os.Stderr, "Choose a packaged ct script ID from nixus-helpers list; PVE host/VM scripts are unsupported")
			return 2
		}
		if info, _ := os.Stdin.Stat(); info.Mode()&os.ModeCharDevice == 0 {
			fmt.Fprintln(os.Stderr, "The upstream wizard requires an interactive terminal")
			return 2
		}
	}
	if r, err := filepath.EvalSymlinks(filepath.Dir(helperState)); err == nil && filepath.Join(r, filepath.Base(helperState)) != helperState || isSymlink(helperState) {
		return fail(Public("Helper state cannot traverse symlinks"))
	}
	os.MkdirAll(helperState, 0o700)
	if info, err := os.Stat(helperState); err != nil || int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() || info.Mode().Perm()&0o077 != 0 {
		return fail(Public("Helper state must be root-owned with mode 0700"))
	}
	os.MkdirAll("/var/lib/nixus-admin", 0o700)
	code := 0
	err := locked(false, func() error {
		release, err := lockFile(incusLock, false)
		if err != nil {
			return err
		}
		defer release()
		active := str(readObj("/var/lib/nixus-admin/active.json")["id"])
		job := M{}
		if active != "" {
			job = readObj(filepath.Join("/var/lib/nixus-admin/jobs", active, "job.json"))
		}
		switch s := str(job["status"]); {
		case exists("/var/lib/nixus-admin/pending.json"), s == "building", s == "applying", s == "awaiting-confirmation", s == "rolling-back":
			return Public("Finish the host configuration transaction before running helper wizards")
		}
		folder, err := os.MkdirTemp(helperState, "client-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(folder)
		env, report, err := helperDoctor(project, folder)
		if err != nil {
			return err
		}
		if action == "doctor" {
			fmt.Print(string(jsonFile(report)))
			return nil
		}
		record := cloneM(report)
		record["script"], record["started"] = script, time.Now().UTC().Format(time.RFC3339Nano)
		before, err := helperInstances(env)
		if err != nil {
			return err
		}
		record["hostSystem"] = resolvedOr("/run/current-system")
		p := filepath.Join(helperState, strconv.Itoa(os.Getpid())+"-"+script+".json")
		os.WriteFile(p, jsonFile(record), 0o600)
		cmd := exec.Command("bash", filepath.Join(helperScripts, "ct", script+".sh"))
		cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = env, os.Stdin, os.Stdout, os.Stderr
		runErr := cmd.Run()
		var exit *exec.ExitError
		switch {
		case runErr == nil:
			record["exitStatus"] = 0
		case errors.As(runErr, &exit):
			code = exit.ExitCode()
			record["exitStatus"] = code
		default:
			code = 1
			record["exitStatus"] = "interrupted"
		}
		record["finished"] = time.Now().UTC().Format(time.RFC3339Nano)
		if after, err := helperInstances(env); err == nil {
			added := M{}
			for name, item := range after {
				if _, ok := before[name]; !ok {
					added[name] = item
				}
			}
			record["observedNewInstances"] = observedVersions(added, env)
		} else {
			record["metadataIncomplete"] = true
		}
		return os.WriteFile(p, jsonFile(record), 0o600)
	})
	if err != nil {
		return fail(err)
	}
	return code
}
