package main

// Sign-in with the host's Linux accounts (PAM + sudo) and local login readiness.

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var portalUser = re(`[a-z_][a-z0-9_-]{0,31}`)
var hex64 = re(`[0-9a-f]{64}`)
var hex48 = re(`[0-9a-f]{48}`)
var hex32 = re(`[0-9a-f]{32}`)

func sha256str(s string) string { return sha256hex([]byte(s)) }

func present(name string) bool { return lexists(filepath.Join(STATE, name)) }

// --- local host administrator proof ---------------------------------------

const pamService = "nixus-enrollment"

var hostProofSlots = make(chan struct{}, 2)
var hostUser = re(`[a-z_][a-z0-9_-]{0,31}`)

type passwdEntry struct {
	name  string
	uid   int
	gid   int
	home  string
	shell string
}

func passwdEntries() []passwdEntry {
	raw, _ := os.ReadFile("/etc/passwd")
	var out []passwdEntry
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, passwdEntry{f[0], uid, gid, f[5], f[6]})
	}
	return out
}

// groupMembers returns the gid and listed members of a local group.
func groupMembers(name string) (int, []string, bool) {
	raw, _ := os.ReadFile("/etc/group")
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 4 || f[0] != name {
			continue
		}
		gid, err := strconv.Atoi(f[2])
		if err != nil {
			return 0, nil, false
		}
		var members []string
		if f[3] != "" {
			members = strings.Split(f[3], ",")
		}
		return gid, members, true
	}
	return 0, nil, false
}

func hostProofVerify(username, password any) (string, error) {
	fail := Public("Host verification failed; use a valid local sudo administrator or console approval")
	name, ok1 := username.(string)
	pw, ok2 := password.(string)
	if !ok1 || !ok2 || !fullmatch(hostUser, name) || len(pw) < 1 || len([]rune(pw)) > 1024 || strings.ContainsAny(pw, "\x00\r\n") {
		return "", fail
	}
	select {
	case hostProofSlots <- struct{}{}:
	default:
		return "", Public("Host verification is busy; wait and retry")
	}
	defer func() { <-hostProofSlots }()
	var entry *passwdEntry
	for _, e := range passwdEntries() {
		if e.name == name {
			e := e
			entry = &e
			break
		}
	}
	shell := filepath.Base(func() string {
		if entry == nil {
			return "nologin"
		}
		return entry.shell
	}())
	helper := lookPath("pamtester")
	if entry == nil || (entry.uid != 0 && entry.uid < 1000) || shell == "false" || shell == "nologin" || helper == "" ||
		!isFile("/etc/pam.d/"+pamService) {
		return "", fail
	}
	res, err := run([]string{helper, pamService, name, "authenticate(PAM_SILENT|PAM_DISALLOW_NULL_AUTHTOK)", "acct_mgmt"},
		[]byte(pw+"\n"), 10*time.Second, nil, "")
	if err != nil || res.Code != 0 {
		return "", fail
	}
	res, err = run([]string{"/run/wrappers/bin/sudo", "-n", "-l", "-U", name, "-u", "root", "--", "/run/current-system/sw/bin/bash"},
		nil, 5*time.Second, []string{"PATH=/run/current-system/sw/bin:/run/wrappers/bin", "LC_ALL=C"}, "")
	if err != nil || res.Code != 0 {
		return "", fail
	}
	return name, nil
}

// linuxLogin checks a Linux account for portal sign-in: the PAM password and
// sudo rights (the same proof as first-run enrollment). Sudo users are
// portal administrators; others use portal-only accounts.
func linuxLogin(username, password any) (M, error) {
	name, err := hostProofVerify(username, password)
	if err != nil {
		return nil, Public("Invalid username or password")
	}
	writeJSON(filepath.Join(STATE, linuxLoginMarker), M{"username": name, "at": now()})
	return M{"username": name, "role": "admin"}, nil
}

const linuxLoginMarker = "linux-login.json"

func lookPath(name string) string {
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		p := filepath.Join(dir, name)
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}

// --- local login readiness ------------------------------------------------

func shadowHash(username string) string {
	res, err := run([]string{"getent", "shadow", username}, nil, 10*time.Second, nil, "")
	if err != nil || res.Code != 0 {
		return ""
	}
	f := strings.Split(strings.TrimSpace(string(res.Stdout)), ":")
	if len(f) == 9 && f[0] == username {
		return f[1]
	}
	return ""
}

func cockpitAccounts() []string {
	gid, members, ok := groupMembers("wheel")
	if !ok {
		return []string{}
	}
	accounts := []string{}
	for _, a := range passwdEntries() {
		if a.uid == 0 || strings.HasSuffix(a.shell, "/nologin") || strings.HasSuffix(a.shell, "/false") {
			continue
		}
		member := a.gid == gid
		for _, m := range members {
			if m == a.name {
				member = true
			}
		}
		if !member {
			continue
		}
		encoded := shadowHash(a.name)
		if encoded != "" && !strings.HasPrefix(encoded, "!") && !strings.HasPrefix(encoded, "*") {
			accounts = append(accounts, a.name)
		}
	}
	sort.Strings(accounts)
	return accounts
}

var _ = sync.Mutex{}
