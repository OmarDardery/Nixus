package main

// Portal identities, first-administrator enrollment authority, local host
// administrator proof and local login readiness.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ROLES = map[string]bool{"admin": true, "operator": true, "viewer": true}
var operatorActions = map[string]bool{"start": true, "stop": true, "restart": true, "snapshot": true, "export": true}
var portalUser = re(`[a-z][a-z0-9_-]{0,31}`)

func accountRecord(username string) M {
	if username == "admin" {
		p := filepath.Join(STATE, "auth.json")
		v, err := readJSON(p, nil)
		if err != nil || isSymlink(p) || !validVerifier(v) {
			return nil
		}
		return M{"role": "admin", "password": v}
	}
	users := obj(must(readJSON(filepath.Join(STATE, "users.json"), M{})))
	item := obj(users[username])
	if item != nil && ROLES[str(item["role"])] && validVerifier(item["password"]) {
		return item
	}
	return nil
}

func accountMatches(username string, password any) bool {
	pw, ok := password.(string)
	item := accountRecord(username)
	baseline := item
	if baseline == nil {
		baseline = accountRecord("admin")
	}
	valid := ok && baseline != nil && passwordMatches(pw, obj(baseline["password"]))
	return item != nil && valid
}

func accountFingerprint(item M) string {
	return str(item["role"]) + ":" + str(obj(item["password"])["hash"])
}

func listUsers() []any {
	users := obj(must(readJSON(filepath.Join(STATE, "users.json"), M{})))
	out := []any{}
	if accountRecord("admin") != nil {
		out = append(out, M{"username": "admin", "role": "admin"})
	}
	for _, name := range keys(users) {
		out = append(out, M{"username": name, "role": str(obj(users[name])["role"])})
	}
	return out
}

func accountUpdate(username string, role any, password any, del bool) (M, error) {
	if !fullmatch(portalUser, username) || username == "admin" {
		return nil, Public("Use a named account other than the reserved recovery administrator")
	}
	err := locked(false, func() error {
		users := obj(must(readJSON(filepath.Join(STATE, "users.json"), M{})))
		if users == nil {
			users = M{}
		}
		if del {
			delete(users, username)
		} else {
			if !ROLES[str(role)] {
				return Public("Choose admin, operator or viewer")
			}
			item := obj(users[username])
			if item == nil {
				item = M{}
			}
			if pw, ok := password.(string); ok && pw != "" {
				record, err := passwordRecord(pw)
				if err != nil {
					return err
				}
				item["password"] = record
			}
			if item["password"] == nil {
				return Public("New accounts require a password")
			}
			item["role"] = role
			users[username] = item
		}
		return writeJSONMode(filepath.Join(STATE, "users.json"), users, 0o640, "nixus-ui")
	})
	if err != nil {
		return nil, err
	}
	audit("portal-account-updated", M{"username": username, "role": role, "deleted": del})
	return M{"users": listUsers()}, nil
}

func changePassword(username string, password any) (M, error) {
	pw, _ := password.(string)
	if username == "admin" {
		verifier, err := passwordRecord(pw)
		if err != nil {
			return nil, err
		}
		err = locked(false, func() error {
			if _, err := enrollmentReconcile(); err != nil {
				return err
			}
			if err := writeJSONMode(filepath.Join(STATE, "auth.json"), verifier, 0o640, "nixus-ui"); err != nil {
				return err
			}
			if err := enrollmentSave("migrated", nil); err != nil {
				return err
			}
			retireLegacyCapabilities()
			return durableUnlink(filepath.Join(STATE, "setup-password"))
		})
		if err != nil {
			return nil, err
		}
	} else {
		current := accountRecord(username)
		if current == nil {
			return nil, Public("Unknown account")
		}
		if _, err := accountUpdate(username, current["role"], pw, false); err != nil {
			return nil, err
		}
	}
	return M{"ok": true}, nil
}

func localRoot() bool { return os.Geteuid() == 0 }

func recoverPassword(password string) error {
	if !localRoot() {
		return &AuthorizationError{"Local root approval is required for account recovery"}
	}
	verifier, err := passwordRecord(password)
	if err != nil {
		return err
	}
	err = locked(false, func() error {
		if _, err := enrollmentLoad(); err != nil {
			return err
		}
		if err := enrollmentSave("recovery-authorized", nil); err != nil {
			return err
		}
		retireLegacyCapabilities()
		if err := writeJSONMode(filepath.Join(STATE, "auth.json"), verifier, 0o640, "nixus-ui"); err != nil {
			return err
		}
		if err := enrollmentSave("migrated", nil); err != nil {
			return err
		}
		return durableUnlink(filepath.Join(STATE, "setup-password"))
	})
	if err == nil {
		audit("portal-account-recovered", nil)
	}
	return err
}

func authorize(session M, path string, body M) error {
	role := str(session["role"])
	if role == "admin" || path == "/api/logout" || path == "/api/password" {
		return nil
	}
	project := "lab"
	if v, ok := body["project"]; ok {
		project = str(v)
	}
	if role == "operator" && path == "/api/operation" && project == "lab" && operatorActions[str(body["action"])] {
		return nil
	}
	return &AuthorizationError{"This operation requires an administrator account"}
}

// --- first-administrator enrollment authority ----------------------------

const enrollmentStateFile = "bootstrap-state.json"

var enrollmentPhases = map[string]bool{"unclaimed": true, "host-verified": true, "committing": true,
	"account-committed": true, "legacy-provisioning": true, "migrated": true, "recovery-authorized": true}
var hex64 = re(`[0-9a-f]{64}`)
var hex48 = re(`[0-9a-f]{48}`)
var hex32 = re(`[0-9a-f]{32}`)

func recoveryError() error {
	return Public("Portal enrollment is locked; use sudo nixus-admin reset-password from a private host terminal or restore supported account state")
}

func present(name string) bool { return lexists(filepath.Join(STATE, name)) }

func validVerifier(v any) bool {
	m := obj(v)
	if m == nil || len(m) != 3 {
		return false
	}
	it, ok := num(m["iterations"])
	return fullmatch(hex48, str(m["salt"])) && fullmatch(hex64, str(m["hash"])) && ok && isInt(m["iterations"]) &&
		it >= 10000 && it <= 10000000
}

func authValid() bool {
	p := filepath.Join(STATE, "auth.json")
	v, err := readJSON(p, nil)
	return err == nil && !isSymlink(p) && validVerifier(v)
}

func accountValid() bool {
	if authValid() || isFile(filepath.Join(STATE, linuxLoginMarker)) {
		return true
	}
	p := filepath.Join(STATE, "users.json")
	v, err := readJSON(p, M{})
	users := obj(v)
	if err != nil || isSymlink(p) || users == nil {
		return false
	}
	for name, item := range users {
		it := obj(item)
		if name != "admin" && fullmatch(portalUser, name) && it != nil && str(it["role"]) == "admin" && validVerifier(it["password"]) {
			return true
		}
	}
	return false
}

func enrollmentLoad() (M, error) {
	if !present(enrollmentStateFile) {
		return nil, nil
	}
	p := filepath.Join(STATE, enrollmentStateFile)
	info, err := os.Lstat(p)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Size() > 16384 {
		return nil, recoveryError()
	}
	value, err := mustReadObj(p)
	if err != nil {
		return nil, recoveryError()
	}
	if v, _ := num(value["version"]); v != 1 || !isInt(value["version"]) || !enrollmentPhases[str(value["phase"])] {
		return nil, recoveryError()
	}
	for k := range value {
		if k != "version" && k != "phase" && k != "proof" && k != "claimDigest" {
			return nil, recoveryError()
		}
	}
	phase := str(value["phase"])
	if phase == "host-verified" || phase == "committing" {
		proof := obj(value["proof"])
		expires, ok := num(proof["expires"])
		if proof == nil || len(proof) != 3 || !fullmatch(hex64, str(proof["digest"])) || str(proof["boot"]) == "" || !ok || expires <= 0 {
			return nil, recoveryError()
		}
	} else if _, ok := value["proof"]; ok {
		return nil, recoveryError()
	}
	if cd, ok := value["claimDigest"]; ok && (phase != "account-committed" || !fullmatch(hex64, str(cd))) {
		return nil, recoveryError()
	}
	return value, nil
}

func enrollmentSave(phase string, fields M) error {
	value := M{"version": 1, "phase": phase}
	for k, v := range fields {
		value[k] = v
	}
	return writeJSON(filepath.Join(STATE, enrollmentStateFile), value)
}

func retireLegacyCapabilities() {
	for _, name := range []string{"web-enrollment", "web-enrollment-approval.json"} {
		durableUnlink(filepath.Join(STATE, name))
	}
}

// enrollmentReconcile requires the mutation lock to be held.
func enrollmentReconcile() (M, error) {
	state, err := enrollmentLoad()
	if err != nil {
		return nil, err
	}
	if accountValid() {
		phase := str(state["phase"])
		if state == nil || (phase != "account-committed" && phase != "migrated") {
			retireLegacyCapabilities()
			if state != nil && phase == "committing" {
				err = enrollmentSave("account-committed", M{"claimDigest": obj(state["proof"])["digest"]})
			} else {
				err = enrollmentSave("migrated", nil)
			}
			if err != nil {
				return nil, err
			}
			return enrollmentLoad()
		}
	}
	return state, nil
}

func hostHistory() bool {
	for _, name := range []string{"active.json", "last-confirmed.json", "pending.json"} {
		if present(name) {
			return true
		}
	}
	entries, err := os.ReadDir(filepath.Join(STATE, "jobs"))
	return err == nil && len(entries) > 0
}

func accountArtifacts() bool {
	return present("auth.json") || present("users.json") || present("setup-password")
}

func enrollmentStatus() (M, error) {
	return lockedValue(true, func() (M, error) {
		state, err := enrollmentReconcile()
		if err != nil {
			return M{"available": false, "recoveryRequired": true}, nil
		}
		phase := str(state["phase"])
		artifacts := accountArtifacts()
		available := (phase == "unclaimed" || phase == "host-verified") && !artifacts
		committed := phase == "committing" || phase == "account-committed" || phase == "migrated" || phase == "recovery-authorized"
		recovery := !accountValid() && (artifacts || committed || (state == nil && (present("web-enrollment") || hostHistory())))
		return M{"available": available, "recoveryRequired": recovery}, nil
	})
}

func enrollmentEnable() error {
	return locked(true, func() error {
		state, err := enrollmentReconcile()
		if err != nil {
			return err
		}
		phase := str(state["phase"])
		if accountArtifacts() || (state != nil && phase != "unclaimed" && phase != "host-verified") {
			return Public("This host already has portal account state; use authorized account recovery")
		}
		if state == nil {
			if err := enrollmentSave("unclaimed", nil); err != nil {
				return err
			}
		}
		return atomicString(filepath.Join(STATE, "web-enrollment"), "1\n", 0o600)
	})
}

func proofDigest(code any) (string, error) {
	c, ok := code.(string)
	if !ok || !fullmatch(hex32, c) {
		return "", Public("Use the approval code displayed in your browser")
	}
	h := sha256.Sum256([]byte(c))
	return hex.EncodeToString(h[:]), nil
}

var bootIDOverride string

func bootID() string {
	if bootIDOverride != "" {
		return bootIDOverride
	}
	raw, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(raw))
}

func enrollmentApprove(code string) error {
	digest, err := proofDigest(code)
	if err != nil {
		return err
	}
	return locked(false, func() error {
		state, err := enrollmentReconcile()
		if err != nil {
			return err
		}
		if accountArtifacts() {
			return Public("First administrator enrollment is unavailable; use authorized account recovery")
		}
		if state == nil && present("web-enrollment") {
			state = M{"phase": "unclaimed"}
		}
		phase := str(state["phase"])
		if state == nil || (phase != "unclaimed" && phase != "host-verified" && phase != "committing") {
			return recoveryError()
		}
		durableUnlink(filepath.Join(STATE, "web-enrollment-approval.json"))
		return enrollmentSave("host-verified", M{"proof": M{"digest": digest, "boot": bootID(), "expires": monotonic() + 600}})
	})
}

func enrollmentClaim(code, password any) (M, error) {
	digest, err := proofDigest(code)
	if err != nil {
		return nil, err
	}
	return lockedValue(false, func() (M, error) { return claimLocked(digest, password, "admin") })
}

// claimLocked commits the first administrator; the caller holds the lock.
func claimLocked(digest string, password any, username any) (M, error) {
	state, err := enrollmentReconcile()
	if err != nil {
		return nil, err
	}
	phase := str(state["phase"])
	if state != nil && phase == "account-committed" && accountValid() && compareDigest(str(state["claimDigest"]), digest) {
		return M{"ok": true, "alreadyComplete": true}, nil
	}
	if state == nil || (phase != "unclaimed" && phase != "host-verified") || accountArtifacts() {
		return nil, Public("First administrator enrollment is unavailable; use authorized account recovery")
	}
	proof := obj(state["proof"])
	expires, _ := num(proof["expires"])
	if str(proof["boot"]) != bootID() || monotonic() >= expires || !compareDigest(str(proof["digest"]), digest) {
		return nil, Public("Approve this browser from the host console before enrolling")
	}
	name, ok := username.(string)
	if !ok || !fullmatch(portalUser, name) {
		return nil, Public("Choose a portal username starting with a letter, followed by up to 31 lowercase letters, numbers, underscores or hyphens")
	}
	pw, _ := password.(string)
	verifier, err := passwordRecord(pw)
	if err != nil {
		return nil, err
	}
	if err := enrollmentSave("committing", M{"proof": proof}); err != nil {
		return nil, err
	}
	retireLegacyCapabilities()
	if name == "admin" {
		err = writeJSONMode(filepath.Join(STATE, "auth.json"), verifier, 0o640, "nixus-ui")
	} else {
		err = writeJSONMode(filepath.Join(STATE, "users.json"), M{name: M{"role": "admin", "password": verifier}}, 0o640, "nixus-ui")
	}
	if err != nil {
		return nil, err
	}
	if err := enrollmentSave("account-committed", M{"claimDigest": digest}); err != nil {
		return nil, err
	}
	audit("first-admin-enrolled", nil)
	return M{"ok": true}, nil
}

// ensureWebEnrollment opens console-approved enrollment on a fresh host.
func ensureWebEnrollment() (string, error) {
	return lockedValue(true, func() (string, error) {
		state, err := enrollmentReconcile()
		if err != nil {
			return "", err
		}
		if accountValid() {
			return "account", nil
		}
		phase := str(state["phase"])
		if state != nil && (phase == "unclaimed" || phase == "host-verified") {
			if !present("web-enrollment") {
				if err := atomicString(filepath.Join(STATE, "web-enrollment"), "1\n", 0o600); err != nil {
					return "", err
				}
			}
			return "enrollment", nil
		}
		if state == nil && !hostHistory() && !accountArtifacts() && !present("web-enrollment") {
			if err := enrollmentSave("unclaimed", nil); err != nil {
				return "", err
			}
			return "enrollment", atomicString(filepath.Join(STATE, "web-enrollment"), "1\n", 0o600)
		}
		return "", recoveryError()
	})
}

func enrollmentObserve(isLocked bool) error {
	if isLocked {
		_, err := enrollmentReconcile()
		return err
	}
	return locked(true, func() error { _, err := enrollmentReconcile(); return err })
}

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

func operatorUnsetMarker() string { return filepath.Join(STATE, "operator-password-unset") }

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

// ensureOperatorPassword locks the managed operator until a password is set.
func ensureOperatorPassword() error {
	encoded := SECRET_PATHS["cockpitPassword"]
	durableUnlink(filepath.Join(STATE, "operator-password"))
	if !exists(encoded) {
		hash, err := lockedPasswordHash()
		if err != nil {
			return err
		}
		if err := atomicString(encoded, hash, 0o600); err != nil {
			return err
		}
		return atomicString(operatorUnsetMarker(), "1\n", 0o600)
	}
	return nil
}

var _ = sync.Mutex{}
