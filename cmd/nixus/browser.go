package main

// Browser-bound first-administrator bootstrap, root-approved account recovery
// and owned Incus browser client certificates.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const bootstrapFile = "bootstrap-sessions.json"
const bootstrapTTL = 600

var browserToken = re(`[A-Za-z0-9_-]{43}`)

func sha256str(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func material(token, label string) string { return sha256str(label + ":" + token) }

func requireEnrollmentOpen() (M, error) {
	state, err := enrollmentReconcile()
	if err != nil {
		return nil, err
	}
	phase := str(state["phase"])
	if state == nil || (phase != "unclaimed" && phase != "host-verified") || accountArtifacts() {
		return nil, Public("First administrator enrollment is closed; sign in or use authorized account recovery")
	}
	return state, nil
}

func finiteTimes(v any, max int) ([]float64, bool) {
	l, ok := v.([]any)
	if !ok || len(l) > max {
		return nil, false
	}
	out := make([]float64, 0, len(l))
	for _, x := range l {
		f, ok := num(x)
		if !ok {
			return nil, false
		}
		out = append(out, f)
	}
	return out, true
}

func freshBootstrap(boot string) M {
	return M{"version": 1, "boot": boot, "sessions": M{}, "attempts": M{}, "created": M{}}
}

func bootstrapLoad() (M, error) {
	fail := Public("Bootstrap session state is unavailable; inspect supported root state or use console recovery")
	at, boot := monotonic(), bootID()
	p := filepath.Join(STATE, bootstrapFile)
	if info, err := os.Lstat(p); err == nil && (info.Mode()&os.ModeSymlink != 0 || info.Size() > 131072) {
		return nil, fail
	}
	raw, err := readJSON(p, freshBootstrap(boot))
	value := obj(raw)
	if err != nil || value == nil || !isInt(value["version"]) || value["version"] != float64(1) && value["version"] != 1 ||
		!isStr(value["boot"]) || obj(value["sessions"]) == nil || obj(value["attempts"]) == nil || obj(value["created"]) == nil {
		return nil, fail
	}
	if str(value["boot"]) != boot {
		return freshBootstrap(boot), nil
	}
	sessions := obj(value["sessions"])
	if len(sessions) > 64 || len(obj(value["attempts"])) > 128 || len(obj(value["created"])) > 128 {
		return nil, fail
	}
	for key, raw := range sessions {
		item := obj(raw)
		expires, ok := num(item["expires"])
		if !fullmatch(hex64, key) || item == nil || !ok || !fullmatch(hex64, str(item["csrfHash"])) ||
			!isStr(item["address"]) || !isStr(item["origin"]) {
			return nil, fail
		}
		if at >= expires {
			delete(sessions, key)
		}
	}
	for _, group := range []string{"attempts", "created"} {
		bucket := obj(value[group])
		for address, times := range bucket {
			list, ok := finiteTimes(times, 64)
			if !ok {
				return nil, fail
			}
			kept := []any{}
			for _, t := range list {
				if at-t >= 0 && at-t < 300 {
					kept = append(kept, t)
				}
			}
			if len(kept) == 0 {
				delete(bucket, address)
			} else {
				bucket[address] = kept
			}
		}
	}
	return value, nil
}

func bootstrapScope(address, origin any) error {
	a, ok1 := address.(string)
	o, ok2 := origin.(string)
	if !ok1 || !ok2 || net.ParseIP(a) == nil || !strings.HasPrefix(o, "https://") || len(o) > 256 {
		return Public("Invalid bootstrap request scope")
	}
	return nil
}

func bootstrapCharge(value M, group, address string, limit, global int) error {
	bucket := obj(value[group])
	total := 0
	for _, v := range bucket {
		total += len(list(v))
	}
	if len(list(bucket[address])) >= limit || total >= global || len(bucket) >= 128 {
		return Public("Too many bootstrap attempts; wait five minutes before retrying")
	}
	bucket[address] = append(list(bucket[address]), monotonic())
	return nil
}

func bootstrapChecked(value M, token, csrf, address, origin any) (M, error) {
	if err := bootstrapScope(address, origin); err != nil {
		return nil, err
	}
	fail := Public("Bootstrap session expired or request token is invalid; reload and verify this browser again")
	t, ok1 := token.(string)
	c, ok2 := csrf.(string)
	if !ok1 || !ok2 || !fullmatch(browserToken, t) {
		return nil, fail
	}
	record := obj(obj(value["sessions"])[sha256str(t)])
	if record == nil || str(record["address"]) != address || str(record["origin"]) != origin ||
		!compareDigest(str(record["csrfHash"]), sha256str(c)) {
		return nil, fail
	}
	return record, nil
}

func bootstrapStart(token, address, origin any) (M, error) {
	if err := bootstrapScope(address, origin); err != nil {
		return nil, err
	}
	return lockedValue(false, func() (M, error) {
		state, err := requireEnrollmentOpen()
		if err != nil {
			return nil, err
		}
		value, err := bootstrapLoad()
		if err != nil {
			return nil, err
		}
		t, _ := token.(string)
		sessions := obj(value["sessions"])
		var record M
		if fullmatch(browserToken, t) {
			record = obj(sessions[sha256str(t)])
		}
		if record != nil && (str(record["address"]) != address || str(record["origin"]) != origin) {
			return nil, Public("Bootstrap browser scope changed; reload on the trusted management address")
		}
		if record == nil {
			if err := bootstrapCharge(value, "created", address.(string), 8, 64); err != nil {
				return nil, err
			}
			if len(sessions) >= 64 {
				return nil, Public("Bootstrap sessions are busy; wait and retry")
			}
			t = tokenURLSafe(32)
			record = M{"address": address, "origin": origin, "expires": monotonic() + bootstrapTTL,
				"csrfHash": sha256str(material(t, "csrf"))}
			sessions[sha256str(t)] = record
		}
		if err := writeJSON(filepath.Join(STATE, bootstrapFile), value); err != nil {
			return nil, err
		}
		code := material(t, "console")[:32]
		proof := obj(state["proof"])
		expires, _ := num(proof["expires"])
		digest, _ := proofDigest(code)
		approved := str(proof["boot"]) == bootID() && monotonic() < expires && compareDigest(str(proof["digest"]), digest)
		recExpires, _ := num(record["expires"])
		return M{"token": t, "csrf": material(t, "csrf"), "approvalCode": code, "approved": approved,
			"expiresIn": max(0, int(recExpires-monotonic()))}, nil
	})
}

func bootstrapVerify(token, csrf, address, origin, username, password any) (M, error) {
	nonce := tokenHex(16)
	err := locked(false, func() error {
		if _, err := requireEnrollmentOpen(); err != nil {
			return err
		}
		value, err := bootstrapLoad()
		if err != nil {
			return err
		}
		record, err := bootstrapChecked(value, token, csrf, address, origin)
		if err != nil {
			return err
		}
		if until, _ := num(record["checkingUntil"]); until > monotonic() {
			return Public("Host verification is busy; wait and retry")
		}
		if err := bootstrapCharge(value, "attempts", address.(string), 5, 20); err != nil {
			return err
		}
		record["checking"] = nonce
		record["checkingUntil"] = monotonic() + 15
		return writeJSON(filepath.Join(STATE, bootstrapFile), value)
	})
	if err != nil {
		return nil, err
	}
	principal, err := hostProofVerify(username, password)
	if err != nil {
		locked(false, func() error {
			value, err := bootstrapLoad()
			if err != nil {
				return err
			}
			record, err := bootstrapChecked(value, token, csrf, address, origin)
			if err == nil && str(record["checking"]) == nonce {
				delete(record, "checking")
				delete(record, "checkingUntil")
				writeJSON(filepath.Join(STATE, bootstrapFile), value)
			}
			return nil
		})
		return nil, Public("Host verification failed; check the local administrator credentials or use console approval")
	}
	err = locked(false, func() error {
		if _, err := requireEnrollmentOpen(); err != nil {
			return err
		}
		value, err := bootstrapLoad()
		if err != nil {
			return err
		}
		record, err := bootstrapChecked(value, token, csrf, address, origin)
		if err != nil {
			return err
		}
		if str(record["checking"]) != nonce {
			return Public("Host verification expired; verify this browser again")
		}
		delete(record, "checking")
		delete(record, "checkingUntil")
		if err := writeJSON(filepath.Join(STATE, bootstrapFile), value); err != nil {
			return err
		}
		digest, _ := proofDigest(material(token.(string), "console")[:32])
		expires, _ := num(record["expires"])
		if err := enrollmentSave("host-verified", M{"proof": M{"digest": digest, "boot": bootID(),
			"expires": min(expires, monotonic()+bootstrapTTL)}}); err != nil {
			return err
		}
		audit("bootstrap-host-verified", M{"principal": principal})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return M{"approved": true}, nil
}

func bootstrapClaim(token, csrf, address, origin, username, password any) (M, error) {
	return lockedValue(false, func() (M, error) {
		if _, err := requireEnrollmentOpen(); err != nil {
			return nil, err
		}
		value, err := bootstrapLoad()
		if err != nil {
			return nil, err
		}
		if _, err := bootstrapChecked(value, token, csrf, address, origin); err != nil {
			return nil, err
		}
		digest, _ := proofDigest(material(token.(string), "console")[:32])
		result, err := claimLocked(digest, password, username)
		if err != nil {
			return nil, err
		}
		value["sessions"] = M{}
		return result, writeJSON(filepath.Join(STATE, bootstrapFile), value)
	})
}

// --- root-approved account recovery (#28) ---------------------------------

const recoveryFile = "recovery-requests.json"
const recoveryTTL = 300

var recoveryRequestID = re(`[0-9A-F]{4}-[0-9A-F]{4}`)

func recoveryRequestIDFor(token string) string {
	value := strings.ToUpper(material(token, "recovery-id")[:8])
	return value[:4] + "-" + value[4:]
}

func recoveryEmpty() M {
	return M{"version": 1, "boot": bootID(), "requests": M{}, "created": M{}}
}

func recoveryLoad() (M, error) {
	fail := Public("Recovery request state is unavailable; use sudo nixus-admin reset-password from a private terminal")
	at := monotonic()
	p := filepath.Join(STATE, recoveryFile)
	if info, err := os.Lstat(p); err == nil && (info.Mode()&os.ModeSymlink != 0 || info.Size() > 65536) {
		return nil, fail
	}
	raw, err := readJSON(p, nil)
	if err != nil {
		return nil, fail
	}
	value := obj(raw)
	if raw == nil {
		value = recoveryEmpty()
	}
	if value == nil || value["version"] != float64(1) && value["version"] != 1 || !isStr(value["boot"]) ||
		obj(value["requests"]) == nil || obj(value["created"]) == nil {
		return nil, fail
	}
	if str(value["boot"]) != bootID() {
		return recoveryEmpty(), nil
	}
	requests := obj(value["requests"])
	for key, raw := range requests {
		item := obj(raw)
		expires, ok := num(item["expires"])
		approved := item["approved"]
		if !fullmatch(hex64, key) || item == nil || !fullmatch(recoveryRequestID, str(item["id"])) || !ok ||
			!fullmatch(hex64, str(item["csrfHash"])) || !isStr(item["address"]) || !isStr(item["origin"]) ||
			(approved != nil && !isStr(approved)) {
			return nil, fail
		}
		if at >= expires || isTrue(item["consumed"]) {
			delete(requests, key)
		}
	}
	created := obj(value["created"])
	for address, times := range created {
		list, ok := finiteTimes(times, 1<<20)
		if !ok {
			return nil, fail
		}
		kept := []any{}
		for _, t := range list {
			if at-t >= 0 && at-t < 300 {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(created, address)
		} else {
			created[address] = kept
		}
	}
	return value, nil
}

func recoverySave(value M) error { return writeJSON(filepath.Join(STATE, recoveryFile), value) }

func recoveryRequireAccounts() ([]any, error) {
	users := listUsers()
	if len(users) == 0 {
		return nil, Public("No portal account exists yet; use first-administrator enrollment")
	}
	return users, nil
}

func recoveryChecked(value M, token, csrf, address, origin any) (M, error) {
	if err := bootstrapScope(address, origin); err != nil {
		return nil, err
	}
	fail := Public("Recovery request expired or invalid; start again from the sign-in page")
	t, ok1 := token.(string)
	c, ok2 := csrf.(string)
	if !ok1 || !ok2 || !fullmatch(browserToken, t) {
		return nil, fail
	}
	record := obj(obj(value["requests"])[sha256str(t)])
	if record == nil || str(record["address"]) != address || str(record["origin"]) != origin ||
		!compareDigest(str(record["csrfHash"]), sha256str(c)) {
		return nil, fail
	}
	return record, nil
}

func recoveryStart(token, address, origin any) (M, error) {
	if err := bootstrapScope(address, origin); err != nil {
		return nil, err
	}
	return lockedValue(false, func() (M, error) {
		if _, err := recoveryRequireAccounts(); err != nil {
			return nil, err
		}
		value, err := recoveryLoad()
		if err != nil {
			return nil, err
		}
		requests := obj(value["requests"])
		t, _ := token.(string)
		var record M
		if fullmatch(browserToken, t) {
			record = obj(requests[sha256str(t)])
		}
		if record != nil && (str(record["address"]) != address || str(record["origin"]) != origin) {
			return nil, Public("Recovery browser scope changed; start again on the management address")
		}
		if record == nil {
			created := obj(value["created"])
			addr := address.(string)
			if len(list(created[addr])) >= 5 || len(requests) >= 32 {
				return nil, Public("Too many recovery requests; wait five minutes before retrying")
			}
			created[addr] = append(list(created[addr]), monotonic())
			t = tokenURLSafe(32)
			record = M{"id": recoveryRequestIDFor(t), "address": address, "origin": origin,
				"expires": monotonic() + recoveryTTL, "csrfHash": sha256str(material(t, "recovery-csrf")), "approved": nil}
			requests[sha256str(t)] = record
		}
		if err := recoverySave(value); err != nil {
			return nil, err
		}
		expires, _ := num(record["expires"])
		return M{"token": t, "csrf": material(t, "recovery-csrf"), "requestId": record["id"],
			"approved": record["approved"] != nil, "username": record["approved"],
			"expiresIn": max(0, int(expires-monotonic()))}, nil
	})
}

func recoveryApprove(identifier string, username string) (M, error) {
	if !localRoot() {
		return nil, &AuthorizationError{"Local root approval is required"}
	}
	identifier = strings.ToUpper(strings.TrimSpace(identifier))
	if !fullmatch(recoveryRequestID, identifier) {
		return nil, Public("Use the request ID shown in the browser, for example ABCD-1234")
	}
	err := locked(false, func() error {
		users, err := recoveryRequireAccounts()
		if err != nil {
			return err
		}
		var names []string
		for _, u := range users {
			names = append(names, str(obj(u)["username"]))
		}
		if username == "" {
			if len(names) != 1 {
				return Public("Several portal accounts exist; choose one with --user NAME")
			}
			username = names[0]
		}
		found := false
		for _, n := range names {
			if n == username {
				found = true
			}
		}
		if !found {
			return Public("Unknown portal account")
		}
		value, err := recoveryLoad()
		if err != nil {
			return err
		}
		var matches []M
		for _, r := range obj(value["requests"]) {
			if compareDigest(str(obj(r)["id"]), identifier) {
				matches = append(matches, obj(r))
			}
		}
		if len(matches) != 1 {
			return Public("No pending recovery request has that ID; it may have expired")
		}
		if matches[0]["approved"] != nil {
			return Public("That recovery request is already approved")
		}
		matches[0]["approved"] = username
		return recoverySave(value)
	})
	if err != nil {
		return nil, err
	}
	audit("portal-recovery-approved", M{"username": username})
	return M{"approved": true}, nil
}

func recoveryComplete(token, csrf, address, origin, password any) (M, error) {
	var username string
	err := locked(false, func() error {
		value, err := recoveryLoad()
		if err != nil {
			return err
		}
		record, err := recoveryChecked(value, token, csrf, address, origin)
		if err != nil {
			return err
		}
		if record["approved"] == nil {
			return Public("Approve this request from the host first with the command shown on this page")
		}
		username = str(record["approved"])
		if accountRecord(username) == nil {
			return Public("The approved account no longer exists; start again")
		}
		pw, ok := password.(string)
		if n := len([]rune(pw)); !ok || n < 16 || n > 256 {
			return Public("Administrator passwords must contain 16–256 characters")
		}
		record["consumed"] = true
		return recoverySave(value)
	})
	if err != nil {
		return nil, err
	}
	if _, err := changePassword(username, password); err != nil {
		return nil, err
	}
	locked(false, func() error {
		value, err := recoveryLoad()
		if err != nil {
			return err
		}
		requests := obj(value["requests"])
		for k, r := range requests {
			if str(obj(r)["approved"]) == username {
				delete(requests, k)
			}
		}
		return recoverySave(value)
	})
	audit("portal-recovery-completed", M{"username": username})
	return M{"ok": true, "username": username}, nil
}

// --- owned Incus browser certificates -------------------------------------

const browserRuntime = "/run/nixus-browser"
const browserValidDays = 90
const browserPrivateLifetime = 300

var deviceName = re(`[A-Za-z0-9][A-Za-z0-9_-]{0,31}`)

func certFingerprint(v any) (string, error) {
	s, ok := v.(string)
	if !ok || !fullmatch(hex64, s) {
		return "", Public("Select a complete owned certificate fingerprint")
	}
	return s, nil
}

// certTime parses OpenSSL "notAfter" dates such as "Mar  5 12:00:00 2027 GMT".
func certTime(s string) (time.Time, error) {
	return time.Parse("Jan _2 15:04:05 2006 MST", strings.Join(strings.Fields(s), " "))
}

func browserRegistry(state string) (M, error) {
	value, err := readJobRecord(filepath.Join(state, "browser-certificates.json"), M{"version": 1, "certificates": M{}})
	if err != nil {
		return nil, err
	}
	fail := Public("Browser certificate ownership registry is invalid; use local recovery")
	if v, _ := num(value["version"]); v != 1 || obj(value["certificates"]) == nil {
		return nil, fail
	}
	for identity, raw := range obj(value["certificates"]) {
		record := obj(raw)
		if _, err := certFingerprint(identity); err != nil || record == nil {
			return nil, fail
		}
		device := str(record["device"])
		restricted, isBool := record["restricted"].(bool)
		wantProjects := []any{}
		if restricted {
			wantProjects = []any{"lab"}
		}
		status := str(record["status"])
		_, okIssued := num(record["issuedAt"])
		if str(record["fingerprint"]) != identity || !fullmatch(deviceName, device) ||
			!fullmatch(re(`nixus-browser-`+regexp.QuoteMeta(device)+`-[0-9a-f]{12}`), str(record["name"])) ||
			!fullmatch(portalUser, str(record["owner"])) || !isBool || !equalJSON(record["projects"], wantProjects) ||
			(status != "issuing" && status != "active" && status != "revoked" && status != "expired") || !okIssued {
			return nil, fail
		}
		if _, err := certTime(str(record["expiresAt"])); err != nil {
			return nil, fail
		}
	}
	return value, nil
}

func browserPublic(record M) M {
	out := M{}
	for _, k := range []string{"name", "device", "fingerprint", "owner", "issuedAt", "expiresAt", "restricted", "projects", "status"} {
		out[k] = record[k]
	}
	return out
}

func trustedCertificates() (map[string]M, error) {
	out, err := command([]string{"incus", "--force-local", "query", "/1.0/certificates?recursion=1"}, 60*time.Second)
	if err != nil {
		return nil, err
	}
	items, ok := must(parseJSON([]byte(out))).([]any)
	if !ok {
		return nil, Public("Incus certificate inventory is unavailable")
	}
	result := map[string]M{}
	for _, item := range items {
		if m := obj(item); m != nil && isStr(m["fingerprint"]) {
			result[str(m["fingerprint"])] = m
		}
	}
	return result, nil
}

func browserInventory(state string) (M, error) {
	return lockedValue(false, func() (M, error) {
		records, err := browserRegistry(state)
		if err != nil {
			return nil, err
		}
		live, err := trustedCertificates()
		if err != nil {
			return nil, err
		}
		result := []any{}
		for identity, raw := range obj(records["certificates"]) {
			record := obj(raw)
			item := browserPublic(record)
			if l, ok := live[identity]; ok {
				item["status"], item["restricted"], item["projects"] = "trusted", l["restricted"], l["projects"]
			} else if s := str(record["status"]); s != "revoked" && s != "expired" {
				item["status"] = "not-trusted"
			}
			result = append(result, item)
		}
		return M{"certificates": result}, nil
	})
}

func browserPrivateRuntime() error {
	fd, err := stagedDirectory(filepath.Dir(browserRuntime))
	if err != nil {
		return err
	}
	syscall.Close(fd)
	if err := os.Mkdir(browserRuntime, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	fd, err = stagedDirectory(browserRuntime)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&0o077 != 0 {
		return Public("Browser certificate runtime storage must be private")
	}
	return nil
}

var issueDir = re(`issue-[a-z0-9_]{8,}`)

func browserCleanupPrivate() error {
	if !exists(browserRuntime) {
		return nil
	}
	fd, err := stagedDirectory(browserRuntime)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&0o077 != 0 {
		return Public("Browser certificate runtime storage must be private")
	}
	names, _ := listFD(fd)
	for _, name := range names {
		if !fullmatch(issueDir, name) {
			continue
		}
		p := filepath.Join(browserRuntime, name)
		if isSymlink(p) {
			return Public("Browser certificate runtime storage contains an alias")
		}
		info, err := os.Stat(p)
		if err == nil && time.Since(info.ModTime()).Seconds() >= browserPrivateLifetime {
			os.RemoveAll(p)
		}
	}
	return nil
}

func opensslRun(stdin []byte, args ...string) ([]byte, error) {
	return check(append([]string{"openssl"}, args...), stdin, 15*time.Second)
}

func browserIssue(state string, device, passphrase any, owner string, fullAdmin any, renew any) (M, error) {
	if err := requirePlausibleClock(); err != nil {
		return nil, err
	}
	dev, ok := device.(string)
	if !ok || !fullmatch(deviceName, dev) {
		return nil, Public("Use a device name of up to 32 letters, digits, hyphens or underscores")
	}
	pass, ok := passphrase.(string)
	if n := len([]rune(pass)); !ok || n < 16 || n > 256 || strings.ContainsAny(pass, "\r\n\x00") {
		return nil, Public("Use a bundle passphrase of 16–256 characters with no line breaks")
	}
	full, ok := fullAdmin.(bool)
	if !ok {
		return nil, Public("Select an explicit certificate scope")
	}
	if !fullmatch(portalUser, owner) {
		return nil, Public("Invalid browser identity owner")
	}
	return lockedValue(false, func() (M, error) {
		records, err := browserRegistry(state)
		if err != nil {
			return nil, err
		}
		certs := obj(records["certificates"])
		if renew != nil {
			id, err := certFingerprint(renew)
			if err != nil {
				return nil, err
			}
			old := obj(certs[id])
			if old == nil || str(old["device"]) != dev {
				return nil, Public("Renew only an owned identity for the selected device")
			}
		}
		fail := Public("Browser certificate issuance failed; refresh the identity list before retrying")
		name := "nixus-browser-" + dev + "-" + tokenHex(6)
		if browserPrivateRuntime() != nil || browserCleanupPrivate() != nil {
			return nil, fail
		}
		folder, err := os.MkdirTemp(browserRuntime, "issue-")
		if err != nil {
			return nil, fail
		}
		defer os.RemoveAll(folder)
		key, cert, p12 := filepath.Join(folder, "key"), filepath.Join(folder, "cert"), filepath.Join(folder, "client.p12")
		if _, err := opensslRun(nil, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:secp384r1",
			"-nodes", "-sha384", "-days", "90", "-subj", "/CN="+name,
			"-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature",
			"-addext", "extendedKeyUsage=clientAuth", "-keyout", key, "-out", cert); err != nil {
			return nil, fail
		}
		der, err := opensslRun(nil, "x509", "-in", cert, "-outform", "DER")
		if err != nil {
			return nil, fail
		}
		identity := sha256hex(der)
		end, err := opensslRun(nil, "x509", "-in", cert, "-noout", "-enddate")
		if err != nil {
			return nil, fail
		}
		_, expiration, _ := strings.Cut(strings.TrimSpace(string(end)), "=")
		if _, err := opensslRun([]byte(pass+"\n"), "pkcs12", "-export", "-in", cert, "-inkey", key, "-out", p12, "-passout", "stdin"); err != nil {
			return nil, fail
		}
		bundle, err := os.ReadFile(p12)
		if err != nil {
			return nil, fail
		}
		projects := []any{"lab"}
		if full {
			projects = []any{}
		}
		record := M{"name": name, "device": dev, "fingerprint": identity, "owner": owner, "issuedAt": now(),
			"expiresAt": expiration, "restricted": !full, "projects": projects, "status": "issuing"}
		if renew != nil {
			record["renews"] = renew
		}
		certs[identity] = record
		if writeJSON(filepath.Join(state, "browser-certificates.json"), records) != nil {
			return nil, fail
		}
		args := []string{"incus", "--force-local", "config", "trust", "add-certificate", cert, "--name", name}
		if !full {
			args = append(args, "--projects", "lab", "--restricted")
		}
		if _, err := command(args, 60*time.Second); err != nil {
			return nil, fail
		}
		record["status"] = "active"
		if writeJSON(filepath.Join(state, "browser-certificates.json"), records) != nil {
			return nil, fail
		}
		audit("browser-certificate-issued", M{"fingerprint": identity, "principal": owner, "restricted": !full})
		out := browserPublic(record)
		out["validDays"] = browserValidDays
		out["pkcs12"] = base64.StdEncoding.EncodeToString(bundle)
		return out, nil
	})
}

func browserRevoke(state string, identity any, owner string) (M, error) {
	id, err := certFingerprint(identity)
	if err != nil {
		return nil, err
	}
	return lockedValue(false, func() (M, error) {
		records, err := browserRegistry(state)
		if err != nil {
			return nil, err
		}
		record := obj(obj(records["certificates"])[id])
		if record == nil {
			return nil, Public("Only Nixus-owned browser identities can be revoked here")
		}
		live, err := trustedCertificates()
		if err != nil {
			return nil, err
		}
		if _, ok := live[id]; ok {
			if _, err := command([]string{"incus", "--force-local", "config", "trust", "remove", id}, 60*time.Second); err != nil {
				return nil, err
			}
		}
		record["status"] = "revoked"
		if err := writeJSON(filepath.Join(state, "browser-certificates.json"), records); err != nil {
			return nil, err
		}
		audit("browser-certificate-revoked", M{"fingerprint": id, "principal": owner})
		return M{"ok": true, "fingerprint": id}, nil
	})
}

// browserExpireOwned runs under the guard's mutation lock.
func browserExpireOwned(state string) error {
	records, err := browserRegistry(state)
	if err != nil {
		return err
	}
	var expired []string
	for identity, raw := range obj(records["certificates"]) {
		record := obj(raw)
		status := str(record["status"])
		t, err := certTime(str(record["expiresAt"]))
		if err != nil {
			return Public("Browser identity expiration metadata is invalid; inspect owned trust before retrying")
		}
		if status != "expired" && status != "revoked" && !time.Now().Before(t) {
			expired = append(expired, identity)
		}
	}
	if len(expired) == 0 {
		return nil
	}
	if err := requirePlausibleClock(); err != nil {
		return err
	}
	live, err := trustedCertificates()
	if err != nil {
		return err
	}
	for _, identity := range expired {
		if _, ok := live[identity]; ok {
			if _, err := command([]string{"incus", "--force-local", "config", "trust", "remove", identity}, 60*time.Second); err != nil {
				return err
			}
		}
		obj(obj(records["certificates"])[identity])["status"] = "expired"
		if err := writeJSON(filepath.Join(state, "browser-certificates.json"), records); err != nil {
			return err
		}
		audit("browser-certificate-expired", M{"fingerprint": identity})
	}
	return nil
}
