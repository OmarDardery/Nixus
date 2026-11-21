package main

// Browser-bound first-administrator bootstrap, root-approved account recovery
// and owned Incus browser client certificates.

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

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
