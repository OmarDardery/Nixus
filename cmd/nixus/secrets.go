package main

// Write-only SOPS/age project secrets plus the passphrase-encrypted,
// self-verifying off-host recovery kit. Values never leave the broker.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/scrypt"
)

var (
	secretName       = re(`[a-z][a-z0-9-]{0,62}`)
	projectRecipient = re(`age1[023456789acdefghjklmnpqrstuvwxyz]{50,70}`)
	agePrivateKey    = re(`AGE-SECRET-KEY-1[023456789ACDEFGHJKLMNPQRSTUVWXYZ]{50,70}`)
	reviewToken      = re(`[0-9a-f]{32}`)
	projectsIdentity = "/var/lib/nixus/keys/projects.agekey"
)

const (
	maxSecret    = 8192
	maxPlaintext = 65536
	maxEncrypted = 1024 * 1024
	reviewTTL    = 600
)

func safeDir(p string, private, create bool) error {
	if create {
		os.Mkdir(p, 0o700)
	}
	info, err := os.Lstat(p)
	mask := os.FileMode(0o022)
	if private {
		mask = 0o077
	}
	if err != nil || !info.IsDir() || int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() || info.Mode().Perm()&mask != 0 {
		return Public("Unsafe secrets directory")
	}
	return nil
}

// safeRegular rejects aliasing, symlinks, foreign owners and oversized input.
func safeRegular(p string, max int64, private bool) ([]byte, error) {
	info, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	st := info.Sys().(*syscall.Stat_t)
	mask := os.FileMode(0o022)
	if private {
		mask = 0o077
	}
	if !info.Mode().IsRegular() || int(st.Uid) != os.Geteuid() || st.Nlink != 1 || info.Size() > max || info.Mode().Perm()&mask != 0 {
		return nil, Public("Unsafe secrets file")
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cur, _ := f.Stat()
	if !os.SameFile(cur, info) {
		return nil, Public("Secret file changed during validation")
	}
	data := make([]byte, max+1)
	n, _ := readFull(f, data)
	if int64(n) != info.Size() || int64(n) > max {
		return nil, Public("Secret file changed during read")
	}
	return data[:n], nil
}

func readFull(f *os.File, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := f.Read(buf[total:])
		total += n
		if err != nil || n == 0 {
			return total, nil
		}
	}
	return total, nil
}

// sopsRun never puts values or private keys into argv, environment or logs.
func secretRun(argv []string, data []byte, keyPath string) ([]byte, error) {
	p := os.Getenv("PATH")
	if p == "" {
		p = "/run/current-system/sw/bin:/usr/bin:/bin"
	}
	env := []string{"PATH=" + p, "HOME=/var/empty", "LC_ALL=C"}
	if keyPath != "" {
		env = append(env, "SOPS_AGE_KEY_FILE="+keyPath)
	}
	res, err := run(argv, data, 25*time.Second, env, "")
	if err != nil {
		return nil, Public("SOPS or age operation unavailable")
	}
	if res.Code != 0 || len(res.Stdout) > 2*maxEncrypted {
		return nil, Public("SOPS or age operation rejected")
	}
	return res.Stdout, nil
}

func writeExclusive(p string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	f.Chmod(mode)
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

type Secrets struct{ state, projects, identity string }

func NewSecrets(state, projects, identity string) *Secrets {
	if state == "" {
		state = STATE
	}
	if projects == "" {
		projects = projectsWorkspace
	}
	if identity == "" {
		identity = projectsIdentity
	}
	return &Secrets{filepath.Join(state, "project-secrets"), projects, identity}
}

func (s *Secrets) privateState() (string, error) {
	if err := safeDir(filepath.Dir(s.state), false, false); err != nil {
		return "", err
	}
	return s.state, safeDir(s.state, true, true)
}

func (s *Secrets) recipient() (string, error) {
	if err := safeDir(filepath.Dir(s.identity), true, false); err != nil {
		return "", err
	}
	if _, err := safeRegular(s.identity, 4096, true); err != nil {
		return "", err
	}
	raw, err := secretRun([]string{"age-keygen", "-y", s.identity}, nil, "")
	if err != nil {
		return "", err
	}
	r := strings.TrimSpace(string(raw))
	if !fullmatch(projectRecipient, r) {
		return "", Public("Invalid age recipient")
	}
	return r, nil
}

func (s *Secrets) identityStatus() M {
	r, err := s.recipient()
	if err != nil {
		if !lexists(s.identity) {
			return M{"configured": false, "healthy": false, "recipient": nil}
		}
		return M{"configured": true, "healthy": false, "recipient": nil}
	}
	return M{"configured": true, "healthy": true, "recipient": r}
}

func singleAgeKey(text string) (string, bool) {
	var found []string
	for _, line := range strings.Split(text, "\n") {
		if l := strings.TrimSpace(line); strings.HasPrefix(l, "AGE-SECRET-KEY-") {
			found = append(found, l)
		}
	}
	if len(found) != 1 || !fullmatch(agePrivateKey, found[0]) {
		return "", false
	}
	return found[0], true
}

func (s *Secrets) enrollIdentity(actor, mode string, privateKey any, acknowledge bool) (M, error) {
	if !acknowledge || (mode != "generate" && mode != "restore") {
		return nil, Public("Explicit generate-or-restore approval required")
	}
	parent := filepath.Dir(s.identity)
	if lexists(parent) {
		if err := safeDir(parent, true, false); err != nil {
			return nil, err
		}
	} else {
		if err := safeDir(filepath.Dir(parent), false, false); err != nil {
			return nil, err
		}
		if err := safeDir(parent, true, true); err != nil {
			return nil, err
		}
	}
	if lexists(s.identity) {
		return nil, Public("Existing age identity cannot be overwritten")
	}
	var key string
	if mode == "generate" {
		if privateKey != nil {
			return nil, Public("Unexpected identity import data")
		}
		out, err := secretRun([]string{"age-keygen"}, nil, "")
		if err != nil {
			return nil, err
		}
		var ok bool
		if key, ok = singleAgeKey(string(out)); !ok {
			return nil, Public("age-keygen returned an invalid identity")
		}
	} else {
		text, ok := privateKey.(string)
		if !ok || len(text) > 4096 {
			return nil, Public("Invalid recovery identity")
		}
		if key, ok = singleAgeKey(text); !ok {
			return nil, Public("Invalid recovery identity")
		}
	}
	raw := []byte(key + "\n")
	out, err := secretRun([]string{"age-keygen", "-y"}, raw, "")
	if err != nil {
		return nil, err
	}
	derived := strings.TrimSpace(string(out))
	if !fullmatch(projectRecipient, derived) {
		return nil, Public("Age recipient verification failed")
	}
	if err := writeExclusive(s.identity, raw, 0o400); err != nil {
		return nil, Public("Could not persist recovery identity")
	}
	fsyncDir(parent)
	audit("native-age-identity-enrolled", M{"principal": actor, "method": mode})
	return M{"configured": true, "healthy": true, "recipient": derived, "recoveryRequired": true,
		"message": "Save the recovery identity offline by an independently protected method"}, nil
}

func (s *Secrets) project(name any) (string, error) {
	n, ok := name.(string)
	if !ok || !fullmatch(secretName, n) {
		return "", Public("Invalid project name")
	}
	if err := safeDir(s.projects, false, false); err != nil {
		return "", err
	}
	p := filepath.Join(s.projects, n)
	if err := safeDir(p, false, false); err != nil {
		return "", err
	}
	if _, err := safeRegular(filepath.Join(p, "default.nix"), 1024*1024, false); err != nil {
		return "", Public("Invalid project entrypoint")
	}
	return p, nil
}

func (s *Secrets) metadata(project string) (M, error) {
	empty := M{"project": project, "keys": []any{}, "revision": nil}
	root := filepath.Join(s.state, "projects")
	target := filepath.Join(root, project)
	index := filepath.Join(target, "index.json")
	for _, p := range []string{root, target} {
		if !lexists(p) {
			return empty, nil
		}
		if err := safeDir(p, true, false); err != nil {
			return nil, err
		}
	}
	if !lexists(index) {
		return empty, nil
	}
	raw, err := safeRegular(index, 65536, true)
	if err != nil {
		return nil, err
	}
	record, err := parseObject(raw)
	keysList, ok := record["keys"].([]any)
	if err != nil || str(record["project"]) != project || !ok {
		return nil, Public("Invalid secret metadata index")
	}
	for _, k := range keysList {
		if !fullmatch(secretKey, str(k)) {
			return nil, Public("Invalid secret metadata index")
		}
	}
	return record, nil
}

// cipher returns nil when no ciphertext exists.
func (s *Secrets) cipher(projectPath string) ([]byte, error) {
	p := filepath.Join(projectPath, "secrets.enc.yaml")
	if !lexists(p) {
		return nil, nil
	}
	return safeRegular(p, maxEncrypted, false)
}

func hashOrNil(data []byte) any {
	if data == nil {
		return nil
	}
	return sha256hex(data)
}

func checkRecipients(value any, host string) ([]string, error) {
	fail := Public("Age policy must retain the host and use 1–16 unique recipients")
	items, ok := anyStrings(value)
	if !ok || len(items) < 1 || len(items) > 16 {
		return nil, fail
	}
	seen, hasHost := map[string]bool{}, false
	for _, r := range items {
		if !fullmatch(projectRecipient, r) || seen[r] {
			return nil, fail
		}
		seen[r] = true
		hasHost = hasHost || r == host
	}
	if !hasHost {
		return nil, fail
	}
	sort.Strings(items)
	return items, nil
}

func sopsPolicy(recipients []string) []byte {
	sorted := append([]string(nil), recipients...)
	sort.Strings(sorted)
	return []byte("creation_rules:\n  - path_regex: secrets\\.enc\\.yaml$\n    age: " + strings.Join(sorted, ",") + "\n")
}

func (s *Secrets) checkPolicy(projectPath, recipient string) ([]string, error) {
	p := filepath.Join(projectPath, ".sops.yaml")
	if !lexists(p) {
		return []string{recipient}, nil
	}
	raw, err := safeRegular(p, 8192, false)
	if err != nil {
		return nil, err
	}
	prefix := "creation_rules:\n  - path_regex: secrets\\.enc\\.yaml$\n    age: "
	text := string(raw)
	if !strings.HasPrefix(text, prefix) || !strings.HasSuffix(text, "\n") {
		return nil, Public("Unrecognized SOPS recipient policy")
	}
	valid, err := checkRecipients(strings2any(strings.Split(text[len(prefix):len(text)-1], ",")), recipient)
	if err != nil {
		return nil, err
	}
	if string(sopsPolicy(valid)) != text {
		return nil, Public("Recipient policy conflicts with managed project secrets")
	}
	return valid, nil
}

func (s *Secrets) decode(ciphertext []byte, keyPath string) (M, error) {
	if ciphertext == nil {
		return M{}, nil
	}
	if keyPath == "" {
		keyPath = s.identity
	}
	raw, err := secretRun([]string{"sops", "decrypt", "--input-type", "yaml", "--output-type", "json", "/dev/stdin"}, ciphertext, keyPath)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxPlaintext {
		return nil, Public("Decrypted secrets exceed size limit")
	}
	doc, err := parseObject(raw)
	if err != nil {
		return nil, Public("Invalid decrypted secrets structure")
	}
	if len(doc) > 128 {
		return nil, Public("Invalid decrypted secrets schema")
	}
	for k, v := range doc {
		text, ok := v.(string)
		if !fullmatch(secretKey, k) || !ok || len(text) > maxSecret {
			return nil, Public("Invalid decrypted secrets schema")
		}
	}
	return doc, nil
}

func (s *Secrets) encode(values M, recipients string) ([]byte, error) {
	data := []byte(canonicalASCII(values))
	if len(data) > maxPlaintext {
		return nil, Public("Secrets exceed plaintext limit")
	}
	out, err := secretRun([]string{"sops", "encrypt", "--age", recipients, "--filename-override", "secrets.enc.yaml",
		"--input-type", "json", "--output-type", "yaml", "/dev/stdin"}, data, "")
	if err != nil {
		return nil, err
	}
	if len(out) > maxEncrypted || !strings.Contains(string(out), "sops:") {
		return nil, Public("SOPS encryption did not produce expected ciphertext")
	}
	return out, nil
}

// canonicalASCII mirrors json.dumps(sort_keys=True, ensure_ascii=True).
func canonicalASCII(v any) string {
	text := canonicalSpaced(v)
	var b strings.Builder
	for _, r := range text {
		if r < 128 {
			b.WriteRune(r)
			continue
		}
		var units []rune
		if r > 0xFFFF {
			r -= 0x10000
			units = []rune{0xD800 + (r >> 10), 0xDC00 + (r & 0x3FF)}
		} else {
			units = []rune{r}
		}
		for _, u := range units {
			b.WriteString("\\u")
			const hexdigits = "0123456789abcdef"
			b.WriteByte(hexdigits[u>>12&0xF])
			b.WriteByte(hexdigits[u>>8&0xF])
			b.WriteByte(hexdigits[u>>4&0xF])
			b.WriteByte(hexdigits[u&0xF])
		}
	}
	return b.String()
}

func (s *Secrets) inventory() (M, error) {
	status := s.identityStatus()
	if !isDir(s.projects) {
		return M{"identity": status, "projects": []any{}}, nil
	}
	if err := safeDir(s.projects, false, false); err != nil {
		return nil, err
	}
	entries, _ := os.ReadDir(s.projects)
	listed := []any{}
	for _, e := range entries {
		if !e.IsDir() || !fullmatch(secretName, e.Name()) || !isFile(filepath.Join(s.projects, e.Name(), "default.nix")) {
			continue
		}
		project, err := s.project(e.Name())
		if err != nil {
			return nil, err
		}
		record, err := s.metadata(e.Name())
		if err != nil {
			return nil, err
		}
		actual, err := s.cipher(project)
		if err != nil {
			return nil, err
		}
		digest := hashOrNil(actual)
		recipients := []any{}
		if isTrue(status["healthy"]) {
			r, err := s.checkPolicy(project, str(status["recipient"]))
			if err != nil {
				return nil, err
			}
			recipients = strings2any(r)
		}
		listed = append(listed, M{"project": e.Name(), "keys": record["keys"], "revision": digest,
			"indexed": equalJSON(digest, record["revision"]), "secretCount": len(list(record["keys"])), "recipients": recipients})
		if len(listed) > 128 {
			return nil, Public("Too many secret projects")
		}
	}
	return M{"identity": status, "projects": listed,
		"note": "Only secret names and ciphertext hashes are returned; values are never readable"}, nil
}

func validSecretText(v any) bool {
	t, ok := v.(string)
	return ok && utf8.ValidString(t) && len(t) <= maxSecret && !strings.Contains(t, "\x00")
}

func (s *Secrets) review(actor string, projectArg, keyArg any, action string, value, expected any) (M, error) {
	root, err := s.privateState()
	if err != nil {
		return nil, err
	}
	public, err := s.recipient()
	if err != nil {
		return nil, err
	}
	projectDir, err := s.project(projectArg)
	if err != nil {
		return nil, err
	}
	project := projectArg.(string)
	current, err := s.checkPolicy(projectDir, public)
	if err != nil {
		return nil, err
	}
	if action != "set" && action != "delete" && action != "import" && action != "replace" && action != "recipients" {
		return nil, Public("Unsupported secret mutation")
	}
	key, _ := keyArg.(string)
	newRecipients := current
	switch action {
	case "recipients":
		if keyArg != nil {
			return nil, Public("Recipient changes cannot select a secret key")
		}
		if newRecipients, err = checkRecipients(value, public); err != nil {
			return nil, err
		}
		if reflect.DeepEqual(newRecipients, current) {
			return nil, Public("Recipient policy is already current")
		}
	case "replace":
		m, ok := value.(M)
		if keyArg != nil || !ok || len(m) < 1 || len(m) > 128 {
			return nil, Public("Keep 1–128 variables")
		}
		total := 0
		for name, text := range m {
			if !fullmatch(secretKey, name) || !validSecretText(text) {
				return nil, Public("Variable names use letters, digits and _; values are text up to 8 KiB")
			}
			total += len(text.(string))
		}
		if total > maxPlaintext {
			return nil, Public("Variables exceed 64 KiB in total")
		}
	case "import":
		m, ok := value.(M)
		if keyArg != nil || !ok || len(m) < 1 || len(m) > 64 {
			return nil, Public("Import requires 1–64 named secrets")
		}
		total := 0
		for name, text := range m {
			if !fullmatch(secretKey, name) || !validSecretText(text) {
				return nil, Public("Invalid imported environment names or values")
			}
			total += len(text.(string))
		}
		if total > maxPlaintext {
			return nil, Public("Invalid imported environment names or values")
		}
	default:
		if !fullmatch(secretKey, key) {
			return nil, Public("Invalid secret variable name")
		}
		if action == "set" {
			if !validSecretText(value) || value.(string) == "" {
				return nil, Public("Secret value must be 1–8192 safe UTF-8 bytes")
			}
		} else if value != nil {
			return nil, Public("Deletion must not include a secret value")
		}
	}
	existing, err := s.cipher(projectDir)
	if err != nil {
		return nil, err
	}
	base := hashOrNil(existing)
	if !equalJSON(expected, base) {
		return nil, Public("Secrets source changed; refresh and review again")
	}
	index, err := s.metadata(project)
	if err != nil {
		return nil, err
	}
	if !equalJSON(index["revision"], base) {
		return nil, Public("Secret metadata/source revision drift; recover before editing")
	}
	if action == "recipients" && existing == nil {
		return nil, Public("Create a project secret before changing recipients")
	}
	values, err := s.decode(existing, "")
	if err != nil {
		return nil, err
	}
	var changed []string
	switch action {
	case "delete":
		if _, ok := values[key]; !ok {
			return nil, Public("Secret key no longer exists")
		}
		delete(values, key)
		changed = []string{key}
	case "import":
		for k, v := range value.(M) {
			values[k] = v
		}
		changed = keys(value.(M))
	case "replace":
		before := values
		values = M{}
		for k, v := range value.(M) {
			values[k] = v
		}
		changed = []string{}
		for _, k := range keys(values) {
			if !equalJSON(before[k], values[k]) {
				changed = append(changed, k)
			}
		}
		for _, k := range keys(before) {
			if _, ok := values[k]; !ok {
				changed = append(changed, k)
			}
		}
	case "set":
		values[key] = value
		changed = []string{key}
	default:
		changed = []string{}
	}
	if len(values) > 128 {
		return nil, Public("Too many project secrets")
	}
	ciphertext, err := s.encode(values, strings.Join(newRecipients, ","))
	if err != nil {
		return nil, err
	}
	check, err := s.decode(ciphertext, "")
	if err != nil || !equalJSON(check, values) {
		return nil, Public("SOPS ciphertext verification failed")
	}
	token := tokenHex(16)
	drafts := filepath.Join(root, "reviews")
	if err := safeDir(drafts, true, true); err != nil {
		return nil, err
	}
	target := filepath.Join(drafts, token)
	if err := os.Mkdir(target, 0o700); err != nil {
		return nil, err
	}
	atomic(filepath.Join(target, "ciphertext.yaml"), ciphertext, 0o400, "")
	revision := sha256hex(ciphertext)
	var keyField any
	if keyArg != nil {
		keyField = key
	}
	writeJSON(filepath.Join(target, "review.json"), M{"id": token, "actor": actor, "project": project, "key": keyField,
		"action": action, "base": base, "revision": revision, "recipient": public, "recipients": strings2any(newRecipients),
		"beforeRecipients": strings2any(current), "keys": strings2any(keys(values)), "changedKeys": strings2any(changed),
		"created": now(), "expires": now() + reviewTTL})
	fsyncDir(target)
	fsyncDir(drafts)
	audit("native-secret-change-reviewed", M{"principal": actor, "project": project, "key": keyField, "operation": action, "revision": revision})
	return M{"reviewId": token, "project": project, "key": keyField, "action": action, "changedKeys": strings2any(changed),
		"baseRevision": base, "revision": revision, "keys": strings2any(keys(values)), "recipients": strings2any(newRecipients),
		"requiresApply": true, "note": "Ciphertext review only; no secret delivery or guest restart"}, nil
}

func (s *Secrets) loadReview(actor string, tokenArg any) (M, []byte, error) {
	token, _ := tokenArg.(string)
	if !fullmatch(reviewToken, token) {
		return nil, nil, Public("Invalid secret review")
	}
	path := filepath.Join(s.state, "reviews", token)
	for _, p := range []string{s.state, filepath.Dir(path), path} {
		if err := safeDir(p, true, false); err != nil {
			return nil, nil, err
		}
	}
	raw, err := safeRegular(filepath.Join(path, "review.json"), 65536, true)
	if err != nil {
		return nil, nil, err
	}
	record, err := parseObject(raw)
	if err != nil || str(record["actor"]) != actor || str(record["id"]) != token {
		return nil, nil, Public("Secret review owner mismatch")
	}
	if exp, _ := num(record["expires"]); now() >= exp {
		return nil, nil, Public("Secret review expired")
	}
	ciphertext, err := safeRegular(filepath.Join(path, "ciphertext.yaml"), maxEncrypted, true)
	if err != nil {
		return nil, nil, err
	}
	if sha256hex(ciphertext) != str(record["revision"]) {
		return nil, nil, Public("Secret review ciphertext changed")
	}
	return record, ciphertext, nil
}

func recipientsOr(v any, fallback string) any {
	if v == nil {
		return []any{fallback}
	}
	return v
}

func (s *Secrets) publish(actor string, token any, acknowledge bool) (M, error) {
	if !acknowledge {
		return nil, Public("Explicit secret publication acknowledgement required")
	}
	record, ciphertext, err := s.loadReview(actor, token)
	if err != nil {
		return nil, err
	}
	public, err := s.recipient()
	if err != nil {
		return nil, err
	}
	if public != str(record["recipient"]) {
		return nil, Public("Age identity changed after review")
	}
	project := str(record["project"])
	projectDir, err := s.project(project)
	if err != nil {
		return nil, err
	}
	current, err := s.checkPolicy(projectDir, public)
	if err != nil {
		return nil, err
	}
	if !equalJSON(strings2any(current), recipientsOr(record["beforeRecipients"], public)) {
		return nil, Public("Recipient policy changed after review")
	}
	next, err := checkRecipients(recipientsOr(record["recipients"], public), public)
	if err != nil {
		return nil, err
	}
	source, err := s.cipher(projectDir)
	if err != nil {
		return nil, err
	}
	base := hashOrNil(source)
	meta, err := s.metadata(project)
	if err != nil {
		return nil, err
	}
	if !equalJSON(base, record["base"]) || !equalJSON(meta["revision"], base) {
		return nil, Public("Secret ciphertext revision changed; review again")
	}
	if _, err := s.decode(ciphertext, ""); err != nil {
		return nil, err
	}
	projectState := filepath.Join(s.state, "projects")
	store := filepath.Join(projectState, project)
	revisions := filepath.Join(store, "revisions")
	for _, p := range []string{projectState, store, revisions} {
		if err := safeDir(p, true, true); err != nil {
			return nil, err
		}
	}
	if source != nil {
		saved := filepath.Join(revisions, base.(string))
		if lexists(saved) {
			old, err := safeRegular(saved, maxEncrypted, true)
			if err != nil || string(old) != string(source) {
				return nil, Public("Previous encrypted revision does not match")
			}
		} else if err := atomic(saved, source, 0o400, ""); err != nil {
			return nil, err
		}
	}
	pending := filepath.Join(store, "pending.json")
	if lexists(pending) {
		return nil, Public("Unrecovered secret publication; restore before retrying")
	}
	writeJSON(pending, M{"project": project, "before": base, "after": record["revision"], "reviewId": token,
		"beforeRecipients": strings2any(current), "afterRecipients": strings2any(next)})
	if err := atomic(filepath.Join(projectDir, ".sops.yaml"), sopsPolicy(next), 0o644, ""); err != nil {
		return nil, err
	}
	if err := atomic(filepath.Join(projectDir, "secrets.enc.yaml"), ciphertext, 0o600, ""); err != nil {
		return nil, err
	}
	if err := writeJSON(filepath.Join(store, "index.json"), M{"project": project, "keys": record["keys"],
		"recipients": strings2any(next), "revision": record["revision"], "previous": base,
		"changedKey": record["key"], "updated": now()}); err != nil {
		return nil, err
	}
	durableUnlink(pending)
	audit("native-secret-ciphertext-published", M{"principal": actor, "project": project, "key": record["key"],
		"operation": record["action"], "revision": record["revision"]})
	notifyAppsRepo()
	return M{"project": project, "revision": record["revision"], "previous": base, "published": true,
		"requiresApply": true, "note": "Ciphertext published; no Incus secret delivery occurred"}, nil
}

// recover rewinds an interrupted ciphertext publication; guests are untouched.
func (s *Secrets) recover(actor string, projectArg any) (M, error) {
	projectDir, err := s.project(projectArg)
	if err != nil {
		return nil, err
	}
	project := projectArg.(string)
	store := filepath.Join(s.state, "projects", project)
	for _, p := range []string{s.state, filepath.Dir(store), store} {
		if err := safeDir(p, true, false); err != nil {
			return nil, err
		}
	}
	pending := filepath.Join(store, "pending.json")
	if !lexists(pending) {
		return M{"recovered": false}, nil
	}
	raw, err := safeRegular(pending, 65536, true)
	if err != nil {
		return nil, err
	}
	record, err := parseObject(raw)
	if err != nil || str(record["project"]) != project {
		return nil, Public("Secret recovery record does not match project")
	}
	current, err := s.cipher(projectDir)
	if err != nil {
		return nil, err
	}
	currentHash := hashOrNil(current)
	if !equalJSON(currentHash, record["before"]) && !equalJSON(currentHash, record["after"]) {
		return nil, Public("Secret ciphertext changed since interrupted publication")
	}
	base := record["before"]
	recipient, err := s.recipient()
	if err != nil {
		return nil, err
	}
	previous, err := checkRecipients(recipientsOr(record["beforeRecipients"], recipient), recipient)
	if err != nil {
		return nil, err
	}
	next, err := checkRecipients(recipientsOr(record["afterRecipients"], recipient), recipient)
	if err != nil {
		return nil, err
	}
	now_, err := s.checkPolicy(projectDir, recipient)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(now_, previous) && !reflect.DeepEqual(now_, next) {
		return nil, Public("Recipient policy changed during secret recovery")
	}
	readPrevious := func() ([]byte, error) {
		data, err := safeRegular(filepath.Join(store, "revisions", str(base)), maxEncrypted, true)
		if err != nil || sha256hex(data) != str(base) {
			return nil, Public("Previous encrypted revision has changed")
		}
		return data, nil
	}
	if equalJSON(currentHash, record["after"]) {
		target := filepath.Join(projectDir, "secrets.enc.yaml")
		if base == nil {
			durableUnlink(target)
		} else {
			data, err := readPrevious()
			if err != nil {
				return nil, err
			}
			atomic(target, data, 0o600, "")
		}
	}
	atomic(filepath.Join(projectDir, ".sops.yaml"), sopsPolicy(previous), 0o644, "")
	index, err := s.metadata(project)
	if err != nil {
		return nil, err
	}
	if equalJSON(index["revision"], record["after"]) {
		restoredKeys := []any{}
		if base != nil {
			data, err := readPrevious()
			if err != nil {
				return nil, err
			}
			values, err := s.decode(data, "")
			if err != nil {
				return nil, err
			}
			restoredKeys = strings2any(keys(values))
		}
		writeJSON(filepath.Join(store, "index.json"), M{"project": project, "revision": base, "keys": restoredKeys,
			"recipients": strings2any(previous), "recovered": now()})
	}
	durableUnlink(pending)
	audit("native-secret-publication-recovered", M{"principal": actor, "project": project})
	return M{"recovered": true, "revision": base,
		"note": "Ciphertext reference restored; independently verify any deployed workload"}, nil
}

// reindex adopts authenticated ciphertext restored from source control.
func (s *Secrets) reindex(actor string, projectArg any, acknowledge bool) (M, error) {
	if !acknowledge {
		return nil, Public("Explicit ciphertext recovery approval required")
	}
	root, err := s.privateState()
	if err != nil {
		return nil, err
	}
	recipient, err := s.recipient()
	if err != nil {
		return nil, err
	}
	directory, err := s.project(projectArg)
	if err != nil {
		return nil, err
	}
	project := projectArg.(string)
	recipients, err := s.checkPolicy(directory, recipient)
	if err != nil {
		return nil, err
	}
	ciphertext, err := s.cipher(directory)
	if err != nil {
		return nil, err
	}
	if ciphertext == nil {
		return nil, Public("No encrypted project secrets to adopt")
	}
	metadata, err := s.metadata(project)
	if err != nil {
		return nil, err
	}
	digest := sha256hex(ciphertext)
	store := filepath.Join(root, "projects", project)
	for _, p := range []string{filepath.Dir(store), store} {
		if err := safeDir(p, true, true); err != nil {
			return nil, err
		}
	}
	if lexists(filepath.Join(store, "pending.json")) {
		return nil, Public("Interrupted publication must be recovered before reindexing")
	}
	values, err := s.decode(ciphertext, "")
	if err != nil {
		return nil, err
	}
	names := strings2any(keys(values))
	if str(metadata["revision"]) == digest && equalJSON(metadata["keys"], names) {
		return M{"indexed": true, "noChange": true, "project": project, "revision": digest, "keys": names}, nil
	}
	writeJSON(filepath.Join(store, "index.json"), M{"project": project, "revision": digest, "keys": names,
		"recipients": strings2any(recipients), "recoveredAt": now()})
	audit("native-secrets-ciphertext-reindexed", M{"principal": actor, "project": project, "revision": digest, "count": len(names)})
	return M{"indexed": true, "noChange": false, "project": project, "revision": digest, "keys": names,
		"note": "Ciphertext authenticated and indexed; no workloads changed"}, nil
}

// --- recovery kit ---------------------------------------------------------------

var kitMagic = []byte("NIXUS-SECRETS-RECOVERY-V1")

const maxKit = 256 * 1024

var kitFiles = map[string]string{
	"host-age-identity": "/var/lib/sops-nix/key.txt",
	"project-restic":    "/var/lib/nixus-secrets/project-restic-password",
	"remote-access":     "/var/lib/nixus-secrets/cloudflared.json",
}

// retiredKitFiles may appear in older kits; they are read but not restored.
var retiredKitFiles = map[string]bool{"restic-password": true, "restic-environment": true}

func b64(data []byte) string { return base64.StdEncoding.EncodeToString(data) }

func unb64(v any) ([]byte, error) {
	s, ok := v.(string)
	if !ok || len(s) > maxKit*2 || strings.ContainsAny(s, "\r\n") {
		return nil, Public("Invalid recovery payload")
	}
	return base64.StdEncoding.Strict().DecodeString(s)
}

func kitAEAD(passphrase any, salt []byte) (cipher.AEAD, error) {
	p, ok := passphrase.(string)
	if !ok || utf8.RuneCountInString(p) < 16 || utf8.RuneCountInString(p) > 256 || len(p) > 1024 {
		return nil, Public("Recovery passphrase must be 16–256 characters")
	}
	key, err := scrypt.Key([]byte(p), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(key)
	return cipher.NewGCM(block)
}

func kitManifest(recipient string, credentials map[string][]byte) M {
	entries := M{}
	for k, v := range credentials {
		entries[k] = M{"sha256": sha256hex(v), "bytes": len(v)}
	}
	return M{"recipient": recipient, "credentials": entries}
}

func kitDecode(serial []byte, passphrase any) (M, map[string][]byte, error) {
	if _, ok := passphrase.(string); !ok {
		return nil, nil, Public("Recovery passphrase must be 16–256 characters")
	}
	invalid := Public("Recovery kit or passphrase is invalid")
	envelope, err := parseObject(serial)
	if err != nil || !exactKeys(envelope, "format", "version", "salt", "nonce", "ciphertext") ||
		str(envelope["format"]) != "nixus-recovery-kit" || !equalJSON(envelope["version"], 1) {
		return nil, nil, invalid
	}
	salt, e1 := unb64(envelope["salt"])
	nonce, e2 := unb64(envelope["nonce"])
	sealed, e3 := unb64(envelope["ciphertext"])
	if e1 != nil || e2 != nil || e3 != nil || len(salt) != 16 || len(nonce) != 12 || len(sealed) > maxKit {
		return nil, nil, invalid
	}
	aead, err := kitAEAD(passphrase, salt)
	if err != nil {
		return nil, nil, err
	}
	plain, err := aead.Open(nil, nonce, sealed, kitMagic)
	if err != nil {
		return nil, nil, invalid
	}
	record, err := parseObject(plain)
	if err != nil || !exactKeys(record, "version", "recipient", "identity", "credentials", "manifest") ||
		!equalJSON(record["version"], 1) || !fullmatch(projectRecipient, str(record["recipient"])) ||
		!fullmatch(agePrivateKey, strings.TrimSpace(str(record["identity"]))) {
		return nil, nil, invalid
	}
	creds := obj(record["credentials"])
	if creds == nil {
		return nil, nil, invalid
	}
	credentials := map[string][]byte{}
	for k, v := range creds {
		if _, ok := kitFiles[k]; !ok && !retiredKitFiles[k] {
			return nil, nil, invalid
		}
		data, err := unb64(v)
		if err != nil || len(data) > 32768 {
			return nil, nil, invalid
		}
		credentials[k] = data
	}
	if !equalJSON(record["manifest"], kitManifest(str(record["recipient"]), credentials)) {
		return nil, nil, invalid
	}
	return record, credentials, nil
}

type RecoveryKit struct {
	manager *Secrets
	files   map[string]string
	staging string
}

func NewRecoveryKit(manager *Secrets) *RecoveryKit { return &RecoveryKit{manager, kitFiles, "/run"} }

// proveUnlock verifies a real SOPS round trip with the kit identity on tmpfs.
func (k *RecoveryKit) proveUnlock(record M) error {
	if err := safeDir(k.staging, false, false); err != nil {
		return err
	}
	work, err := os.MkdirTemp(k.staging, ".nixus-recovery-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	private := filepath.Join(work, "identity")
	if err := writeExclusive(private, []byte(strings.TrimSpace(str(record["identity"]))+"\n"), 0o400); err != nil {
		return err
	}
	probe := []byte(`{"RECOVERY_PROBE":"offline-unlock-check"}`)
	encrypted, err := secretRun([]string{"sops", "encrypt", "--age", str(record["recipient"]), "--filename-override", "secrets.enc.yaml",
		"--input-type", "json", "--output-type", "yaml", "/dev/stdin"}, probe, "")
	if err != nil {
		return err
	}
	out, err := secretRun([]string{"sops", "decrypt", "--input-type", "yaml", "--output-type", "json", "/dev/stdin"}, encrypted, private)
	if err != nil {
		return err
	}
	got, err := parseJSON(out)
	want, _ := parseJSON(probe)
	if err != nil || !equalJSON(got, want) {
		return Public("Recovery kit could not unlock verified SOPS ciphertext")
	}
	if isDir(k.manager.projects) {
		if err := safeDir(k.manager.projects, false, false); err != nil {
			return err
		}
		entries, _ := os.ReadDir(k.manager.projects)
		for _, e := range entries {
			if !fullmatch(secretName, e.Name()) || !isFile(filepath.Join(k.manager.projects, e.Name(), "default.nix")) {
				continue
			}
			project, err := k.manager.project(e.Name())
			if err != nil {
				return err
			}
			ciphertext, err := k.manager.cipher(project)
			if err != nil {
				return err
			}
			if ciphertext != nil {
				if _, err := k.manager.decode(ciphertext, private); err != nil {
					return Public("Recovery source ciphertext cannot be validated")
				}
			}
		}
	}
	return nil
}

func (k *RecoveryKit) export(actor string, passphrase any, includeBackup bool) (M, error) {
	recipient, err := k.manager.recipient()
	if err != nil {
		return nil, err
	}
	raw, err := safeRegular(k.manager.identity, 4096, true)
	if err != nil {
		return nil, err
	}
	private := strings.TrimSpace(string(raw))
	if !fullmatch(agePrivateKey, private) {
		return nil, Public("Private age identity is invalid")
	}
	saved := map[string][]byte{}
	for label, p := range k.files {
		if (includeBackup || label == "host-age-identity") && lexists(p) {
			if err := safeDir(filepath.Dir(p), true, false); err != nil {
				return nil, err
			}
			data, err := safeRegular(p, 32768, true)
			if err != nil {
				return nil, err
			}
			saved[label] = data
		}
	}
	credentials := M{}
	for k, v := range saved {
		credentials[k] = b64(v)
	}
	payload := canonical(M{"version": 1, "recipient": recipient, "identity": private, "credentials": credentials,
		"manifest": kitManifest(recipient, saved)})
	salt, nonce := make([]byte, 16), make([]byte, 12)
	rand.Read(salt)
	rand.Read(nonce)
	aead, err := kitAEAD(passphrase, salt)
	if err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nonce, []byte(payload), kitMagic)
	serial := []byte(canonical(M{"format": "nixus-recovery-kit", "version": 1, "salt": b64(salt), "nonce": b64(nonce), "ciphertext": b64(sealed)}))
	if len(serial) > maxKit {
		return nil, Public("Recovery kit exceeded size limit")
	}
	verified, _, err := kitDecode(serial, passphrase)
	if err != nil || str(verified["recipient"]) != recipient {
		return nil, Public("Recovery kit self-test failed")
	}
	names := strings2any(sortedKeys(boolSet(saved)))
	audit("native-recovery-kit-exported", M{"principal": actor, "backupCredentials": names, "encrypted": true})
	return M{"format": "nixus-recovery-kit-v1", "encrypted": b64(serial), "sha256": sha256hex(serial), "verified": false,
		"requiresOfflineUnlockVerification": true, "recipient": recipient, "credentialNames": names,
		"note": "Store offline, separate from encrypted project sources; never share the passphrase"}, nil
}

func boolSet[V any](m map[string]V) map[string]bool {
	out := map[string]bool{}
	for k := range m {
		out[k] = true
	}
	return out
}

func (k *RecoveryKit) verifiedRecord(encrypted, passphrase any) (M, map[string][]byte, error) {
	serial, err := unb64(encrypted)
	if err != nil || len(serial) > maxKit {
		return nil, nil, Public("Invalid recovery kit")
	}
	record, credentials, err := kitDecode(serial, passphrase)
	if err != nil {
		return nil, nil, err
	}
	out, err := secretRun([]string{"age-keygen", "-y"}, []byte(str(record["identity"])+"\n"), "")
	if err != nil || strings.TrimSpace(string(out)) != str(record["recipient"]) {
		return nil, nil, Public("Recovery identity did not match its recipient")
	}
	if err := k.proveUnlock(record); err != nil {
		return nil, nil, err
	}
	return record, credentials, nil
}

func (k *RecoveryKit) inspect(actor string, encrypted, passphrase any) (M, error) {
	record, credentials, err := k.verifiedRecord(encrypted, passphrase)
	if err != nil {
		return nil, err
	}
	audit("native-recovery-kit-verified", M{"principal": actor})
	if isFile(k.manager.identity) {
		if r, err := k.manager.recipient(); err == nil && r == str(record["recipient"]) {
			recordRecoveryKit(k.manager.identity)
		}
	}
	return M{"valid": true, "verified": true, "recipient": record["recipient"],
		"credentialNames": strings2any(sortedKeys(boolSet(credentials))),
		"note":            "Recovery kit verified in memory; no host files modified"}, nil
}

func (k *RecoveryKit) restore(actor string, encrypted, passphrase any, acknowledge bool) (M, error) {
	if !acknowledge {
		return nil, Public("Explicit offline recovery approval required")
	}
	record, credentials, err := k.verifiedRecord(encrypted, passphrase)
	if err != nil {
		return nil, err
	}
	for label := range credentials {
		if k.files[label] == "" {
			delete(credentials, label)
		}
	}
	for label := range credentials {
		target := k.files[label]
		if lexists(target) {
			return nil, Public("Recovery target already exists; no credential may be replaced")
		}
		if err := safeDir(filepath.Dir(target), true, true); err != nil {
			return nil, err
		}
	}
	if lexists(k.manager.identity) {
		return nil, Public("An existing age identity may not be replaced")
	}
	if _, err := k.manager.enrollIdentity(actor, "restore", record["identity"], true); err != nil {
		return nil, err
	}
	names := sortedKeys(boolSet(credentials))
	for _, label := range names {
		target := k.files[label]
		if err := writeExclusive(target, credentials[label], 0o600); err != nil {
			return nil, Public("Recovery credential could not be written")
		}
		fsyncDir(filepath.Dir(target))
	}
	audit("native-recovery-kit-restored", M{"principal": actor, "backupCredentials": strings2any(names)})
	return M{"restored": true, "recipient": record["recipient"], "credentialNames": strings2any(names),
		"note": "Age identity and selected unlock material restored; project data remains separate"}, nil
}
