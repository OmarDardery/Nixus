package main

// Host credentials as SOPS/age ciphertext inside the reviewed machine source.
// Plaintext only moves through pipes, never files, return values or logs.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const hostKeyFile = "/var/lib/sops-nix/key.txt"
const hostSecretsRelative = "machine/secrets/host.yaml"
const hostSecretsPlaceholder = "nixus-host-secrets"
const hostSecretsUnset = "cockpit-operator-password-unset"

var hostSecretNames = map[string]string{"cockpitPassword": "cockpit-operator-password", "wifiPassword": "wifi-env",
	"tunnelCredentials": "cloudflared"}

var ageRecipient = re(`age1[02-9ac-hj-np-z]{58}`)
var topKey = re(`([A-Za-z0-9][A-Za-z0-9_-]{0,63}):.*`)

func sopsRun(args []string, data []byte, keyFile string) ([]byte, error) {
	env := os.Environ()
	if keyFile != "" {
		env = append(env, "SOPS_AGE_KEY_FILE="+keyFile)
	}
	res, err := run(args, data, 60*time.Second, env, "")
	if err != nil || res.Code != 0 {
		return nil, Public("SOPS or age operation failed")
	}
	return res.Stdout, nil
}

func hostSecretsPath(root string) string { return filepath.Join(root, hostSecretsRelative) }

// ensureIdentity creates the host age identity once and never overwrites it.
func ensureIdentity(keyFile string) (string, error) {
	if isSymlink(keyFile) {
		return "", Public("Host age identity must be a regular file")
	}
	if !exists(keyFile) {
		dir := filepath.Dir(keyFile)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		os.Chmod(dir, 0o700)
		temporary, err := os.MkdirTemp(dir, "tmp")
		if err != nil {
			return "", err
		}
		defer os.RemoveAll(temporary)
		candidate := filepath.Join(temporary, "key.txt")
		if _, err := sopsRun([]string{"age-keygen", "-o", candidate}, nil, ""); err != nil {
			return "", err
		}
		os.Chmod(candidate, 0o600)
		if err := os.Link(candidate, keyFile); err != nil && !errors.Is(err, os.ErrExist) {
			return "", err
		}
	}
	return ageRecipientOf(keyFile)
}

func ageRecipientOf(keyFile string) (string, error) {
	out, err := sopsRun([]string{"age-keygen", "-y", keyFile}, nil, "")
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(out))
	if !fullmatch(ageRecipient, value) {
		return "", Public("Invalid host age identity")
	}
	return value, nil
}

// sopsNames lists top-level secret names without decrypting.
func sopsNames(file string) map[string]bool {
	out := map[string]bool{}
	raw, err := os.ReadFile(file)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if m := topKey.FindStringSubmatch(line); m != nil && m[1] != "sops" {
			out[m[1]] = true
		}
	}
	return out
}

func hostSecretPresent(root, field string) bool {
	return sopsNames(hostSecretsPath(root))[hostSecretNames[field]]
}

func hostDecrypt(file, keyFile string) (M, error) {
	out, err := sopsRun([]string{"sops", "decrypt", "--output-type", "json", file}, nil, keyFile)
	if err != nil {
		return nil, err
	}
	return parseObject(out)
}

func hostEncrypt(values M, target, keyFile string) error {
	data, _ := json.Marshal(values)
	recipient, err := ageRecipientOf(keyFile)
	if err != nil {
		return err
	}
	out, err := sopsRun([]string{"sops", "encrypt", "--input-type", "json", "--output-type", "yaml",
		"--age", recipient, "--filename-override", "host.yaml", "/dev/stdin"}, data, "")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	return atomic(target, out, 0o644, "")
}

// lockedPasswordHash is a SHA-512 crypt of a discarded random password.
func lockedPasswordHash() (string, error) {
	out, err := sopsRun([]string{"openssl", "passwd", "-6", "-stdin"}, []byte(tokenURLSafe(32)+"\n"), "")
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(out))
	if !strings.HasPrefix(value, "$6$") {
		return "", Public("Could not create a locked operator password")
	}
	return value + "\n", nil
}

func hostSecretsInitialize(root, keyFile string) (string, error) {
	target := hostSecretsPath(root)
	if !isFile(target) {
		hash, err := lockedPasswordHash()
		if err != nil {
			return "", err
		}
		if err := hostEncrypt(M{hostSecretsPlaceholder: "initialized", hostSecretNames["cockpitPassword"]: hash,
			hostSecretsUnset: "true"}, target, keyFile); err != nil {
			return "", err
		}
	}
	return target, nil
}

func operatorPasswordSet(root string) bool {
	found := sopsNames(hostSecretsPath(root))
	return found[hostSecretNames["cockpitPassword"]] && !found[hostSecretsUnset]
}

// hostSecretsWrite merges encoded values into the staged source ciphertext.
func hostSecretsWrite(root string, values M, keyFile string) ([]string, error) {
	for field, value := range values {
		if _, ok := hostSecretNames[field]; !ok {
			return nil, Public("Unknown host secret field")
		}
		if !isStr(value) {
			return nil, Public("Invalid host secret value")
		}
	}
	target := hostSecretsPath(root)
	current := M{hostSecretsPlaceholder: "initialized"}
	if isFile(target) {
		var err error
		if current, err = hostDecrypt(target, keyFile); err != nil {
			return nil, err
		}
	}
	delete(current, "sops")
	for field, value := range values {
		current[hostSecretNames[field]] = value
	}
	if _, ok := values["cockpitPassword"]; ok {
		delete(current, hostSecretsUnset)
	}
	if err := hostEncrypt(current, target, keyFile); err != nil {
		return nil, err
	}
	out := keys(values)
	sort.Strings(out)
	return out, nil
}
