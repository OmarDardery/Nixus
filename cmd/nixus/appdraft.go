package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// App drafts: a half-filled New app form kept on the server so it can be
// finished from another device. Files and the Nix text are stored as typed;
// environment variables are sealed to the secrets key like a pending deploy.

const (
	maxDraftEntries = 16
	maxDraftEntry   = 256 * 1024
	maxDraftTotal   = 1024 * 1024
)

func draftDir() string { return filepath.Join(STATE, "app-drafts") }

func draftPath(name string) string { return filepath.Join(draftDir(), name+".json") }

func draftEnvPath(name string) string { return filepath.Join(draftDir(), name+".env.age") }

func draftName(raw any) (string, error) {
	name, _ := raw.(string)
	if !fullmatch(projectName, name) {
		return "", Public("Use a lowercase name: letters, digits and dashes")
	}
	return name, nil
}

// cleanDraft validates the form state and returns only the fields a draft keeps.
func cleanDraft(body M) (M, error) {
	mode := str(body["mode"])
	if mode != "files" && mode != "nix" {
		return nil, Public("Choose files or a Nix declaration")
	}
	total := 0
	entries := []any{}
	for _, raw := range list(body["entries"]) {
		e := obj(raw)
		path, text := str(e["path"]), str(e["text"])
		if len(path) > 200 || len(text) > maxDraftEntry || strings.Contains(text, "\x00") {
			return nil, Public("A draft file is too large")
		}
		if total += len(path) + len(text); total > maxDraftTotal {
			return nil, Public("The draft is larger than 1 MiB")
		}
		entries = append(entries, M{"path": path, "text": text})
	}
	if len(entries) > maxDraftEntries {
		return nil, Public("A draft holds up to 16 files")
	}
	nix := str(body["nix"])
	if len(nix) > 65536 || strings.Contains(nix, "\x00") {
		return nil, Public("The Nix declaration is too large")
	}
	instance := M{}
	for k, v := range obj(body["instance"]) {
		if s, ok := v.(string); ok && len(s) <= 200 {
			instance[k] = s
		} else if n, ok := v.(float64); ok {
			instance[k] = n
		}
	}
	if len(instance) > 16 {
		return nil, Public("Too many instance settings")
	}
	return M{"mode": mode, "entries": entries, "nix": nix, "instance": instance}, nil
}

func saveDraft(actor string, body M) (M, error) {
	name, err := draftName(body["name"])
	if err != nil {
		return nil, err
	}
	draft, err := cleanDraft(body)
	if err != nil {
		return nil, err
	}
	vars, err := deployEnv(body["env"])
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(draftDir(), 0o700); err != nil {
		return nil, err
	}
	envSaved := false
	if vars != nil {
		if err := sealVars(draftEnvPath(name), vars); err != nil {
			// Keep the rest of the draft; tell the user why the variables were left out.
			os.Remove(draftEnvPath(name))
		} else {
			envSaved = true
		}
	} else {
		os.Remove(draftEnvPath(name))
	}
	draft["name"], draft["updatedAt"], draft["envCount"] = name, now(), len(vars)
	if !envSaved {
		draft["envCount"] = 0
	}
	if err := writeJSONMode(draftPath(name), draft, 0o600, ""); err != nil {
		return nil, err
	}
	out := M{"saved": true, "envSaved": envSaved}
	if vars != nil && !envSaved {
		out["note"] = "Saved without the environment variables. Create the encryption key first (Backups → Encryption key) to keep them in drafts."
	}
	audit("app-draft-saved", M{"principal": actor, "project": name})
	return out, nil
}

func listDrafts() M {
	matches, _ := filepath.Glob(filepath.Join(draftDir(), "*.json"))
	drafts := []any{}
	for _, p := range matches {
		d := readObj(p)
		if name := str(d["name"]); fullmatch(projectName, name) && filepath.Base(p) == name+".json" {
			drafts = append(drafts, M{"name": name, "updatedAt": d["updatedAt"], "mode": d["mode"], "envCount": d["envCount"]})
		}
	}
	sort.Slice(drafts, func(i, j int) bool { return str(obj(drafts[i])["name"]) < str(obj(drafts[j])["name"]) })
	return M{"drafts": drafts}
}

func readDraft(raw any) (M, error) {
	name, err := draftName(raw)
	if err != nil {
		return nil, err
	}
	if !isFile(draftPath(name)) {
		return nil, Public("No draft with that name")
	}
	draft := readObj(draftPath(name))
	if isFile(draftEnvPath(name)) {
		vars, err := openVars(draftEnvPath(name))
		if err != nil {
			draft["envError"] = "The saved variables could not be decrypted with this server's key."
		} else {
			draft["env"] = vars
		}
	}
	return draft, nil
}

func deleteDraft(raw any) (M, error) {
	name, err := draftName(raw)
	if err != nil {
		return nil, err
	}
	os.Remove(draftPath(name))
	os.Remove(draftEnvPath(name))
	return M{"deleted": true}, nil
}
