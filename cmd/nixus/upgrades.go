package main

// Immutable platform-code updates; machine state is preserved independently.

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const upstream = "https://github.com/OmarDardery/Nixus.git"

var protectedTop = map[string]bool{"machine": true, "local": true, "installed-system": true, "site-modules": true, "secrets": true, ".git": true}
var sha40 = re(`[0-9a-f]{40}`)
var semver = re(`v?[0-9]+\.[0-9]+\.[0-9]+(?:[-.][A-Za-z0-9.-]+)?`)

func mainRevision() (string, error) {
	out, err := check([]string{"git", "-c", "core.hooksPath=/dev/null", "ls-remote", "--refs", upstream, "refs/heads/main"}, nil, 30*time.Second)
	if err != nil {
		return "", Public("Could not resolve Nixus main to one exact revision")
	}
	fields := strings.Fields(string(out))
	if len(fields) != 2 || !fullmatch(sha40, fields[0]) || fields[1] != "refs/heads/main" {
		return "", Public("Could not resolve Nixus main to one exact revision")
	}
	return fields[0], nil
}

func platformVersion(root string) string {
	raw, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err == nil {
		v := strings.TrimSpace(string(raw))
		if fullmatch(re(`[0-9]+\.[0-9]+\.[0-9]+(?:[-.][A-Za-z0-9.-]+)?`), v) {
			return v
		}
	}
	return "unknown"
}

func platformPath(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || name == "hardware-configuration.nix" || name == ".nixus-files.json" {
		return false
	}
	parts := strings.Split(strings.Trim(name, "/"), "/")
	for _, p := range parts {
		if p == ".." {
			return false
		}
	}
	return !protectedTop[parts[0]]
}

func upgradeMetadata(root string) M {
	explicit := readObj(filepath.Join(root, "platform-release.json"))
	var record M
	if fullmatch(sha40, str(explicit["revision"])) {
		record = explicit
	} else {
		revision := "unversioned"
		if out, err := check([]string{"git", "-C", root, "rev-parse", "HEAD"}, nil, 10*time.Second); err == nil {
			revision = strings.TrimSpace(string(out))
		}
		record = M{"version": platformVersion(root), "revision": revision, "repository": upstream}
	}
	helpers := readObj(filepath.Join(root, "helpers/sources.json"))
	if len(helpers) == 0 {
		helpers = readObj(filepath.Join(SOURCE, "helper-sources.json"))
	}
	record["helperSources"] = helpers
	return record
}

func upgradePrepare(source, revision string, log *os.File) ([]any, error) {
	if !fullmatch(sha40, revision) {
		return nil, Public("Platform updates require a reviewed full 40-character Git commit SHA")
	}
	files, err := sourceFiles(source)
	if err != nil {
		return nil, err
	}
	before := map[string][]byte{}
	for _, f := range files {
		if platformPath(f.name) {
			before[f.name], _ = os.ReadFile(f.path)
		}
	}
	folder, err := os.MkdirTemp(filepath.Dir(source), "upstream-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(folder)
	git := func(args ...string) ([]byte, error) {
		res, err := run(append([]string{"git", "-c", "core.hooksPath=/dev/null", "-C", folder}, args...), nil, 300*time.Second, nil, "")
		if log != nil {
			log.Write(res.Stderr)
		}
		if err != nil || res.Code != 0 {
			return nil, Public("Platform source fetch failed")
		}
		return res.Stdout, nil
	}
	if _, err := git("init", "-q"); err != nil {
		return nil, err
	}
	if _, err := git("fetch", "--depth=1", "--no-tags", upstream, revision); err != nil {
		return nil, err
	}
	head, err := git("rev-parse", "FETCH_HEAD")
	if err != nil || strings.TrimSpace(string(head)) != revision {
		return nil, Public("Fetched revision did not match the reviewed SHA")
	}
	archive, err := git("archive", "--format=tar", "FETCH_HEAD")
	if err != nil {
		return nil, err
	}
	if len(archive) > 100<<20 {
		return nil, Public("Platform archive exceeds the 100 MiB review limit")
	}
	type incomingFile struct {
		data []byte
		mode os.FileMode
	}
	incoming := map[string]incomingFile{}
	tr := tar.NewReader(bytes.NewReader(archive))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, Public("Platform source must contain bounded regular files only")
		}
		if h.Typeflag == tar.TypeDir || h.Typeflag == tar.TypeXGlobalHeader || !platformPath(h.Name) {
			continue
		}
		if h.Typeflag != tar.TypeReg || h.Size > 16<<20 || len(incoming) >= 10000 {
			return nil, Public("Platform source must contain bounded regular files only")
		}
		data, _ := io.ReadAll(tr)
		mode := os.FileMode(0o644)
		if h.Mode&0o111 != 0 {
			mode = 0o755
		}
		incoming[h.Name] = incomingFile{data, mode}
	}
	_, hasFlake := incoming["flake.nix"]
	_, hasLock := incoming["flake.lock"]
	_, hasGo := incoming["go.mod"]
	if !hasFlake || !hasLock || !hasGo {
		return nil, Public("Selected revision does not contain a Nixus platform")
	}
	for name := range before {
		if _, ok := incoming[name]; !ok {
			os.Remove(filepath.Join(source, name))
		}
	}
	for name, f := range incoming {
		if err := atomic(filepath.Join(source, name), f.data, f.mode, ""); err != nil {
			return nil, err
		}
	}
	if err := writeJSON(filepath.Join(source, "platform-release.json"), M{"version": platformVersion(source), "revision": revision, "repository": upstream}); err != nil {
		return nil, err
	}
	release, _ := os.ReadFile(filepath.Join(source, "platform-release.json"))
	incoming["platform-release.json"] = incomingFile{release, 0o644}
	files, err = sourceFiles(source)
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, f := range files {
		if !platformPath(f.name) {
			names[f.name] = true
		}
	}
	for n := range incoming {
		names[n] = true
	}
	delete(names, ".nixus-files.json")
	if err := writeJSON(filepath.Join(source, ".nixus-files.json"), strings2any(sortedKeys(names))); err != nil {
		return nil, err
	}
	all := map[string]bool{}
	for n := range before {
		all[n] = true
	}
	for n := range incoming {
		all[n] = true
	}
	changes := []any{}
	for _, name := range sortedKeys(all) {
		old, hadOld := before[name]
		newFile, hasNew := incoming[name]
		if hadOld && hasNew && bytes.Equal(old, newFile.data) {
			continue
		}
		var b, a any
		if hadOld {
			b = sha256hex(old)
		}
		if hasNew {
			a = sha256hex(newFile.data)
		}
		changes = append(changes, M{"path": name, "before": b, "after": a})
	}
	return changes, nil
}

// upgradePublish publishes reviewed platform files, keeping machine state.
func upgradePublish(source, root string) error {
	desiredFiles, err := sourceFiles(source)
	if err != nil {
		return err
	}
	rootFiles, err := sourceFiles(root)
	if err != nil {
		return err
	}
	desired, current, local := map[string]string{}, map[string]bool{}, map[string]bool{}
	for _, f := range desiredFiles {
		if platformPath(f.name) {
			desired[f.name] = f.path
		}
	}
	for _, f := range rootFiles {
		if platformPath(f.name) {
			current[f.name] = true
		} else {
			local[f.name] = true
		}
	}
	for name := range desired {
		for p := filepath.Join(root, name); p != root && p != "/"; p = filepath.Dir(p) {
			if isSymlink(p) {
				return Public("Platform destination cannot traverse symlinks")
			}
		}
	}
	union := map[string]bool{}
	for _, set := range []map[string]bool{local, current} {
		for k := range set {
			union[k] = true
		}
	}
	for k := range desired {
		union[k] = true
	}
	delete(union, ".nixus-files.json")
	if err := writeJSON(filepath.Join(root, ".nixus-files.json"), strings2any(sortedKeys(union))); err != nil {
		return err
	}
	names := make([]string, 0, len(desired))
	for n := range desired {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		data, err := os.ReadFile(desired[name])
		if err != nil {
			return err
		}
		info, _ := os.Stat(desired[name])
		if err := atomic(filepath.Join(root, name), data, info.Mode().Perm(), ""); err != nil {
			return err
		}
	}
	for name := range current {
		if _, ok := desired[name]; !ok {
			durableUnlink(filepath.Join(root, name))
		}
	}
	final := map[string]bool{}
	for k := range local {
		final[k] = true
	}
	for k := range desired {
		final[k] = true
	}
	delete(final, ".nixus-files.json")
	return writeJSON(filepath.Join(root, ".nixus-files.json"), strings2any(sortedKeys(final)))
}
