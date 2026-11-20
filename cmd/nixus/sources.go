package main

// Private, byte-exact project source staging and immutable publication, strict
// data-only ZIP/TAR extraction, and fail-closed credential guards. Nothing here
// evaluates, builds or deploys source.

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

var projectName = re(`[a-z][a-z0-9-]{0,62}`)
var sourcePart = re(`(?:[A-Za-z0-9][A-Za-z0-9_.-]*|\.[A-Za-z0-9][A-Za-z0-9._-]*)`)

const (
	importMaxFiles   = 256
	importMaxFile    = 64 * 1024 * 1024
	importMaxTotal   = 128 * 1024 * 1024
	importMaxArchive = 64 * 1024 * 1024
	importMaxChunk   = 96 * 1024
	importExpiry     = 3600
)

func checkPath(v any) (string, error) {
	value, ok := v.(string)
	if !ok || value == "" || len(value) > 255 || strings.Contains(value, `\`) || strings.HasPrefix(value, "/") {
		return "", Public("Invalid relative source path")
	}
	parts := strings.Split(value, "/")
	if len(parts) > 12 {
		return "", Public("Unsupported relative source path")
	}
	for _, p := range parts {
		if !fullmatch(sourcePart, p) || p == "." || p == ".." {
			return "", Public("Unsupported relative source path")
		}
		lower := strings.ToLower(p)
		switch lower {
		case ".git", ".ssh", ".gnupg", ".nixus", "node_modules", ".env", "id_rsa", "id_ed25519", "id_ecdsa", "projects.agekey":
			return "", Public("Potential plaintext credentials or unsafe metadata in source")
		}
		if (strings.HasPrefix(lower, ".env.") && lower != ".env.example" && lower != ".env.sample" && lower != ".env.template") ||
			strings.HasSuffix(lower, ".agekey") || strings.HasSuffix(lower, ".p12") || strings.HasSuffix(lower, ".pfx") || strings.HasSuffix(lower, ".key") ||
			(strings.HasPrefix(lower, "secrets.") && !fullmatch(re(`secrets\.enc\.(ya?ml|json)`), lower)) {
			return "", Public("Potential plaintext credentials or unsafe metadata in source")
		}
	}
	return value, nil
}

type sourceEntry struct {
	Path   string
	Size   int64
	SHA256 string
}

func (e sourceEntry) M() M { return M{"path": e.Path, "size": e.Size, "sha256": e.SHA256} }

func entriesAny(entries []sourceEntry) []any {
	out := make([]any, len(entries))
	for i, e := range entries {
		out[i] = e.M()
	}
	return out
}

func checkFiles(v any) ([]sourceEntry, error) {
	files, ok := v.([]any)
	if !ok || len(files) < 1 || len(files) > importMaxFiles {
		return nil, Public("Select 1–256 source files")
	}
	seen := map[string]bool{}
	var total int64
	var result []sourceEntry
	for _, raw := range files {
		item := obj(raw)
		if item == nil || len(item) != 3 || item["path"] == nil || item["size"] == nil || item["sha256"] == nil {
			return nil, Public("Unsupported source manifest")
		}
		name, err := checkPath(item["path"])
		if err != nil {
			return nil, err
		}
		if seen[name] {
			return nil, Public("Duplicate import path")
		}
		size, ok := intValue(item["size"])
		if !ok || size < 0 || size > importMaxFile {
			return nil, Public("Source file exceeds 64 MiB")
		}
		digest := str(item["sha256"])
		if !fullmatch(hex64, digest) {
			return nil, Public("Invalid source SHA-256")
		}
		seen[name] = true
		total += int64(size)
		result = append(result, sourceEntry{name, int64(size), digest})
	}
	if total > importMaxTotal {
		return nil, Public("Source selection exceeds 128 MiB")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, nil
}

func manifestSHA(entries []sourceEntry) string { return digestJSON(entriesAny(entries)) }

func ownedPrivateDir(p string, private bool) error {
	info, err := os.Lstat(p)
	if err != nil {
		return Public("Project source directory ownership or permissions are unsafe")
	}
	mask := os.FileMode(0o022)
	if private {
		mask = 0o077
	}
	st := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || int(st.Uid) != os.Geteuid() || info.Mode().Perm()&mask != 0 {
		return Public("Project source directory ownership or permissions are unsafe")
	}
	return nil
}

// --- staging ---------------------------------------------------------------

type ImportStaging struct{ root string }

func NewImportStaging(state string) (*ImportStaging, error) {
	if state == "" {
		state = STATE
	}
	root := filepath.Join(state, "project-imports")
	os.MkdirAll(root, 0o700)
	if err := ownedPrivateDir(root, true); err != nil {
		return nil, Public("Private import root must be broker-owned and mode 0700")
	}
	return &ImportStaging{root}, nil
}

func (s *ImportStaging) record(identity any, actor string) (string, M, error) {
	id, ok := identity.(string)
	if !ok || !fullmatch(jobID, id) {
		return "", nil, Public("Invalid import identity")
	}
	directory := filepath.Join(s.root, id)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
		return "", nil, Public("Untrusted import directory")
	}
	record := readObj(filepath.Join(directory, "manifest.json"))
	if str(record["id"]) != id || str(record["actor"]) != actor {
		return "", nil, Public("Import owner does not match authenticated actor")
	}
	expires, _ := num(record["expires"])
	if str(record["status"]) != "ready" && now() >= expires {
		return "", nil, Public("Import expired; submit a new review")
	}
	return directory, record, nil
}

func (s *ImportStaging) prepare(actor string, project, files, archive any) (M, error) {
	if !fullmatch(portalUser, actor) {
		return nil, Public("Invalid import actor")
	}
	p, ok := project.(string)
	if !ok || !fullmatch(projectName, p) {
		return nil, Public("Invalid project name")
	}
	entries, err := checkFiles(files)
	if err != nil {
		return nil, err
	}
	isArchive, ok := archive.(bool)
	if archive == nil {
		isArchive, ok = false, true
	}
	if !ok {
		return nil, Public("Invalid archive import selection")
	}
	if isArchive && (len(entries) != 1 || !isArchiveName(entries[0].Path) || entries[0].Size > importMaxArchive) {
		return nil, Public("Choose one bounded ZIP/TAR archive for extraction")
	}
	id := tokenHex(16)
	target := filepath.Join(s.root, id)
	if err := os.Mkdir(target, 0o700); err != nil {
		return nil, err
	}
	source := filepath.Join(target, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.Size != 0 {
			continue
		}
		f := filepath.Join(source, e.Path)
		os.MkdirAll(filepath.Dir(f), 0o700)
		fd, err := os.OpenFile(f, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		fd.Close()
	}
	record := M{"id": id, "format": 1, "status": "uploading", "actor": actor, "project": p, "files": entriesAny(entries),
		"manifestHash": manifestSHA(entries), "archive": isArchive, "created": now(), "expires": now() + importExpiry}
	if err := writeJSON(filepath.Join(target, "manifest.json"), record); err != nil {
		return nil, err
	}
	audit("native-source-import-created", M{"identity": id, "principal": actor, "count": len(entries)})
	return M{"id": id, "manifestHash": record["manifestHash"], "status": "uploading", "expires": record["expires"]}, nil
}

func (s *ImportStaging) chunk(identity any, actor string, pathArg, offset, encoded any) (M, error) {
	directory, record, err := s.record(identity, actor)
	if err != nil {
		return nil, err
	}
	if str(record["status"]) != "uploading" {
		return nil, Public("Source import already sealed")
	}
	name, err := checkPath(pathArg)
	if err != nil {
		return nil, err
	}
	entries, err := checkFiles(record["files"])
	if err != nil {
		return nil, err
	}
	var entry *sourceEntry
	for i := range entries {
		if entries[i].Path == name {
			entry = &entries[i]
		}
	}
	off, ok := intValue(offset)
	if entry == nil || !ok || off < 0 || int64(off) > entry.Size {
		return nil, Public("File not in immutable manifest or invalid offset")
	}
	text, ok := encoded.(string)
	if !ok || len(text) > 4*((importMaxChunk+2)/3) {
		return nil, Public("Upload chunk too large")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil {
		return nil, Public("Invalid source chunk")
	}
	if len(data) == 0 || len(data) > importMaxChunk || int64(off+len(data)) > entry.Size {
		return nil, Public("Upload chunk differs from manifest limits")
	}
	target := filepath.Join(directory, "source", name)
	os.MkdirAll(filepath.Dir(target), 0o700)
	fd, err := syscall.Open(target, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_APPEND|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), target)
	defer f.Close()
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Nlink != 1 || st.Size != int64(off) {
		return nil, Public("Unexpected import offset; restart review")
	}
	if _, err := f.Write(data); err != nil {
		return nil, Public("Incomplete source write")
	}
	f.Sync()
	return M{"id": identity, "path": name, "offset": off + len(data)}, nil
}

func hashOpenFile(f *os.File) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *ImportStaging) finish(identity any, actor string, manifestHash any) (M, error) {
	directory, record, err := s.record(identity, actor)
	if err != nil {
		return nil, err
	}
	if str(record["status"]) != "uploading" || str(manifestHash) != str(record["manifestHash"]) {
		return nil, Public("Import already sealed or manifest changed")
	}
	source := filepath.Join(directory, "source")
	entries, err := checkFiles(record["files"])
	if err != nil {
		return nil, err
	}
	expected := map[string]bool{}
	for _, e := range entries {
		expected[e.Path] = true
	}
	actual := map[string]bool{}
	filepath.WalkDir(source, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			rel, _ := filepath.Rel(source, p)
			actual[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if !equalJSON(mapToM(expected), mapToM(actual)) {
		return nil, Public("Import files are missing or unexpected")
	}
	for _, e := range entries {
		fd, err := syscall.Open(filepath.Join(source, e.Path), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, Public("Source file changed during upload")
		}
		f := os.NewFile(uintptr(fd), e.Path)
		var st syscall.Stat_t
		syscall.Fstat(fd, &st)
		if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Nlink != 1 || st.Size != e.Size {
			f.Close()
			return nil, Public("Source file changed during upload")
		}
		digest, err := hashOpenFile(f)
		if err != nil || digest != e.SHA256 {
			f.Close()
			return nil, Public("Source bytes do not match reviewed manifest")
		}
		syscall.Fchmod(fd, 0o400)
		f.Close()
	}
	retained := ""
	if isTrue(record["archive"]) {
		if len(entries) != 1 {
			return nil, Public("Archive import manifest changed")
		}
		scratch, err := os.MkdirTemp(directory, ".unpack-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(scratch)
		extracted, err := extractArchive(filepath.Join(source, entries[0].Path), scratch, importMaxFiles, importMaxFile, importMaxTotal)
		if err != nil {
			return nil, err
		}
		expanded, err := checkFiles(entriesAny(extracted))
		if err != nil {
			return nil, err
		}
		retained = filepath.Join(directory, "uploaded-archive")
		if lexists(retained) {
			return nil, Public("Unfinished archive extraction requires a fresh import")
		}
		if err := os.Rename(source, retained); err != nil {
			return nil, err
		}
		if err := os.Rename(scratch, source); err != nil {
			os.Rename(retained, source)
			return nil, err
		}
		fsyncDir(directory)
		record["archiveSha256"] = entries[0].SHA256
		record["archive"] = false
		record["expandedFromArchive"] = true
		record["files"] = entriesAny(expanded)
		record["manifestHash"] = manifestSHA(expanded)
		entries = expanded
	}
	record["status"] = "ready"
	record["sealedAt"] = now()
	if err := writeJSON(filepath.Join(directory, "manifest.json"), record); err != nil {
		return nil, err
	}
	if retained != "" {
		os.RemoveAll(retained)
	}
	audit("native-source-import-sealed", M{"identity": identity, "principal": actor, "project": record["project"], "sourceHash": record["manifestHash"]})
	return M{"id": identity, "project": record["project"], "status": "ready", "manifestHash": record["manifestHash"],
		"files": len(entries), "expandedFromArchive": isTrue(record["expandedFromArchive"]), "entries": entriesAny(entries),
		"note": "Private source staging only: no evaluation, build, publication or Incus deployment"}, nil
}

// verifiedSource rereads the sealed source; optionally copies verified bytes.
func verifiedSource(source string, files []sourceEntry, destination string) error {
	if err := ownedPrivateDir(source, true); err != nil {
		return err
	}
	if destination != "" {
		if err := ownedPrivateDir(destination, true); err != nil {
			return err
		}
	}
	for _, item := range files {
		relative, err := checkPath(item.Path)
		if err != nil {
			return err
		}
		parent := source
		parts := strings.Split(relative, "/")
		for _, c := range parts[:len(parts)-1] {
			parent = filepath.Join(parent, c)
			if err := ownedPrivateDir(parent, true); err != nil {
				return err
			}
		}
		fd, err := syscall.Open(filepath.Join(parent, parts[len(parts)-1]), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			return Public("Sealed source changed after review")
		}
		in := os.NewFile(uintptr(fd), relative)
		err = func() error {
			defer in.Close()
			var st syscall.Stat_t
			syscall.Fstat(fd, &st)
			if st.Mode&syscall.S_IFMT != syscall.S_IFREG || int(st.Uid) != os.Geteuid() || st.Nlink != 1 || st.Size != item.Size || st.Mode&0o277 != 0 {
				return Public("Sealed source changed after review")
			}
			var out *os.File
			if destination != "" {
				target := filepath.Join(destination, relative)
				os.MkdirAll(filepath.Dir(target), 0o700)
				ofd, err := syscall.Open(target, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
				if err != nil {
					return Public("Project source publication could not be completed")
				}
				out = os.NewFile(uintptr(ofd), target)
				defer out.Close()
			}
			h := sha256.New()
			var w io.Writer = h
			if out != nil {
				w = io.MultiWriter(h, out)
			}
			if _, err := io.Copy(w, in); err != nil {
				return Public("Project source publication could not be completed")
			}
			if hex.EncodeToString(h.Sum(nil)) != item.SHA256 {
				return Public("Sealed source checksum changed after review")
			}
			if out != nil {
				out.Sync()
				out.Chmod(0o400)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// --- publication -------------------------------------------------------------

type PublishedSources struct{ root string }

func NewPublishedSources(root string) *PublishedSources {
	if root == "" {
		root = envPath("NIXUS_PROJECT_SOURCES", "/srv/nixus/project-sources")
	}
	return &PublishedSources{root}
}

func (p *PublishedSources) current(project string) (M, error) {
	if !fullmatch(projectName, project) {
		return nil, Public("Invalid project name")
	}
	if !lexists(p.root) {
		return nil, nil
	}
	if err := ownedPrivateDir(p.root, true); err != nil {
		return nil, err
	}
	directory := filepath.Join(p.root, project)
	if !lexists(directory) {
		return nil, nil
	}
	if err := ownedPrivateDir(directory, true); err != nil {
		return nil, err
	}
	ref := filepath.Join(directory, "current.json")
	if !lexists(ref) {
		return nil, nil
	}
	info, err := os.Lstat(ref)
	if err != nil || !info.Mode().IsRegular() || int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() ||
		info.Sys().(*syscall.Stat_t).Nlink != 1 || info.Mode().Perm()&0o077 != 0 {
		return nil, Public("Published source reference is untrusted")
	}
	record := readObj(ref)
	if str(record["project"]) != project || !fullmatch(hex64, str(record["revision"])) {
		return nil, Public("Published source reference is invalid")
	}
	return record, nil
}

func (p *PublishedSources) attest(project, revision any) (M, error) {
	return p.attestOpts(project, revision, true)
}

func (p *PublishedSources) attestOpts(projectArg, revisionArg any, requireCurrent bool) (M, error) {
	project, ok1 := projectArg.(string)
	revision, ok2 := revisionArg.(string)
	if !ok1 || !ok2 || !fullmatch(projectName, project) || !fullmatch(hex64, revision) {
		return nil, Public("Invalid published source identity")
	}
	current, err := p.current(project)
	if err != nil {
		return nil, err
	}
	if current == nil || (requireCurrent && str(current["revision"]) != revision) {
		return nil, Public("Published source revision has changed; review again")
	}
	folder := filepath.Join(p.root, project, "revisions", revision)
	if err := ownedPrivateDir(folder, true); err != nil {
		return nil, err
	}
	manifestPath := filepath.Join(folder, "manifest.json")
	info, err := os.Lstat(manifestPath)
	if err != nil || !info.Mode().IsRegular() || int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() ||
		info.Sys().(*syscall.Stat_t).Nlink != 1 || info.Mode().Perm()&0o077 != 0 {
		return nil, Public("Published source manifest is untrusted")
	}
	manifest := readObj(manifestPath)
	files, err := checkFiles(manifest["files"])
	if err != nil {
		return nil, err
	}
	if v, _ := num(manifest["schemaVersion"]); v != 1 || str(manifest["project"]) != project ||
		str(manifest["sourceHash"]) != revision || manifestSHA(files) != revision {
		return nil, Public("Published source manifest differs from reviewed bytes")
	}
	if err := verifiedSource(filepath.Join(folder, "source"), files, ""); err != nil {
		return nil, err
	}
	if err := checkSource(filepath.Join(folder, "source"), files); err != nil {
		return nil, err
	}
	var total int64
	for _, f := range files {
		total += f.Size
	}
	return M{"revision": revision, "fileCount": len(files), "bytes": total}, nil
}

func (p *PublishedSources) inventory() (M, error) {
	if !lexists(p.root) {
		return M{"projects": []any{}}, nil
	}
	if err := ownedPrivateDir(p.root, true); err != nil {
		return nil, err
	}
	entries, _ := os.ReadDir(p.root)
	projects := []any{}
	for _, e := range entries {
		if !fullmatch(projectName, e.Name()) {
			return nil, Public("Invalid published source project directory")
		}
		if err := ownedPrivateDir(filepath.Join(p.root, e.Name()), true); err != nil {
			return nil, err
		}
		record, err := p.current(e.Name())
		if err != nil {
			return nil, err
		}
		if record != nil {
			projects = append(projects, M{"project": e.Name(), "revision": record["revision"], "publishedAt": record["publishedAt"]})
		}
		if len(projects) > 128 {
			return nil, Public("Too many published source projects")
		}
	}
	return M{"projects": projects}, nil
}

func (p *PublishedSources) review(s *ImportStaging, identity any, actor string, manifestHash any) (M, error) {
	directory, record, err := s.record(identity, actor)
	if err != nil {
		return nil, err
	}
	if str(record["status"]) != "ready" || str(record["manifestHash"]) != str(manifestHash) {
		return nil, Public("Only a sealed, matching source import may be reviewed")
	}
	files, err := checkFiles(record["files"])
	if err != nil {
		return nil, err
	}
	if manifestSHA(files) != str(manifestHash) {
		return nil, Public("Source manifest changed after staging")
	}
	source := filepath.Join(directory, "source")
	if err := verifiedSource(source, files, ""); err != nil {
		return nil, err
	}
	if err := checkSource(source, files); err != nil {
		return nil, err
	}
	if err := inspectSourceSecrets(source, files); err != nil {
		return nil, err
	}
	project := str(record["project"])
	current, err := p.current(project)
	if err != nil {
		return nil, err
	}
	var base any
	old := map[string]string{}
	if current != nil {
		base = current["revision"]
		revision := filepath.Join(p.root, project, "revisions", str(base))
		if err := ownedPrivateDir(revision, true); err != nil {
			return nil, err
		}
		previous := readObj(filepath.Join(revision, "manifest.json"))
		if str(previous["sourceHash"]) != str(base) {
			return nil, Public("Existing published source metadata is invalid")
		}
		prevFiles, err := checkFiles(previous["files"])
		if err != nil {
			return nil, err
		}
		for _, f := range prevFiles {
			old[f.Path] = f.SHA256
		}
	}
	added, removed, modified := []string{}, []string{}, []string{}
	newer := map[string]string{}
	for _, f := range files {
		newer[f.Path] = f.SHA256
		if prev, ok := old[f.Path]; !ok {
			added = append(added, f.Path)
		} else if prev != f.SHA256 {
			modified = append(modified, f.Path)
		}
	}
	for n := range old {
		if _, ok := newer[n]; !ok {
			removed = append(removed, n)
		}
	}
	sort.Strings(removed)
	token := tokenHex(16)
	if err := writeJSON(filepath.Join(directory, "publish-review.json"), M{"id": token, "actor": actor, "project": project,
		"manifestHash": manifestHash, "baseRevision": base, "expires": now() + 600}); err != nil {
		return nil, err
	}
	audit("native-source-publication-reviewed", M{"principal": actor, "identity": identity, "project": project, "sourceHash": manifestHash})
	var total int64
	for _, f := range files {
		total += f.Size
	}
	return M{"reviewId": token, "project": project, "revision": manifestHash, "baseRevision": base,
		"changes":   M{"added": strings2any(added), "removed": strings2any(removed), "modified": strings2any(modified)},
		"fileCount": len(files), "bytes": total, "alreadyPublished": str(base) == str(manifestHash),
		"note": "Review publishes inert source only; no build, evaluation, or Incus change"}, nil
}

func (p *PublishedSources) ensureTree(project string) (string, string, error) {
	parent := filepath.Dir(p.root)
	if !lexists(parent) {
		if err := ownedPrivateDir(filepath.Dir(parent), false); err != nil {
			return "", "", err
		}
		os.Mkdir(parent, 0o700)
	}
	if err := ownedPrivateDir(parent, false); err != nil {
		return "", "", err
	}
	os.Mkdir(p.root, 0o700)
	if err := ownedPrivateDir(p.root, true); err != nil {
		return "", "", err
	}
	directory := filepath.Join(p.root, project)
	os.Mkdir(directory, 0o700)
	if err := ownedPrivateDir(directory, true); err != nil {
		return "", "", err
	}
	revisions := filepath.Join(directory, "revisions")
	os.Mkdir(revisions, 0o700)
	if err := ownedPrivateDir(revisions, true); err != nil {
		return "", "", err
	}
	return directory, revisions, nil
}

func (p *PublishedSources) publish(s *ImportStaging, identity any, actor string, reviewID any, acknowledge any) (M, error) {
	rid, ok := reviewID.(string)
	if !isTrue(acknowledge) || !ok || !fullmatch(jobID, rid) {
		return nil, Public("Explicit reviewed source publication acknowledgement required")
	}
	directory, record, err := s.record(identity, actor)
	if err != nil {
		return nil, err
	}
	if str(record["status"]) != "ready" {
		return nil, Public("Only sealed source can be published")
	}
	review := readObj(filepath.Join(directory, "publish-review.json"))
	expires, _ := num(review["expires"])
	if str(review["id"]) != rid || str(review["actor"]) != actor || str(review["project"]) != str(record["project"]) ||
		str(review["manifestHash"]) != str(record["manifestHash"]) || now() >= expires {
		return nil, Public("Review expired or source identity changed; review again")
	}
	files, err := checkFiles(record["files"])
	if err != nil {
		return nil, err
	}
	revision := str(record["manifestHash"])
	if manifestSHA(files) != revision {
		return nil, Public("Source manifest changed after review")
	}
	staged := filepath.Join(directory, "source")
	if err := verifiedSource(staged, files, ""); err != nil {
		return nil, err
	}
	if err := checkSource(staged, files); err != nil {
		return nil, err
	}
	if err := inspectSourceSecrets(staged, files); err != nil {
		return nil, err
	}
	project := str(record["project"])
	existing, err := p.current(project)
	if err != nil {
		return nil, err
	}
	var base any
	if existing != nil {
		base = existing["revision"]
	}
	if !equalJSON(base, review["baseRevision"]) {
		return nil, Public("Published source changed after review; review again")
	}
	projectDir, revisions, err := p.ensureTree(project)
	if err != nil {
		return nil, err
	}
	target := filepath.Join(revisions, revision)
	if lexists(target) {
		if err := ownedPrivateDir(target, true); err != nil {
			return nil, err
		}
		metadata := readObj(filepath.Join(target, "manifest.json"))
		existingFiles, err := checkFiles(metadata["files"])
		if str(metadata["sourceHash"]) != revision || err != nil || !equalJSON(entriesAny(existingFiles), entriesAny(files)) {
			return nil, Public("Existing published source revision is untrusted")
		}
		if err := verifiedSource(filepath.Join(target, "source"), files, ""); err != nil {
			return nil, err
		}
		if err := checkSource(filepath.Join(target, "source"), files); err != nil {
			return nil, err
		}
	} else {
		temporary, err := os.MkdirTemp(revisions, ".pending-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(temporary)
		os.Chmod(temporary, 0o700)
		dest := filepath.Join(temporary, "source")
		os.Mkdir(dest, 0o700)
		if err := verifiedSource(staged, files, dest); err != nil {
			return nil, err
		}
		if err := writeJSON(filepath.Join(temporary, "manifest.json"), M{"schemaVersion": 1, "project": project,
			"sourceHash": revision, "files": entriesAny(files), "actor": actor, "created": now()}); err != nil {
			return nil, err
		}
		var dirs []string
		filepath.WalkDir(dest, func(p string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				dirs = append(dirs, p)
			}
			return nil
		})
		for i := len(dirs) - 1; i >= 0; i-- {
			fsyncDir(dirs[i])
		}
		fsyncDir(temporary)
		if err := os.Rename(temporary, target); err != nil {
			return nil, err
		}
		fsyncDir(revisions)
	}
	if str(base) != revision {
		if err := writeJSON(filepath.Join(projectDir, "current.json"), M{"schemaVersion": 1, "project": project,
			"revision": revision, "previous": base, "actor": actor, "publishedAt": now()}); err != nil {
			return nil, err
		}
	}
	audit("native-source-published", M{"principal": actor, "identity": identity, "project": project, "revision": revision, "previous": base})
	published := cloneM(record)
	published["status"] = "published"
	writeJSON(filepath.Join(directory, "manifest.json"), published)
	return M{"project": project, "revision": revision, "previous": base, "status": "published", "noChange": str(base) == revision,
		"note": "Source only: no OCI build, Incus deployment or Nix evaluation"}, nil
}

// --- archive extraction -------------------------------------------------------

const maxArchiveEntries = 1024
const maxZipDirectory = 2 * 1024 * 1024

func isArchiveName(name string) bool {
	lower := strings.ToLower(name)
	for _, s := range []string{".zip", ".tar", ".tar.gz", ".tgz"} {
		if strings.HasSuffix(lower, s) {
			return true
		}
	}
	return false
}

func preflightZipDirectory(p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	size, _ := f.Seek(0, io.SeekEnd)
	start := max(0, size-65557)
	f.Seek(start, io.SeekStart)
	tail, _ := io.ReadAll(f)
	where := strings.LastIndex(string(tail), "PK\x05\x06")
	if where < 0 || len(tail)-where < 22 {
		return Public("Archive has no valid bounded ZIP directory")
	}
	b := tail[where:]
	disk := binary.LittleEndian.Uint16(b[4:])
	dirDisk := binary.LittleEndian.Uint16(b[6:])
	diskEntries := binary.LittleEndian.Uint16(b[8:])
	entries := binary.LittleEndian.Uint16(b[10:])
	length := binary.LittleEndian.Uint32(b[12:])
	offset := binary.LittleEndian.Uint32(b[16:])
	comment := binary.LittleEndian.Uint16(b[20:])
	if disk != 0 || dirDisk != 0 || diskEntries != entries || entries < 1 || entries > maxArchiveEntries ||
		length > maxZipDirectory || entries == 0xFFFF || offset == 0xFFFFFFFF || length == 0xFFFFFFFF ||
		int64(offset)+int64(length) > size || where+22+int(comment) != len(tail) {
		return Public("Archive has an unsupported or oversized ZIP directory")
	}
	return nil
}

func memberPath(name string, directory bool) (string, bool) {
	for strings.HasPrefix(name, "./") {
		name = name[2:]
	}
	if directory {
		trimmed := strings.TrimRight(name, "/")
		if trimmed == "" || trimmed == "." {
			return "", false
		}
		return trimmed, true
	}
	return name, true
}

func copyMember(reader io.Reader, root, relative string, stated, maxFile, maxTotal, total int64) (sourceEntry, error) {
	target := filepath.Join(root, relative)
	os.MkdirAll(filepath.Dir(target), 0o700)
	if stated < 0 || stated > maxFile || total+stated > maxTotal {
		return sourceEntry{}, Public("Archive entry exceeds uncompressed source quota")
	}
	fd, err := syscall.Open(target, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return sourceEntry{}, Public("Archive contains duplicate source paths")
	}
	out := os.NewFile(uintptr(fd), target)
	defer out.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(h, out), io.LimitReader(reader, stated+1))
	if err != nil {
		return sourceEntry{}, Public("Archive is invalid, incomplete or unsupported")
	}
	if n > stated || n > maxFile || total+n > maxTotal {
		return sourceEntry{}, Public("Archive entry exceeds declared size or uncompressed quota")
	}
	if n != stated {
		return sourceEntry{}, Public("Truncated archive entry")
	}
	out.Sync()
	out.Chmod(0o400)
	return sourceEntry{relative, n, hex.EncodeToString(h.Sum(nil))}, nil
}

func extractArchive(archive, destination string, maxFiles int, maxFile, maxTotal int64) ([]sourceEntry, error) {
	if !isArchiveName(filepath.Base(archive)) {
		return nil, Public("Upload a ZIP, TAR, TAR.GZ or TGZ archive")
	}
	entriesNow, _ := os.ReadDir(destination)
	if isSymlink(destination) || !isDir(destination) || len(entriesNow) > 0 {
		return nil, Public("Archive extraction target must be an empty private directory")
	}
	info, err := os.Lstat(archive)
	if err != nil || !info.Mode().IsRegular() || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return nil, Public("Archive upload must be a regular file")
	}
	var files []sourceEntry
	seen := map[string]bool{}
	var total int64
	count := 0
	accept := func(name string, size int64, reader io.Reader) error {
		count++
		if count > maxArchiveEntries {
			return Public("Archive has too many members")
		}
		raw, _ := memberPath(name, false)
		safe, err := checkPath(raw)
		if err != nil {
			return err
		}
		if seen[safe] {
			return Public("Archive contains duplicate source paths")
		}
		if len(files) >= maxFiles {
			return Public("Archive exceeds source file count limit")
		}
		if size > maxFile || total+size > maxTotal {
			return Public("Archive exceeds uncompressed source quota")
		}
		seen[safe] = true
		entry, err := copyMember(reader, destination, safe, size, maxFile, maxTotal, total)
		if err != nil {
			return err
		}
		total += entry.Size
		files = append(files, entry)
		return nil
	}
	invalid := Public("Archive is invalid, incomplete or unsupported")
	if strings.HasSuffix(strings.ToLower(archive), ".zip") {
		if err := preflightZipDirectory(archive); err != nil {
			return nil, err
		}
		z, err := zip.OpenReader(archive)
		if err != nil {
			return nil, invalid
		}
		defer z.Close()
		if len(z.File) > maxArchiveEntries {
			return nil, Public("Archive has too many members")
		}
		for _, m := range z.File {
			mode := m.ExternalAttrs >> 16
			kind := mode & syscall.S_IFMT
			if m.Flags&1 != 0 {
				return nil, Public("Encrypted archive entries are unsupported")
			}
			if strings.HasSuffix(m.Name, "/") {
				if kind != 0 && kind != syscall.S_IFDIR {
					return nil, Public("Unsafe archive directory")
				}
				if rel, ok := memberPath(m.Name, true); ok {
					if _, err := checkPath(rel); err != nil {
						return nil, err
					}
				}
				continue
			}
			if kind != 0 && kind != syscall.S_IFREG {
				return nil, Public("Archive links and special files are forbidden")
			}
			r, err := m.Open()
			if err != nil {
				return nil, invalid
			}
			err = accept(m.Name, int64(m.UncompressedSize64), r)
			r.Close()
			if err != nil {
				return nil, err
			}
		}
	} else {
		f, err := os.Open(archive)
		if err != nil {
			return nil, invalid
		}
		defer f.Close()
		var reader io.Reader = f
		lower := strings.ToLower(archive)
		if strings.HasSuffix(lower, ".gz") || strings.HasSuffix(lower, ".tgz") {
			gz, err := gzip.NewReader(f)
			if err != nil {
				return nil, invalid
			}
			defer gz.Close()
			reader = gz
		}
		tr := tar.NewReader(reader)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, invalid
			}
			switch h.Typeflag {
			case tar.TypeDir:
				count++
				if count > maxArchiveEntries {
					return nil, Public("Archive has too many members")
				}
				if rel, ok := memberPath(h.Name, true); ok {
					if _, err := checkPath(rel); err != nil {
						return nil, err
					}
				}
			case tar.TypeReg:
				if err := accept(h.Name, h.Size, tr); err != nil {
					return nil, err
				}
			case tar.TypeXGlobalHeader:
			default:
				return nil, Public("Archive links, sparse entries and special files are forbidden")
			}
		}
	}
	if len(files) == 0 {
		return nil, Public("Archive contains no source files")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

// --- credential guards ---------------------------------------------------------

const maxInspect = 2 * 1024 * 1024

var dockerfileName = regexp.MustCompile(`(?i)^(?:dockerfile|containerfile)(?:[._-][a-z0-9._-]+)?$`)
var composeName = regexp.MustCompile(`(?i)^(?:docker-)?compose(?:[._-][a-z0-9_-]+)?\.ya?ml$`)
var credentialWord = regexp.MustCompile(`(?i)(?:password|passwd|passphrase|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|authorization|auth[_-]?token)`)
var credentialAssignment = regexp.MustCompile(`(?i)\b([A-Za-z_][A-Za-z_0-9.-]*(?:PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)[A-Za-z_0-9.-]*)\s*(?:=|:)\s*([^\s#]+)`)
var credentialURL = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s@/]+@`)
var privateMaterial = regexp.MustCompile(`(?i)-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----|AGE-SECRET-KEY-1`)

func guardFail(p, problem string) error {
	return Publicf("Source publication blocked for %s: %s. Import values using Projects → Environment & Secrets (SOPS/age); re-upload a redacted original file. Upload bytes were not modified.", p, problem)
}

func placeholderValue(v any) bool {
	value := strings.Trim(strings.TrimSpace(fmt.Sprint(v)), `"'`)
	return value == "" || value == "null" || value == "~" || (strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}")) ||
		(strings.HasPrefix(value, "{{") && strings.HasSuffix(value, "}}"))
}

func inspectText(p string, data []byte) (string, error) {
	text := string(data)
	if !utf8Valid(data) {
		return "", guardFail(p, "Dockerfile/Compose/.env source is not valid UTF-8")
	}
	if strings.Contains(text, "\x00") {
		return "", guardFail(p, "Dockerfile/Compose/.env source has NUL bytes")
	}
	if privateMaterial.MatchString(text) {
		return "", guardFail(p, "private key material detected")
	}
	if credentialURL.MatchString(text) {
		return "", guardFail(p, "credential-bearing URL detected")
	}
	for i, line := range splitLines(text) {
		if m := credentialAssignment.FindStringSubmatch(line); m != nil && !placeholderValue(m[2]) {
			return "", guardFail(p, fmt.Sprintf("possible plaintext credential on line %d", i+1))
		}
	}
	return text, nil
}

func splitLines(text string) []string {
	return strings.Split(strings.TrimSuffix(strings.ReplaceAll(text, "\r\n", "\n"), "\n"), "\n")
}

var envArgDirective = regexp.MustCompile(`(?i)^\s*(?:ENV|ARG)\s+`)

func checkComposeYAML(p, text string) error {
	var doc any
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return guardFail(p, "Compose YAML could not be safely parsed")
	}
	root := yamlMap(doc)
	services := yamlMap(root["services"])
	if root == nil || services == nil {
		return guardFail(p, "Compose services mapping is invalid or unsupported")
	}
	for _, raw := range services {
		spec := yamlMap(raw)
		if spec == nil {
			return guardFail(p, "Compose service structure is invalid")
		}
		if build := yamlMap(spec["build"]); build != nil {
			for _, k := range []string{"secrets", "ssh"} {
				if _, ok := build[k]; ok {
					return guardFail(p, "unsupported upstream Compose build."+k+"; runtime SOPS cannot satisfy build-time "+k)
				}
			}
			switch args := build["args"].(type) {
			case map[string]any:
				for k := range args {
					if credentialWord.MatchString(k) {
						return guardFail(p, "secret-bearing build.args cannot enter an OCI build worker")
					}
				}
			case []any:
				for _, item := range args {
					key, _, _ := strings.Cut(fmt.Sprint(item), "=")
					if credentialWord.MatchString(key) {
						return guardFail(p, "secret-bearing build.args cannot enter an OCI build worker")
					}
				}
			}
		}
		switch env := spec["environment"].(type) {
		case map[string]any:
			for k, v := range env {
				if credentialWord.MatchString(k) && v != nil && !placeholderValue(v) {
					return guardFail(p, "plaintext secret in Compose environment")
				}
			}
		case []any:
			for _, item := range env {
				if s, ok := item.(string); ok {
					if k, v, ok := strings.Cut(s, "="); ok && credentialWord.MatchString(k) && !placeholderValue(v) {
						return guardFail(p, "plaintext secret in Compose environment")
					}
				}
			}
		}
	}
	return nil
}

// yamlMap converts a YAML mapping into map[string]any (keys stringified).
func yamlMap(v any) map[string]any {
	switch m := v.(type) {
	case map[string]any:
		return m
	case map[any]any:
		out := map[string]any{}
		for k, val := range m {
			out[fmt.Sprint(k)] = val
		}
		return out
	}
	return nil
}

func checkSource(directory string, files []sourceEntry) error {
	for _, item := range files {
		base := strings.ToLower(filepath.Base(item.Path))
		example := base == ".env.example" || base == ".env.sample" || base == ".env.template"
		if strings.HasSuffix(base, ".env") || base == ".env" || (strings.HasPrefix(base, ".env.") && !example) {
			return guardFail(item.Path, "plaintext .env upload is not publishable")
		}
		docker := dockerfileName.MatchString(base)
		compose := composeName.MatchString(base)
		if !docker && !compose && !example {
			continue
		}
		if item.Size > maxInspect {
			return guardFail(item.Path, "source exceeds bounded credential-inspection limit")
		}
		data, err := os.ReadFile(filepath.Join(directory, item.Path))
		if err != nil || int64(len(data)) != item.Size {
			return guardFail(item.Path, "source changed during inspection")
		}
		text, err := inspectText(item.Path, data)
		if err != nil {
			return err
		}
		if docker {
			for i, line := range splitLines(text) {
				if envArgDirective.MatchString(line) && credentialWord.MatchString(line) {
					return guardFail(item.Path, fmt.Sprintf("unsafe build ARG/ENV credential on line %d", i+1))
				}
			}
		}
		if compose {
			if err := checkComposeYAML(item.Path, text); err != nil {
				return err
			}
		}
	}
	return nil
}

var secretCredential = regexp.MustCompile(`(?i)(?:PASSWORD|PASSWD|PASS|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|CLIENT[_-]?SECRET|AUTH[_-]?TOKEN|CREDENTIAL)`)
var envDirective = regexp.MustCompile(`(?i)^\s*(?:ENV|ARG)\s+(.+)$`)
var assignmentToken = regexp.MustCompile(`(?:^|[^A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)=([^\s]+)`)
var composeKey = regexp.MustCompile(`^(\s*)([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(.*?)\s*(?:#.*)?$`)
var listItem = regexp.MustCompile(`^\s*-\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)

func inspectDockerfileSecrets(p string, raw []byte) error {
	if !utf8Valid(raw) {
		return Public("Cannot inspect Dockerfile as UTF-8")
	}
	for _, line := range splitLines(string(raw)) {
		if strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
			continue
		}
		m := envDirective.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		directive := strings.ToUpper(strings.Fields(line)[0])
		rest := strings.TrimSpace(m[1])
		for _, a := range assignmentToken.FindAllStringSubmatch(rest, -1) {
			if secretCredential.MatchString(a[1]) {
				return Publicf("Credential-bearing Dockerfile %s in %s; use the Nixus SOPS secrets UI and runtime file bindings", directive, p)
			}
		}
		first, _, _ := strings.Cut(strings.Fields(rest)[0], "=")
		if directive == "ARG" && secretCredential.MatchString(first) {
			return Publicf("Credential-bearing Dockerfile ARG in %s; build-time secrets are not supported", p)
		}
		if directive == "ENV" && !strings.Contains(rest, "=") {
			parts := strings.Fields(rest)
			if len(parts) >= 2 && secretCredential.MatchString(parts[0]) {
				return Publicf("Credential-bearing Dockerfile ENV in %s; use SOPS", p)
			}
		}
	}
	return nil
}

func inspectComposeSecrets(p string, raw []byte) error {
	if !utf8Valid(raw) {
		return Public("Cannot inspect Compose YAML as UTF-8")
	}
	section := ""
	indent := -1
	for _, line := range splitLines(string(raw)) {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
			continue
		}
		if m := composeKey.FindStringSubmatch(line); m != nil {
			level, key, value := len(m[1]), m[2], m[3]
			if section != "" && level <= indent {
				section = ""
			}
			if (key == "environment" || key == "args") && value == "" {
				section, indent = key, level
				continue
			}
			if section != "" && level > indent && secretCredential.MatchString(key) {
				return Publicf("Credential-bearing Compose %s in %s; import values into SOPS and use scoped runtime files", section, p)
			}
		}
		if section != "" && len(line)-len(strings.TrimLeft(line, " \t")) > indent {
			if m := listItem.FindStringSubmatch(line); m != nil && secretCredential.MatchString(m[1]) {
				return Publicf("Credential-bearing Compose %s in %s; use the Nixus SOPS secrets UI", section, p)
			}
		}
	}
	return nil
}

func inspectSourceSecrets(source string, files []sourceEntry) error {
	for _, item := range files {
		base := strings.ToLower(filepath.Base(item.Path))
		switch {
		case base == "dockerfile" || base == "containerfile" || strings.HasPrefix(base, "dockerfile.") || strings.HasPrefix(base, "containerfile."):
			if item.Size > 1024*1024 {
				return Public("Dockerfile too large for credential preflight")
			}
			raw, err := os.ReadFile(filepath.Join(source, item.Path))
			if err != nil {
				return err
			}
			if err := inspectDockerfileSecrets(item.Path, raw); err != nil {
				return err
			}
		case base == "compose.yaml" || base == "compose.yml" || base == "docker-compose.yaml" || base == "docker-compose.yml":
			if item.Size > 1024*1024 {
				return Public("Compose source too large for credential preflight")
			}
			raw, err := os.ReadFile(filepath.Join(source, item.Path))
			if err != nil {
				return err
			}
			if err := inspectComposeSecrets(item.Path, raw); err != nil {
				return err
			}
		}
	}
	return nil
}
