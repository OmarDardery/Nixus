package main

// Image lock and update detection for published project source. Every
// external image (Compose image: and Dockerfile FROM) is recorded with its
// registry, tracked tag and pinned digest. A periodic check asks registries
// for the current digest of each tracked tag. An update is never applied
// directly: it is prepared as a new staged source revision, with only the
// matching @sha256 digests replaced, for the normal review and deployment.

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var imageUpdatesPath = func() string { return filepath.Join(STATE, "image-updates.json") }

var digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var refComponent = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`)
var tagRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
var hostRe = regexp.MustCompile(`^(?:localhost|[A-Za-z0-9.-]+\.[A-Za-z]{2,}|[A-Za-z0-9.-]+:[0-9]+)$`)

type imageRef struct {
	Registry, Repository, Tag, Digest string
}

// parseImageRef splits [registry/]repository[:tag][@sha256:digest].
func parseImageRef(ref string) (imageRef, bool) {
	var r imageRef
	if ref == "" || len(ref) > 512 || strings.ContainsAny(ref, " \t\n$") {
		return r, false
	}
	name := ref
	if i := strings.Index(name, "@"); i >= 0 {
		r.Digest, name = name[i+1:], name[:i]
		if !digestRe.MatchString(r.Digest) {
			return r, false
		}
	}
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		r.Tag, name = name[i+1:], name[:i]
		if !tagRe.MatchString(r.Tag) {
			return r, false
		}
	}
	parts := strings.Split(name, "/")
	if len(parts) > 1 && hostRe.MatchString(parts[0]) {
		r.Registry, parts = parts[0], parts[1:]
	} else {
		r.Registry = "docker.io"
	}
	if r.Registry == "docker.io" && len(parts) == 1 {
		parts = append([]string{"library"}, parts...)
	}
	for _, p := range parts {
		if !refComponent.MatchString(p) {
			return r, false
		}
	}
	r.Repository = strings.Join(parts, "/")
	return r, r.Repository != ""
}

// dockerfileBases returns external FROM references, skipping scratch and
// references to earlier build stages.
func dockerfileBases(text string) []string {
	stages := map[string]bool{}
	var refs []string
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || !strings.EqualFold(fields[0], "FROM") {
			continue
		}
		args := fields[1:]
		for len(args) > 0 && strings.HasPrefix(args[0], "--") {
			args = args[1:]
		}
		if len(args) == 0 {
			continue
		}
		ref := args[0]
		if len(args) >= 3 && strings.EqualFold(args[1], "AS") {
			stages[strings.ToLower(args[2])] = true
		}
		if strings.EqualFold(ref, "scratch") || stages[strings.ToLower(ref)] && !strings.ContainsAny(ref, ":/@") {
			continue
		}
		refs = append(refs, ref)
	}
	return refs
}

func lockEntry(file, kind, raw string) M {
	r, ok := parseImageRef(raw)
	entry := M{"file": file, "kind": kind, "ref": raw, "valid": ok}
	if ok {
		entry["registry"], entry["repository"], entry["tag"], entry["digest"] = r.Registry, r.Repository, r.Tag, r.Digest
	}
	entry["pinned"] = ok && r.Digest != ""
	return entry
}

// imageLock lists every external image referenced by a published revision.
func imageLock(folder string, files []sourceEntry) []any {
	var out []any
	for _, f := range files {
		base := path.Base(f.Path)
		if !composeNames[base] && !dockerfileNames[base] || f.Size > 1024*1024 {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(folder, "source", f.Path))
		if err != nil {
			continue
		}
		if dockerfileNames[base] {
			for _, ref := range dockerfileBases(string(raw)) {
				out = append(out, lockEntry(f.Path, "dockerfile-from", ref))
			}
			continue
		}
		var doc struct {
			Services map[string]struct {
				Image string `yaml:"image"`
				Build any    `yaml:"build"`
			} `yaml:"services"`
		}
		if yaml.Unmarshal(raw, &doc) != nil {
			continue
		}
		names := make([]string, 0, len(doc.Services))
		for n := range doc.Services {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			svc := doc.Services[n]
			if svc.Image != "" && svc.Build == nil {
				e := lockEntry(f.Path, "compose-image", svc.Image)
				e["service"] = n
				out = append(out, e)
			}
		}
	}
	if out == nil {
		out = []any{}
	}
	return out
}

// unpinnedBases reports Dockerfile bases the offline builder cannot resolve.
func unpinnedBases(lock []any) bool {
	for _, raw := range lock {
		e := obj(raw)
		if str(e["kind"]) == "dockerfile-from" && !isTrue(e["pinned"]) {
			return true
		}
	}
	return false
}

// --- registry digest lookup -----------------------------------------------------

// loopbackRegistry reports a registry on this machine, which may use plain HTTP.
func loopbackRegistry(registry string) bool {
	return strings.HasPrefix(registry, "localhost:") || strings.HasPrefix(registry, "127.0.0.1:")
}

// registryDigest returns the manifest digest a tag currently points to. skopeo
// does the registry protocol and authentication.
var registryDigest = func(r imageRef) (string, error) {
	argv := []string{"skopeo", "--insecure-policy", "inspect", "--format", "{{.Digest}}"}
	if loopbackRegistry(r.Registry) {
		argv = append(argv, "--tls-verify=false")
	}
	res, err := run(append(argv, "docker://"+r.Registry+"/"+r.Repository+":"+r.Tag), nil, 60*time.Second,
		[]string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}, "")
	if err != nil {
		return "", Public("Registry unreachable")
	}
	if res.Code != 0 {
		return "", Public("Registry has no manifest for this tag")
	}
	digest := strings.TrimSpace(string(res.Stdout))
	if !digestRe.MatchString(digest) {
		return "", Public("Registry returned no usable digest")
	}
	return digest, nil
}

// --- checks and prepared updates ---------------------------------------------------

func publishedRevisionFiles(publisher *PublishedSources, project string) (string, string, []sourceEntry, error) {
	current, err := publisher.current(project)
	if err != nil || current == nil {
		return "", "", nil, err
	}
	revision := str(current["revision"])
	if _, err := publisher.attestOpts(project, revision, true); err != nil {
		return "", "", nil, err
	}
	folder := filepath.Join(publisher.root, project, "revisions", revision)
	files, err := checkFiles(readObj(filepath.Join(folder, "manifest.json"))["files"])
	return revision, folder, files, err
}

func checkImageUpdates() (M, error) {
	publisher := NewPublishedSources("")
	projects := M{}
	entries, _ := os.ReadDir(publisher.root)
	for _, e := range entries {
		if !e.IsDir() || !fullmatch(projectName, e.Name()) {
			continue
		}
		revision, folder, files, err := publishedRevisionFiles(publisher, e.Name())
		if err != nil || revision == "" {
			continue
		}
		images := imageLock(folder, files)
		held := heldDigests(e.Name())
		updates := 0
		for _, raw := range images {
			img := obj(raw)
			switch {
			case !isTrue(img["valid"]):
				img["status"] = "invalid-reference"
			case str(img["tag"]) == "":
				img["status"] = "untracked"
				img["detail"] = "pinned without a tag, so there is nothing to follow"
			case !isTrue(img["pinned"]):
				img["status"] = "unpinned"
			default:
				latest, err := registryDigest(imageRef{str(img["registry"]), str(img["repository"]), str(img["tag"]), ""})
				if err != nil {
					img["status"], img["detail"] = "error", publicError(err)
				} else if latest == str(img["digest"]) {
					img["status"], img["latest"] = "current", latest
				} else if held[latest] {
					img["status"], img["latest"] = "held", latest
				} else {
					img["status"], img["latest"] = "update-available", latest
					updates++
				}
			}
		}
		projects[e.Name()] = M{"revision": revision, "images": images, "updates": updates}
	}
	result := M{"checkedAt": now(), "projects": projects}
	if err := writeJSONMode(imageUpdatesPath(), result, 0o640, ""); err != nil {
		return nil, err
	}
	audit("image-updates-checked", M{"projects": len(projects)})
	return result, nil
}

// replaceDigests swaps old digests for new ones only on lines that mention the
// image's repository, leaving every other byte unchanged.
func replaceDigests(text string, changes []M) (string, int) {
	lines := strings.SplitAfter(text, "\n")
	count := 0
	for i, line := range lines {
		for _, c := range changes {
			old, latest := "@"+str(c["digest"]), "@"+str(c["latest"])
			repo := str(c["repository"])
			short := strings.TrimPrefix(repo, "library/")
			if strings.Contains(line, old) && (strings.Contains(line, repo) || strings.Contains(line, short)) {
				lines[i] = strings.ReplaceAll(lines[i], old, latest)
				count++
			}
		}
	}
	return strings.Join(lines, ""), count
}

// prepareImageUpdate stages a new source revision for the normal review flow.
func prepareImageUpdate(actor string, projectArg any) (M, error) {
	project, ok := projectArg.(string)
	if !ok || !fullmatch(projectName, project) {
		return nil, Public("Choose a project with published source")
	}
	status := obj(obj(readObj(imageUpdatesPath())["projects"])[project])
	publisher := NewPublishedSources("")
	revision, folder, files, err := publishedRevisionFiles(publisher, project)
	if err != nil || revision == "" {
		return nil, Public("The project has no published source")
	}
	if str(status["revision"]) != revision {
		return nil, Public("Published source changed since the last check; check for updates again")
	}
	byFile := map[string][]M{}
	for _, raw := range list(status["images"]) {
		img := obj(raw)
		if str(img["status"]) == "update-available" {
			byFile[str(img["file"])] = append(byFile[str(img["file"])], img)
		}
	}
	if len(byFile) == 0 {
		return nil, Public("No image updates are available for this project")
	}
	contents := map[string][]byte{}
	changed := []any{}
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(folder, "source", f.Path))
		if err != nil || sha256hex(data) != f.SHA256 {
			return nil, Public("Published source changed during preparation")
		}
		if updates := byFile[f.Path]; len(updates) > 0 {
			text, n := replaceDigests(string(data), updates)
			if n == 0 {
				return nil, Public("Could not locate the pinned digest in " + f.Path)
			}
			data = []byte(text)
			for _, u := range updates {
				changed = append(changed, M{"file": f.Path, "repository": u["repository"], "tag": u["tag"], "from": u["digest"], "to": u["latest"]})
			}
		}
		contents[f.Path] = data
	}
	entries := []any{}
	for _, f := range files {
		entries = append(entries, M{"path": f.Path, "size": len(contents[f.Path]), "sha256": sha256hex(contents[f.Path])})
	}
	result, err := stageFiles(actor, project, entries, files, contents)
	if err != nil {
		return nil, err
	}
	result["imageChanges"] = changed
	audit("image-update-prepared", M{"principal": actor, "project": project, "changes": len(changed)})
	return result, nil
}

func imageUpdatesCLI(args []string) error {
	if len(args) == 1 && args[0] == "check" {
		result, err := checkImageUpdates()
		if err == nil {
			printJSON(result)
		}
		return err
	}
	if len(args) == 1 && args[0] == "status" {
		printJSON(imageUpdatesView())
		return nil
	}
	if len(args) == 1 && args[0] == "auto" {
		result, err := autoImageUpdates()
		if result != nil {
			printJSON(result)
		}
		return err
	}
	if len(args) == 1 && args[0] == "apply-all" {
		result, err := applyAllImageUpdates("root")
		if result != nil {
			printJSON(result)
		}
		return err
	}
	if len(args) == 2 && args[0] == "apply" {
		result, err := applyImageUpdate("root", args[1])
		if result != nil {
			printJSON(result)
		}
		return err
	}
	if len(args) == 3 && (args[0] == "hold" || args[0] == "unhold") {
		result, err := setHold("root", args[1], args[2], args[0] == "hold", "held from the root CLI")
		if err == nil {
			printJSON(result)
		}
		return err
	}
	return Public("usage: nixus-admin image-updates {check|status|auto|apply PROJECT|apply-all|hold PROJECT DIGEST|unhold PROJECT DIGEST}")
}

// --- pinning pasted source ----------------------------------------------------------

var composeImageLine = regexp.MustCompile(`^(\s*image:\s*["']?)([^"'\s#]+)(["']?\s*(?:#.*)?)$`)

// pinText rewrites unpinned Dockerfile FROM and Compose image references to
// name:tag@sha256:digest. Untagged references follow "latest". Other bytes
// are unchanged.
func pinText(file, text string, resolve func(imageRef) (string, error)) (string, []any, error) {
	base := strings.ToLower(path.Base(file))
	isDockerfile := dockerfileNames[path.Base(file)] || strings.HasSuffix(base, ".dockerfile")
	isCompose := composeNames[path.Base(file)]
	if !isDockerfile && !isCompose {
		return text, nil, nil
	}
	changes := []any{}
	cache := map[string]string{}
	pin := func(ref string) (string, error) {
		r, ok := parseImageRef(ref)
		if !ok || r.Digest != "" {
			return ref, nil
		}
		if pinned, ok := cache[ref]; ok {
			return pinned, nil
		}
		tagged := ref
		if r.Tag == "" {
			r.Tag, tagged = "latest", ref+":latest"
		}
		digest, err := resolve(r)
		if err != nil {
			return "", Public("Could not resolve " + ref + ": " + publicError(err))
		}
		pinned := tagged + "@" + digest
		cache[ref] = pinned
		changes = append(changes, M{"file": file, "from": ref, "to": pinned})
		return pinned, nil
	}
	stages := map[string]bool{}
	lines := strings.SplitAfter(text, "\n")
	for i, line := range lines {
		body := strings.TrimRight(line, "\r\n")
		ending := line[len(body):]
		if isDockerfile {
			fields := strings.Fields(body)
			if len(fields) < 2 || !strings.EqualFold(fields[0], "FROM") {
				continue
			}
			args := fields[1:]
			for len(args) > 0 && strings.HasPrefix(args[0], "--") {
				args = args[1:]
			}
			if len(args) == 0 {
				continue
			}
			ref := args[0]
			stage := ""
			if len(args) >= 3 && strings.EqualFold(args[1], "AS") {
				stage = strings.ToLower(args[2])
			}
			if !strings.EqualFold(ref, "scratch") && !(stages[strings.ToLower(ref)] && !strings.ContainsAny(ref, ":/@")) {
				pinned, err := pin(ref)
				if err != nil {
					return "", nil, err
				}
				if pinned != ref {
					idx := strings.Index(body, ref)
					lines[i] = body[:idx] + pinned + body[idx+len(ref):] + ending
				}
			}
			if stage != "" {
				stages[stage] = true
			}
			continue
		}
		if m := composeImageLine.FindStringSubmatch(body); m != nil {
			pinned, err := pin(m[2])
			if err != nil {
				return "", nil, err
			}
			if pinned != m[2] {
				lines[i] = m[1] + pinned + m[3] + ending
			}
		}
	}
	return strings.Join(lines, ""), changes, nil
}

// pinSources pins every pasted file, returning the rewritten texts.
func pinSources(filesArg any) (M, error) {
	files := list(filesArg)
	if len(files) == 0 || len(files) > 64 {
		return nil, Public("Paste 1–64 files to pin")
	}
	out := []any{}
	changes := []any{}
	for _, raw := range files {
		f := obj(raw)
		name, text := str(f["path"]), str(f["text"])
		if name == "" || len(text) > 1024*1024 {
			return nil, Public("Invalid file to pin")
		}
		pinned, c, err := pinText(name, text, registryDigest)
		if err != nil {
			return nil, err
		}
		changes = append(changes, c...)
		out = append(out, M{"path": name, "text": pinned})
	}
	return M{"files": out, "changes": changes}, nil
}
