package main

// OCI source planning, Compose secret classification and model validation,
// untrusted artifact verification, fingerprint-checked Incus image import and
// the unprivileged builder child that runs *inside* the bubblewrap sandbox.

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// --- source plan -----------------------------------------------------------

var composeNames = map[string]bool{"compose.yaml": true, "compose.yml": true, "docker-compose.yaml": true, "docker-compose.yml": true}
var dockerfileNames = map[string]bool{"Dockerfile": true, "Containerfile": true}
var buildkitPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?mi)^\s*#\s*syntax\s*=\s*docker/dockerfile:`),
	regexp.MustCompile(`(?mi)^\s*RUN\s+--(?:mount|security|device)\b`),
	regexp.MustCompile(`(?mi)^\s*(?:COPY|ADD)\s+--link\b`),
}

func jsonString(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

func generatedCompose(project, revision, dockerfile string) (string, string) {
	parent := path.Dir(dockerfile)
	context := "./" + parent
	if parent == "." {
		context = "."
	}
	image := "localhost/nixus-" + truncate(project, 24) + "-app:" + revision[:32]
	return "services:\n  app:\n    image: " + jsonString(image) + "\n    build:\n      context: " + jsonString(context) +
		"\n      dockerfile: " + jsonString(path.Base(dockerfile)) + "\n", image
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func sourcePlan(project, revision any, publisher *PublishedSources) (M, error) {
	if publisher == nil {
		publisher = NewPublishedSources("")
	}
	attestation, err := publisher.attest(project, revision)
	if err != nil {
		return nil, err
	}
	p, rev := project.(string), revision.(string)
	folder := filepath.Join(publisher.root, p, "revisions", rev)
	files, err := checkFiles(readObj(filepath.Join(folder, "manifest.json"))["files"])
	if err != nil {
		return nil, err
	}
	byPath := map[string]sourceEntry{}
	var compose, dockerfiles []string
	for _, e := range files {
		byPath[e.Path] = e
		if composeNames[path.Base(e.Path)] {
			compose = append(compose, e.Path)
		}
		if dockerfileNames[path.Base(e.Path)] {
			dockerfiles = append(dockerfiles, e.Path)
		}
	}
	sort.Strings(compose)
	sort.Strings(dockerfiles)
	reasons := []string{}
	var generated, image, selected, policy any
	mode := "unsupported"
	switch {
	case len(compose) == 1:
		mode, selected = "compose", compose[0]
		reasons = append(reasons, "sandboxed-incus-compose-compatibility-check-required")
		raw, err := os.ReadFile(filepath.Join(folder, "source", compose[0]))
		classified, cerr := classifyComposeSecrets(raw, nil)
		if err != nil || cerr != nil {
			reasons = append(reasons, "compose-secret-preflight-failed")
		} else {
			policy = classified
			b, _ := anyStrings(classified["blocking"])
			reasons = append(reasons, b...)
			if len(list(classified["fileRoutes"])) > 0 {
				reasons = append(reasons, "compose-secret-binding-review-required")
			}
		}
	case len(compose) > 1:
		mode = "ambiguous-compose"
		reasons = append(reasons, "multiple-compose-files-require-explicit-selection")
	case len(dockerfiles) == 1:
		mode, selected = "dockerfile", dockerfiles[0]
		g, i := generatedCompose(p, rev, dockerfiles[0])
		generated, image = g, i
		if byPath[dockerfiles[0]].Size > 1024*1024 {
			reasons = append(reasons, "dockerfile-exceeds-preflight-source-size")
		} else {
			raw, _ := os.ReadFile(filepath.Join(folder, "source", dockerfiles[0]))
			for _, pattern := range buildkitPatterns {
				if pattern.Match(raw) {
					reasons = append(reasons, "unsupported-buildkit-feature-requires-explicit-policy")
					break
				}
			}
		}
	case len(dockerfiles) > 1:
		mode = "ambiguous-dockerfile"
		reasons = append(reasons, "multiple-dockerfiles-require-explicit-selection")
	default:
		reasons = append(reasons, "no-compose-or-dockerfile-entrypoint")
	}
	lock := imageLock(folder, files)
	if unpinnedBases(lock) {
		reasons = append(reasons, "dockerfile-base-image-must-be-pinned-by-digest")
	}
	reasons = append(reasons, "isolated-oci-builder-not-qualified", "source-qualified-image-import-not-qualified",
		"incus-compose-owned-deployment-not-qualified")
	return M{"format": 1, "project": p, "revision": attestation["revision"], "fileCount": attestation["fileCount"],
		"bytes": attestation["bytes"], "sourceFiles": entriesAny(files), "mode": mode, "entrypoint": selected,
		"generatedCompose": generated, "proposedImage": image, "composeSecretPolicy": policy, "buildContextHash": rev,
		"buildIdentity": sha256str(p + "\x00" + rev), "imageLock": lock, "canBuild": false, "canDeploy": false, "blocking": strings2any(reasons),
		"note": "Source-only planning: no OCI image, Incus resources or volume created"}, nil
}

// --- Compose secret classification -----------------------------------------

var composeSecretName = re(`[a-z][a-z0-9-]{0,62}`)
var secretKey = re(`[A-Za-z_][A-Za-z0-9_]{0,127}`)
var interpolation = regexp.MustCompile(`\$(?:\{([A-Za-z_][A-Za-z0-9_]*)(?:[:?+\-][^}]*)?\}|([A-Za-z_][A-Za-z0-9_]*))`)
var credentialName = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credential)`)

func checkRelativeSecret(v any) bool {
	value, ok := v.(string)
	if !ok || value == "" || len(value) > 255 || strings.ContainsAny(value, "\x00\\") || strings.HasPrefix(value, "/") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(value, "./"), "/")
	if len(parts) < 1 || len(parts) > 12 {
		return false
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || !fullmatch(re(`[A-Za-z0-9_.-]+`), p) {
			return false
		}
	}
	last := strings.ToLower(parts[len(parts)-1])
	return last != ".env" && last != "secrets.enc.yaml"
}

func yamlToJSON(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := M{}
		for k, val := range x {
			out[k] = yamlToJSON(val)
		}
		return out
	case map[any]any:
		out := M{}
		for k, val := range x {
			out[fmt.Sprint(k)] = yamlToJSON(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = yamlToJSON(val)
		}
		return out
	case int:
		return float64(x)
	}
	return v
}

func classifyComposeSecrets(contents []byte, bindings M) (M, error) {
	if len(contents) > maxInspect {
		return nil, Public("Invalid or oversized Compose source")
	}
	var raw any
	if !utf8Valid(contents) || yaml.Unmarshal(contents, &raw) != nil {
		return nil, Public("Compose secret preflight could not parse source")
	}
	document := obj(yamlToJSON(raw))
	services := obj(document["services"])
	if document == nil || len(services) == 0 {
		return nil, Public("Compose source has no valid services")
	}
	if bindings == nil {
		bindings = M{}
	}
	if len(bindings) > 128 {
		return nil, Public("Invalid Compose secret bindings")
	}
	declared := map[string]M{}
	for alias, b := range bindings {
		binding := obj(b)
		if !fullmatch(secretKey, alias) || binding == nil || !fullmatch(secretKey, str(binding["key"])) ||
			!fullmatch(composeSecretName, str(binding["instance"])) || str(binding["backend"]) != "incus-file" {
			return nil, Public("Invalid Compose secret delivery binding")
		}
		declared[alias] = binding
	}
	reasons := map[string]bool{}
	topLevel := M{}
	if v, ok := document["secrets"]; ok && v != nil {
		if topLevel = obj(v); topLevel == nil {
			return nil, Public("Compose top-level secrets must be a mapping")
		}
	}
	sensitive := map[string]bool{}
	for alias, b := range declared {
		sensitive[alias], sensitive[str(b["key"])] = true, true
	}
	refName := func(m []string) string {
		if m[1] != "" {
			return m[1]
		}
		return m[2]
	}
	for _, m := range interpolation.FindAllStringSubmatch(string(contents), -1) {
		if n := refName(m); sensitive[n] || credentialName.MatchString(n) {
			reasons["secret-interpolation-may-persist-in-incus-config"] = true
		}
	}
	consumed, usedPaths := map[string]bool{}, map[string]bool{}
	routes := []any{}
	for _, service := range keys(services) {
		spec := obj(services[service])
		if !fullmatch(composeSecretName, service) || spec == nil {
			return nil, Public("Invalid Compose service identity")
		}
		if spec["env_file"] != nil {
			reasons["compose-env-file-may-persist-in-incus-config"] = true
		}
		type kv struct {
			key   string
			value any
		}
		var entries []kv
		switch env := spec["environment"].(type) {
		case nil:
		case M:
			for k, v := range env {
				entries = append(entries, kv{k, v})
			}
		case []any:
			for _, item := range env {
				s, ok := item.(string)
				if !ok {
					return nil, Public("Compose environment list has an invalid entry")
				}
				k, v, has := strings.Cut(s, "=")
				if has {
					entries = append(entries, kv{k, v})
				} else {
					entries = append(entries, kv{k, nil})
				}
			}
		default:
			return nil, Public("Invalid Compose environment")
		}
		for _, e := range entries {
			if credentialName.MatchString(e.key) || sensitive[e.key] {
				reasons["compose-secret-environment-may-persist-in-incus-config"] = true
			}
			if s, ok := e.value.(string); ok {
				for _, m := range interpolation.FindAllStringSubmatch(s, -1) {
					if sensitive[refName(m)] {
						reasons["secret-interpolation-may-persist-in-incus-config"] = true
					}
				}
			}
		}
		grants := spec["secrets"]
		if grants == nil {
			grants = []any{}
		}
		grantList, ok := grants.([]any)
		if !ok {
			return nil, Public("Compose service secrets must be a list")
		}
		for _, grant := range grantList {
			var alias string
			gm := obj(grant)
			if s, ok := grant.(string); ok {
				alias = s
			} else if gm != nil && isStr(gm["source"]) {
				alias = str(gm["source"])
			} else {
				return nil, Public("Invalid Compose service secret grant")
			}
			if b, ok := declared[alias]; !ok || str(b["instance"]) != service {
				reasons["compose-secret-grant-not-bound-to-service"] = true
				continue
			}
			consumed[alias] = true
			definition := obj(topLevel[alias])
			if definition == nil || len(definition) != 1 || definition["file"] == nil {
				reasons["compose-secret-not-relative-file"] = true
				continue
			}
			if !checkRelativeSecret(definition["file"]) {
				reasons["compose-secret-file-path-unsafe"] = true
				continue
			}
			clean := strings.TrimPrefix(str(definition["file"]), "./")
			target, hasTarget := gm["target"]
			if usedPaths[clean] || (gm != nil && hasTarget && (!isStr(target) || !strings.HasPrefix(str(target), "/"))) {
				reasons["compose-secret-file-target-ambiguous"] = true
				continue
			}
			usedPaths[clean] = true
			routes = append(routes, M{"service": service, "alias": alias, "relativeFile": clean})
			reasons["incus-compose-secret-persists-in-guest-rootfs-unqualified"] = true
		}
	}
	if len(declared) > 0 && len(declared) != len(consumed) {
		reasons["declared-secret-not-consumed-by-compose"] = true
	}
	for k := range topLevel {
		if !consumed[k] {
			reasons["compose-secrets-without-approved-file-consumer"] = true
		}
	}
	if len(topLevel) > 0 && len(routes) == 0 {
		reasons["compose-secrets-without-approved-file-consumer"] = true
	}
	if len(routes) > 0 && (len(declared) == 0 || len(routes) != len(consumed)) {
		reasons["compose-file-secret-mapping-incomplete"] = true
	}
	sort.Slice(routes, func(i, j int) bool {
		a, b := obj(routes[i]), obj(routes[j])
		if str(a["service"]) != str(b["service"]) {
			return str(a["service"]) < str(b["service"])
		}
		return str(a["alias"]) < str(b["alias"])
	})
	qualification := "no-secret-delivery-claimed"
	if len(reasons) > 0 {
		qualification = "blocked"
	}
	return M{"format": 1, "qualification": qualification, "blocking": strings2any(sortedKeys(reasons)), "fileRoutes": routes,
		"note": "Static review only; no plaintext, guest mutation or Incus runtime qualification"}, nil
}

// --- Compose model validation ----------------------------------------------

var composeServiceName = re(`[a-z][a-z0-9_-]{0,62}`)
var composeSource = re(`[A-Za-z0-9][A-Za-z0-9_.-]*`)
var sensitiveEnv = regexp.MustCompile(`(?i)(?:PASSWORD|PASSWD|TOKEN|SECRET|PRIVATE|AUTH|KEY|CREDENTIAL)`)
var bannedService = map[string]bool{"privileged": true, "cap_add": true, "device_cgroup_rules": true,
	"security_opt": true, "userns_mode": true, "pid": true, "ipc": true, "uts": true, "cgroup": true, "cgroup_parent": true,
	"cgroupns_mode": true, "network_mode": true, "volumes_from": true, "extends": true, "develop": true, "secrets": true,
	"configs": true, "env_file": true, "x-incus": true, "x-incus-compose": true}
var bannedTop = map[string]bool{"secrets": true, "configs": true, "include": true, "x-incus": true, "x-incus-compose": true}

func safeRelative(v any, allowDot bool) (string, error) {
	value, ok := v.(string)
	if !ok || strings.ContainsAny(value, "\\\x00") || strings.HasPrefix(value, "/") {
		return "", Public("Unsupported or absolute Compose source path")
	}
	parts := strings.Split(value, "/")
	var kept []string
	allDots := true
	for _, p := range parts {
		if p == ".." || p == "" {
			return "", Public("Compose context cannot escape its source directory")
		}
		if p != "." {
			allDots = false
			if strings.HasPrefix(p, "-") || !fullmatch(composeSource, p) {
				return "", Public("Unsupported Compose source component")
			}
			kept = append(kept, p)
		}
	}
	if allowDot && allDots {
		return ".", nil
	}
	return strings.Join(kept, "/"), nil
}

func composeSourcePath(base string, v any, allowDot bool) (string, error) {
	if s, ok := v.(string); ok && (s == "/context" || strings.HasPrefix(s, "/context/")) {
		relative := strings.TrimLeft(strings.TrimPrefix(s, "/context"), "/")
		if relative == "" {
			return ".", nil
		}
		return safeRelative(relative, allowDot)
	}
	var parts []string
	if base != "." {
		parts = strings.Split(base, "/")
	}
	leaf, err := safeRelative(v, allowDot)
	if err != nil {
		return "", err
	}
	if leaf != "." && leaf != "" {
		parts = append(parts, strings.Split(leaf, "/")...)
	}
	if len(parts) == 0 {
		return ".", nil
	}
	return strings.Join(parts, "/"), nil
}

func composeVolumes(v any) ([]string, error) {
	if v == nil {
		return []string{}, nil
	}
	items, ok := v.([]any)
	if !ok || len(items) > 32 {
		return nil, Public("Invalid Compose mounts")
	}
	names := []string{}
	for _, item := range items {
		switch x := item.(type) {
		case string:
			source, _, has := strings.Cut(x, ":")
			if !has || source == "" || strings.HasPrefix(source, "/") || strings.HasPrefix(source, ".") || strings.HasPrefix(source, "~") || strings.Contains(source, "/") {
				return nil, Public("Compose bind or anonymous mounts require explicit separate review")
			}
			if !fullmatch(composeServiceName, source) {
				return nil, Public("Invalid named volume")
			}
			names = append(names, source)
		case M:
			for k := range x {
				switch k {
				case "type", "source", "target", "read_only", "volume":
				default:
					return nil, Public("Unsupported Compose volume attributes")
				}
			}
			if str(x["type"]) != "volume" || !fullmatch(composeServiceName, str(x["source"])) {
				return nil, Public("Bind/anonymous mounts are forbidden in this deployment adapter")
			}
			names = append(names, str(x["source"]))
		default:
			return nil, Public("Invalid Compose volume")
		}
	}
	return names, nil
}

func composeEnvironments(v any) error {
	if v == nil {
		return nil
	}
	env, ok := v.(M)
	if !ok {
		return Public("Compose environment must be explicit named entries")
	}
	if len(env) > 64 {
		return Public("Compose environment exceeds review bounds")
	}
	for k, value := range env {
		if !fullmatch(re(`[A-Za-z_][A-Za-z0-9_]{0,79}`), k) {
			return Public("Invalid environment variable name")
		}
		if sensitiveEnv.MatchString(k) {
			return Public("Secret-like environment variable requires scoped #134 SOPS delivery")
		}
		switch value.(type) {
		case nil, string, float64, bool, json.Number:
		default:
			return Public("Unsupported Compose environment value")
		}
	}
	return nil
}

// plainNamedVolume accepts a local named volume as Compose normalizes it: no
// options, or only the default "<project>_<name>" name and external: false.
var serialSource = re(`/dev/(serial/by-(id|path)/[A-Za-z0-9._:+-]{1,200}|tty(ACM|USB)[0-9]{1,3})`)
var deviceTarget = re(`/dev/[A-Za-z0-9._-]{1,64}`)
var usbID = re(`([0-9a-f]{4}):([0-9a-f]{4})`)

// composeDevices translates the supported device subset into Incus devices:
// serial ports (Compose devices:) become hotpluggable unix-char devices and
// x-nixus.usb vendor:product IDs become usb devices. Anything else is refused.
func composeDevices(v any, ext any) (M, error) {
	out := M{}
	refuse := Public("Only serial devices (/dev/serial/by-id/..., /dev/ttyACM*, /dev/ttyUSB*) and x-nixus.usb IDs can be passed through")
	items, ok := v.([]any)
	if v != nil && !ok {
		return nil, refuse
	}
	if len(items) > 8 {
		return nil, refuse
	}
	for i, raw := range items {
		var source, target, perms string
		switch d := raw.(type) {
		case string:
			parts := strings.Split(d, ":")
			if len(parts) > 3 {
				return nil, refuse
			}
			source, target = parts[0], parts[0]
			if len(parts) > 1 {
				target = parts[1]
			}
			if len(parts) > 2 {
				perms = parts[2]
			}
		case M:
			for k := range d {
				if k != "source" && k != "target" && k != "permissions" {
					return nil, refuse
				}
			}
			source, target, perms = str(d["source"]), str(d["target"]), str(d["permissions"])
			if target == "" {
				target = source
			}
		default:
			return nil, refuse
		}
		if !fullmatch(serialSource, source) || !fullmatch(deviceTarget, target) && !fullmatch(serialSource, target) ||
			(perms != "" && perms != "rwm" && perms != "rw") || strings.Contains(source+target, "..") {
			return nil, refuse
		}
		out[fmt.Sprintf("nixus-serial%d", i)] = M{"type": "unix-char", "source": source, "path": target,
			"required": "false", "mode": "0666"}
	}
	if ext != nil {
		x := obj(ext)
		usb, ok := x["usb"].([]any)
		if x == nil || len(x) != 1 || !ok || len(usb) > 8 {
			return nil, Public("x-nixus supports only usb: [\"vendor:product\"]")
		}
		for i, raw := range usb {
			m := usbID.FindStringSubmatch(str(raw))
			if m == nil || m[0] != str(raw) {
				return nil, Public("USB IDs look like 1d50:614e")
			}
			out[fmt.Sprintf("nixus-usb%d", i)] = M{"type": "usb", "vendorid": m[1], "productid": m[2], "required": "false"}
		}
	}
	return out, nil
}

func plainNamedVolume(project, name string, props any) bool {
	if props == nil {
		return true
	}
	for k, v := range obj(props) {
		switch {
		case k == "name" && v == project+"_"+name:
		case k == "external" && v == false:
		default:
			return false
		}
	}
	return obj(props) != nil
}

func validateComposeModel(model M, project, revision, composePath string, files []sourceEntry) (M, error) {
	if !fullmatch(composeServiceName, project) {
		return nil, Public("Invalid project")
	}
	if !fullmatch(hex64, revision) {
		return nil, Public("Invalid source revision")
	}
	if model == nil {
		return nil, Public("Compose demands unsupported privileged or secret resources")
	}
	for k := range model {
		if bannedTop[k] {
			return nil, Public("Compose demands unsupported privileged or secret resources")
		}
	}
	if v := model["volumes"]; v != nil {
		volumes, ok := v.(M)
		if !ok {
			return nil, Public("Custom storage drivers, external volumes and unsafe volume options are forbidden")
		}
		for name, props := range volumes {
			if !fullmatch(composeServiceName, name) || !plainNamedVolume(project, name, props) {
				return nil, Public("Custom storage drivers, external volumes and unsafe volume options are forbidden")
			}
		}
	}
	if v := model["networks"]; v != nil {
		networks, ok := v.(M)
		if !ok {
			return nil, Public("External or customized Compose networks require #133")
		}
		for name, props := range networks {
			pm := obj(props)
			if name != "default" || !(props == nil || len(pm) == 0 || (len(pm) == 1 && str(pm["name"]) == project+"_default")) {
				return nil, Public("External or customized Compose networks require #133")
			}
		}
	}
	services := obj(model["services"])
	if len(services) < 1 || len(services) > 16 {
		return nil, Public("Compose requires 1–16 services")
	}
	known := map[string]bool{}
	for _, f := range files {
		known[f.Path] = true
	}
	base := path.Dir(composePath)
	preview := []any{}
	for _, service := range keys(services) {
		data := obj(services[service])
		if !fullmatch(composeServiceName, service) || data == nil {
			return nil, Public("Invalid Compose service")
		}
		for k := range data {
			if bannedService[k] || (strings.HasPrefix(k, "x-") && k != "x-nixus") {
				return nil, Public("Compose service requires forbidden host privileges or runtime secrets")
			}
		}
		if err := composeEnvironments(data["environment"]); err != nil {
			return nil, err
		}
		ports := data["ports"]
		portList, ok := ports.([]any)
		if ports == nil {
			portList, ok = []any{}, true
		}
		if !ok || len(portList) > 32 {
			return nil, Public("Invalid Compose host port exposure")
		}
		for _, p := range portList {
			switch p.(type) {
			case string, float64, M, json.Number:
			default:
				return nil, Public("Invalid Compose host port exposure")
			}
		}
		named, err := composeVolumes(data["volumes"])
		if err != nil {
			return nil, err
		}
		devices, err := composeDevices(data["devices"], data["x-nixus"])
		if err != nil {
			return nil, err
		}
		var context, dockerfile any
		switch build := data["build"].(type) {
		case string:
			context, dockerfile = build, "Dockerfile"
		case M:
			for k := range build {
				switch k {
				case "context", "dockerfile", "args", "target", "no_cache", "pull", "labels", "platforms":
				default:
					return nil, Public("Unsupported build options; source retained unchanged")
				}
			}
			for _, k := range []string{"args", "target", "platforms", "pull"} {
				if v := build[k]; v != nil && v != false && v != "" && !(obj(v) != nil && len(obj(v)) == 0) && !(list(v) != nil && len(list(v)) == 0) {
					return nil, Public("Build args, network/pull, target and platforms require explicit build policy")
				}
			}
			context, dockerfile = build["context"], build["dockerfile"]
			if context == nil {
				context = "."
			}
			if dockerfile == nil {
				dockerfile = "Dockerfile"
			}
		case nil:
		default:
			return nil, Public("Invalid Compose build definition")
		}
		var image any
		var contextPath, dockerfilePath any
		built := context != nil
		if built {
			cp, err := composeSourcePath(base, context, true)
			if err != nil {
				return nil, err
			}
			dp, err := composeSourcePath(cp, dockerfile, false)
			if err != nil {
				return nil, err
			}
			if !known[dp] {
				return nil, Public("Compose Dockerfile is missing from the exact published context")
			}
			contextPath, dockerfilePath = cp, dp
			image = fmt.Sprintf("localhost/nixus-%s-%s:%s", truncate(project, 24), truncate(service, 24), revision[:32])
		} else {
			img, ok := data["image"].(string)
			if !ok || !strings.Contains(img, "@sha256:") {
				return nil, Public("Non-built services must use explicit immutable OCI image digests")
			}
			image = img
		}
		preview = append(preview, M{"service": service, "image": image, "built": built, "context": contextPath,
			"dockerfile": dockerfilePath, "namedVolumes": strings2any(named), "ports": portList, "devices": devices})
	}
	lines := []string{"services:"}
	for _, raw := range preview {
		svc := obj(raw)
		devices := obj(svc["devices"])
		if !isTrue(svc["built"]) && len(devices) == 0 {
			continue
		}
		lines = append(lines, "  "+str(svc["service"])+":")
		if isTrue(svc["built"]) {
			lines = append(lines, "    image: "+jsonString(str(svc["image"])), "    build: !reset null")
		}
		if len(devices) > 0 {
			lines = append(lines, "    x-incus-compose:", "      devices:")
			for _, name := range keys(devices) {
				lines = append(lines, "        "+name+":")
				d := obj(devices[name])
				for _, k := range keys(d) {
					lines = append(lines, "          "+k+": "+jsonString(str(d[k])))
				}
			}
		}
	}
	override := ""
	if len(lines) > 1 {
		override = strings.Join(lines, "\n") + "\n"
	}
	identity := digestJSON(M{"project": project, "revision": revision, "services": preview})
	wouldCreate := []any{}
	requiresBuilder := false
	for _, raw := range preview {
		wouldCreate = append(wouldCreate, obj(raw)["service"])
		requiresBuilder = requiresBuilder || isTrue(obj(raw)["built"])
	}
	return M{"format": 1, "project": project, "revision": revision, "services": preview, "separateOverride": override,
		"sourceHash": revision, "intentHash": identity, "requiresBuilder": requiresBuilder, "wouldCreateOrRecreate": wouldCreate,
		"note": "Intent only. Apply requires separate approval and exact Incus ownership checks."}, nil
}

// --- untrusted artifact verification -------------------------------------------

const maxImageBytes = 1024 * 1024 * 1024
const maxArchiveMembers = 4096
const maxManifestJSON = 1024 * 1024
const maxRootfsEntries = 262144

var ociMediaTypes = map[string]bool{"application/vnd.oci.image.manifest.v1+json": true, "application/vnd.oci.image.config.v1+json": true,
	"application/vnd.oci.image.layer.v1.tar+gzip": true, "application/vnd.oci.image.layer.v1.tar": true, "application/vnd.oci.image.layer.v1.tar+zstd": true}

func ociRef(v any) (string, error) {
	o := obj(v)
	digest := str(o["digest"])
	size, ok := intValue(o["size"])
	if o == nil || !ociMediaTypes[str(o["mediaType"])] || !strings.HasPrefix(digest, "sha256:") || !fullmatch(hex64, digest[min(7, len(digest)):]) || !ok || size < 0 {
		return "", Public("OCI image reference is malformed or unsupported")
	}
	return digest[7:], nil
}

func checkArtifactFile(p string, expectedSHA any, expectedBytes any) (int64, error) {
	info, err := os.Lstat(p)
	size, ok := intValue(expectedBytes)
	if err != nil || !info.Mode().IsRegular() || info.Sys().(*syscall.Stat_t).Nlink != 1 || !ok || info.Size() != int64(size) ||
		info.Size() <= 0 || info.Size() > maxImageBytes || !fullmatch(hex64, str(expectedSHA)) {
		return 0, Public("Untrusted OCI artifact metadata")
	}
	digest, err := fileSHA256(p)
	if err != nil || digest != str(expectedSHA) {
		return 0, Public("OCI artifact hash differs from reviewed builder output")
	}
	return info.Size(), nil
}

// verifyArchive checks a single OCI tar and its reachable digest graph.
func verifyArchive(p string, expectedSHA, expectedBytes any) (M, error) {
	size, err := checkArtifactFile(p, expectedSHA, expectedBytes)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	blobs := map[string]int64{}
	small := map[string][]byte{}
	content := map[string][]byte{}
	seen := map[string]bool{}
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, Public("OCI archive is invalid")
		}
		if len(seen) >= maxArchiveMembers {
			return nil, Public("OCI archive contains excessive members")
		}
		name := strings.TrimPrefix(h.Name, "./")
		if seen[name] {
			return nil, Public("Duplicate OCI archive entry")
		}
		seen[name] = true
		if h.Typeflag == tar.TypeDir {
			if n := strings.TrimRight(name, "/"); n != "blobs" && n != "blobs/sha256" {
				return nil, Public("Unexpected OCI directory metadata")
			}
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return nil, Public("OCI archive contains symbolic/hard links or special files")
		}
		isBlob := strings.HasPrefix(name, "blobs/sha256/") && fullmatch(hex64, strings.TrimPrefix(name, "blobs/sha256/"))
		if name != "oci-layout" && name != "index.json" && !isBlob {
			return nil, Public("Unexpected OCI archive path or member type")
		}
		if h.Size < 0 || h.Size > maxImageBytes {
			return nil, Public("OCI archive member exceeds budget")
		}
		hash := sha256.New()
		var buf bytes.Buffer
		w := io.Writer(hash)
		if h.Size <= maxManifestJSON {
			w = io.MultiWriter(hash, &buf)
		}
		n, err := io.Copy(w, tr)
		if err != nil || n != h.Size {
			return nil, Public("OCI archive member is truncated")
		}
		if isBlob {
			ident := strings.TrimPrefix(name, "blobs/sha256/")
			if ident != hex.EncodeToString(hash.Sum(nil)) {
				return nil, Public("OCI blob content digest does not match path")
			}
			blobs[ident] = h.Size
			if h.Size <= maxManifestJSON {
				content[ident] = buf.Bytes()
			}
		} else if h.Size <= maxManifestJSON {
			small[name] = buf.Bytes()
		} else {
			return nil, Public("OCI metadata exceeds size limit")
		}
	}
	if len(small) != 2 || small["oci-layout"] == nil || small["index.json"] == nil {
		return nil, Public("OCI archive lacks required descriptors")
	}
	layout, err := parseObject(small["oci-layout"])
	if err != nil || len(layout) != 1 || str(layout["imageLayoutVersion"]) != "1.0.0" {
		return nil, Public("Unsupported OCI image archive layout")
	}
	index, err := parseObject(small["index.json"])
	manifests := list(index["manifests"])
	if v, _ := num(index["schemaVersion"]); err != nil || v != 2 || len(manifests) != 1 {
		return nil, Public("Only a single-image OCI manifest is supported")
	}
	manifestID, err := ociRef(manifests[0])
	if err != nil {
		return nil, err
	}
	wantSize, _ := intValue(obj(manifests[0])["size"])
	if blobs[manifestID] != int64(wantSize) || content[manifestID] == nil {
		return nil, Public("OCI top-level manifest blob is missing")
	}
	manifest, err := parseObject(content[manifestID])
	layers := list(manifest["layers"])
	if v, _ := num(manifest["schemaVersion"]); err != nil || v != 2 || manifest["layers"] == nil || len(layers) > 128 {
		return nil, Public("Unsupported OCI image manifest")
	}
	for _, item := range append([]any{manifest["config"]}, layers...) {
		ident, err := ociRef(item)
		if err != nil {
			return nil, err
		}
		s, _ := intValue(obj(item)["size"])
		if got, ok := blobs[ident]; !ok || got != int64(s) {
			return nil, Public("OCI image config or layer missing from archive")
		}
	}
	configID, _ := ociRef(manifest["config"])
	if content[configID] == nil {
		return nil, Public("OCI image config is oversized")
	}
	image, err := parseObject(content[configID])
	if err != nil || (image["config"] != nil && obj(image["config"]) == nil) || !isStr(image["architecture"]) {
		return nil, Public("OCI image config is malformed")
	}
	config := obj(image["config"])
	if config == nil {
		config = M{}
	}
	return M{"sha256": expectedSHA, "bytes": size, "ociManifestDigest": manifestID, "blobs": len(blobs),
		"architecture": image["architecture"], "config": config}, nil
}

func rootfsMemberName(name string) (string, error) {
	if name == "." || name == "./" {
		return ".", nil
	}
	if !strings.HasPrefix(name, "./") {
		return "", Public("Rootfs member is not relative to the image root")
	}
	parts := strings.Split(strings.TrimRight(name[2:], "/"), "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return "", Public("Rootfs member path escapes or is not normalized")
		}
	}
	return strings.Join(parts, "/"), nil
}

// verifyRootfs checks the sandbox's flattened rootfs tar without extracting it.
func verifyRootfs(p string, expectedSHA, expectedBytes any) (M, error) {
	if _, err := checkArtifactFile(p, expectedSHA, expectedBytes); err != nil {
		if strings.Contains(publicError(err), "hash") {
			return nil, Public("Rootfs hash differs from builder output")
		}
		return nil, Public("Untrusted rootfs artifact metadata")
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	seen := map[string]bool{}
	accounts := map[string]string{}
	tr := tar.NewReader(f)
	for count := 0; ; count++ {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, Public("Rootfs archive is invalid")
		}
		if count >= maxRootfsEntries {
			return nil, Public("Rootfs contains excessive members")
		}
		name, err := rootfsMemberName(h.Name)
		if err != nil {
			return nil, err
		}
		if seen[name] && h.Typeflag != tar.TypeDir {
			return nil, Public("Duplicate rootfs member")
		}
		switch h.Typeflag {
		case tar.TypeLink:
			target, err := rootfsMemberName("./" + strings.TrimPrefix(h.Linkname, "./"))
			if err != nil || !seen[target] {
				return nil, Public("Rootfs hard link target is outside the archive")
			}
		case tar.TypeDir, tar.TypeReg, tar.TypeSymlink:
		default:
			return nil, Public("Rootfs contains device nodes, FIFOs or other special files")
		}
		if h.Mode&0o6000 != 0 && h.Uid != 0 {
			return nil, Public("Rootfs contains set-ID files owned by an unprivileged user")
		}
		seen[name] = true
		if (name == "etc/passwd" || name == "etc/group") && h.Typeflag == tar.TypeReg {
			if h.Size > 65536 {
				return nil, Public("Rootfs account database is oversized")
			}
			data, _ := io.ReadAll(tr)
			accounts[name] = strings.ToValidUTF8(string(data), "�")
		}
	}
	return M{"sha256": expectedSHA, "bytes": expectedBytes, "passwd": accounts["etc/passwd"], "group": accounts["etc/group"]}, nil
}

// --- Incus image import (#47) ------------------------------------------------

const defaultImagePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
const imageOwnerKey = "user.nixus.owner"
const imageBackendKey = "user.nixus.backend"
const composeBackend = "incus-compose"

var imageArchitectures = map[string]string{"amd64": "x86_64", "arm64": "aarch64"}
var localImage = re(`localhost/(nixus-[a-z0-9-]{1,50}):([0-9a-f]{1,64})`)
var envName = re(`[A-Za-z_][A-Za-z0-9_]*`)

func incusProjectName(name string) (string, error) {
	value := regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(name), "-")
	value = strings.Trim(regexp.MustCompile(`-+`).ReplaceAllString(value, "-"), "-")
	if value == "" {
		return "", Public("Project name has no Incus equivalent")
	}
	return value, nil
}

func aliasFor(image string) (string, error) {
	m := localImage.FindStringSubmatch(image)
	if m == nil || m[0] != image {
		return "", Public("Only reviewed local Nixus image references can be imported")
	}
	return "local/" + m[1] + ":" + m[2], nil
}

type accountRow []string

func accountRows(text string) []accountRow {
	var rows []accountRow
	for _, line := range strings.Split(text, "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 3 && fullmatch(re(`[0-9]+`), f[2]) {
			rows = append(rows, f)
		}
	}
	return rows
}

func atoiSafe(s string) int64 {
	var n int64
	for _, c := range s {
		n = n*10 + int64(c-'0')
		if n > 1<<40 {
			return n
		}
	}
	return n
}

func imageIdentity(value string, rows []accountRow, kind string) (int64, error) {
	var number int64
	if fullmatch(re(`[0-9]+`), value) {
		number = atoiSafe(value)
	} else {
		var found []int64
		for _, r := range rows {
			if r[0] == value {
				found = append(found, atoiSafe(r[2]))
			}
		}
		if len(found) != 1 {
			return 0, Public("Image " + kind + " is not a number and is not defined in the image")
		}
		number = found[0]
	}
	if number > 0xFFFFFFFE {
		return 0, Public("Image " + kind + " is out of range")
	}
	return number, nil
}

func imageStrings(v any, label string) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	l, ok := anyStrings(v)
	if !ok || len(l) > 256 {
		return nil, Public("Image " + label + " must be a list of strings")
	}
	return l, nil
}

func runtimeSpec(config M, passwd, group string) ([]byte, error) {
	if config == nil {
		return nil, Public("Image config is malformed")
	}
	entry, err := imageStrings(config["Entrypoint"], "entrypoint")
	if err != nil {
		return nil, err
	}
	cmd, err := imageStrings(config["Cmd"], "command")
	if err != nil {
		return nil, err
	}
	args := append(entry, cmd...)
	if len(args) == 0 {
		return nil, Public("Image defines no ENTRYPOINT or CMD to run")
	}
	users, groups := accountRows(passwd), accountRows(group)
	user, ok := config["User"].(string)
	if config["User"] != nil && !ok {
		return nil, Public("Image user is malformed")
	}
	name, groupName, _ := strings.Cut(user, ":")
	var uid, gid int64
	if name != "" {
		if uid, err = imageIdentity(name, users, "user"); err != nil {
			return nil, err
		}
	}
	if groupName != "" {
		if gid, err = imageIdentity(groupName, groups, "group"); err != nil {
			return nil, err
		}
	} else {
		for _, r := range users {
			if atoiSafe(r[2]) == uid && len(r) > 3 && fullmatch(re(`[0-9]+`), r[3]) {
				gid = atoiSafe(r[3])
				break
			}
		}
	}
	env := []string{"PATH=" + defaultImagePath, "TERM=xterm"}
	extra, err := imageStrings(config["Env"], "environment")
	if err != nil {
		return nil, err
	}
	for _, e := range extra {
		key, _, has := strings.Cut(e, "=")
		if !has || !fullmatch(envName, key) {
			return nil, Public("Image environment entry is malformed")
		}
		var kept []string
		for _, x := range env {
			if !strings.HasPrefix(x, key+"=") {
				kept = append(kept, x)
			}
		}
		env = append(kept, e)
	}
	hasHome := false
	for _, e := range env {
		hasHome = hasHome || strings.HasPrefix(e, "HOME=")
	}
	if !hasHome {
		for _, r := range users {
			if atoiSafe(r[2]) == uid && len(r) > 5 && r[5] != "" {
				env = append(env, "HOME="+r[5])
				break
			}
		}
	}
	cwd := "/"
	if v, ok := config["WorkingDir"]; ok && v != nil && v != "" {
		s, ok := v.(string)
		if !ok || !strings.HasPrefix(s, "/") {
			return nil, Public("Image working directory must be absolute")
		}
		cwd = s
	}
	spec := M{"ociVersion": "1.2.0", "process": M{"args": strings2any(args), "env": strings2any(env), "cwd": cwd,
		"user": M{"uid": uid, "gid": gid}}}
	return []byte(canonical(spec)), nil
}

func metadataTar(image, architecture string, created int64, configJSON []byte) ([]byte, error) {
	arch, ok := imageArchitectures[architecture]
	if !ok {
		return nil, Public("Unsupported image architecture")
	}
	if created < 0 {
		return nil, Public("Image creation time is malformed")
	}
	metadata := []byte(canonical(M{"architecture": arch, "creation_date": created,
		"properties": M{"description": image + " (built by Nixus)", "type": "oci"}}))
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range []struct {
		name string
		data []byte
	}{{"metadata.yaml", metadata}, {"config.json", configJSON}} {
		tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.data)), ModTime: time.Unix(created, 0),
			Typeflag: tar.TypeReg, Format: tar.FormatPAX})
		tw.Write(f.data)
	}
	tw.Close()
	return buf.Bytes(), nil
}

func imageFingerprint(metadataPath, rootfsPath string) (string, error) {
	h := sha256.New()
	for _, p := range []string{metadataPath, rootfsPath} {
		f, err := os.Open(p)
		if err != nil {
			return "", err
		}
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type incusFunc func(timeout time.Duration, args ...string) (string, error)

func defaultIncus(timeout time.Duration, args ...string) (string, error) {
	if timeout == 0 {
		timeout = 600 * time.Second
	}
	return opIncus(timeout, args...)
}

func incusQueryObj(incus incusFunc, p string) M {
	out, err := incus(0, "query", p)
	if err != nil {
		return nil
	}
	m, err := parseObject([]byte(out))
	if err != nil {
		return nil
	}
	return m
}

func ensureComposeProject(project string, incus incusFunc) error {
	if project == "default" || project == "lab" {
		return Public("Compose apps never use the default or host-owned lab Incus project")
	}
	current := incusQueryObj(incus, "/1.0/projects/"+project)
	if current == nil {
		_, err := incus(0, "project", "create", project, "-c", "features.images=true", "-c", "features.profiles=true",
			"-c", imageOwnerKey+"=true", "-c", imageBackendKey+"="+composeBackend)
		return err
	}
	config := obj(current["config"])
	if str(config[imageOwnerKey]) != "true" || str(config[imageBackendKey]) != composeBackend {
		return Public("The Incus project is not owned by Nixus for Compose; refusing to adopt it")
	}
	if str(config["features.images"]) != "true" {
		return Public("The Incus project shares the default image store; refusing to import into it")
	}
	return nil
}

var importedFingerprint = regexp.MustCompile(`fingerprint: ([0-9a-f]{64})`)

func importImage(project, alias, expected, metadataPath, rootfsPath string, incus incusFunc) (M, error) {
	if !fullmatch(hex64, expected) {
		return nil, Public("Expected image fingerprint is malformed")
	}
	suffix := "?project=" + project
	if incusQueryObj(incus, "/1.0/images/"+expected+suffix) == nil {
		out, err := incus(1800*time.Second, "image", "import", metadataPath, rootfsPath, "--project", project)
		if err != nil {
			return nil, err
		}
		if m := importedFingerprint.FindStringSubmatch(out); m != nil && m[1] != expected {
			incus(0, "image", "delete", m[1], "--project", project)
			return nil, Public("Incus computed a different image fingerprint; the import was removed")
		}
		if incusQueryObj(incus, "/1.0/images/"+expected+suffix) == nil {
			return nil, Public("Incus did not store the image under the expected fingerprint")
		}
	}
	image := incusQueryObj(incus, "/1.0/images/"+expected+suffix)
	if str(jget(image, "properties", "type")) != "oci" {
		return nil, Public("Imported image is not marked as an OCI image")
	}
	current := incusQueryObj(incus, "/1.0/images/aliases/"+alias+suffix)
	if current == nil {
		if _, err := incus(0, "image", "alias", "create", alias, expected, "--project", project); err != nil {
			return nil, err
		}
	} else if str(current["target"]) != expected {
		return nil, Public("The image alias already points at different content; refusing to move it")
	}
	return M{"alias": alias, "fingerprint": expected, "incusProject": project}, nil
}

// --- builder child (runs inside bubblewrap as the unprivileged builder) -------

const childContext = "/context"
const childWork = "/work"
const childOutput = "/out"
const childPolicyPath = "/work/policy.json"

var childPolicy = M{"default": []any{M{"type": "reject"}}, "transports": M{
	"containers-storage": M{"": []any{M{"type": "insecureAcceptAnything"}}},
	"oci-archive":        M{"": []any{M{"type": "insecureAcceptAnything"}}}}}

func childExec(argv []string, timeout time.Duration, cwd string) ([]byte, error) {
	env := []string{"PATH=" + os.Getenv("NIXUS_OCI_PATH"), "HOME=/work/home", "TMPDIR=/work/tmp", "XDG_RUNTIME_DIR=/work/run",
		"XDG_CONFIG_HOME=/work/config", "CONTAINERS_STORAGE_CONF=/work/storage.conf", "BUILDAH_ISOLATION=chroot"}
	res, err := run(argv, nil, timeout, env, cwd)
	if err != nil || res.Code != 0 {
		if os.Getenv("NIXUS_OCI_VM_TEST") == "1" {
			fmt.Fprintln(os.Stderr, "OCI-VM-CHILD-TOOL:", strings.Join(argv, " "), string(res.Stderr))
		}
		return nil, Public("Isolated OCI tool refused the pinned build or Compose configuration")
	}
	if len(res.Stdout) > maxManifestJSON {
		return nil, Public("Compose validation result is too large")
	}
	return res.Stdout, nil
}

func childComposeJSON(spec M, extra string) (M, error) {
	compose := os.Getenv("NIXUS_OCI_COMPOSE_BIN")
	var flags []string
	if e := str(spec["entrypoint"]); e != "" {
		flags = []string{"-f", childContext + "/" + e}
	}
	if g := str(spec["generatedCompose"]); g != "" {
		original := path.Dir(str(spec["entrypoint"]))
		relative, absolute := "./"+original, "/context/"+original
		if original == "." {
			relative, absolute = ".", "/context"
		}
		expected := "context: " + jsonString(relative)
		if strings.Count(g, expected) != 1 {
			return nil, Public("Reviewed Dockerfile context differs from generated launch manifest")
		}
		generated := filepath.Join(childWork, "generated.yaml")
		if err := os.WriteFile(generated, []byte(strings.Replace(g, expected, "context: "+jsonString(absolute), 1)), 0o600); err != nil {
			return nil, err
		}
		flags = []string{"-f", generated}
	}
	if extra != "" {
		flags = append(flags, "-f", extra)
	}
	base := append([]string{compose, "-p", str(spec["project"])}, flags...)
	if _, err := childExec(append(append([]string{}, base...), "config", "--quiet"), 30*time.Second, childContext); err != nil {
		return nil, err
	}
	out, err := childExec(append(append([]string{}, base...), "config", "--format", "json"), 30*time.Second, childContext)
	if err != nil {
		return nil, err
	}
	m, err := parseObject(out)
	if err != nil {
		return nil, Public("Pinned Compose parser produced an invalid model")
	}
	return m, nil
}

func childModel(spec M) (M, error) {
	original, err := childComposeJSON(spec, "")
	if err != nil {
		return nil, err
	}
	files, err := checkFiles(spec["sourceFiles"])
	if err != nil {
		return nil, err
	}
	composePath := str(spec["entrypoint"])
	if composePath == "" {
		composePath = "."
	}
	checked, err := validateComposeModel(original, str(spec["project"]), str(spec["revision"]), composePath, files)
	if err != nil {
		return nil, err
	}
	if override := str(checked["separateOverride"]); override != "" {
		extra := filepath.Join(childWork, "generated-override.yaml")
		os.WriteFile(extra, []byte(override), 0o600)
		patched, err := childComposeJSON(spec, extra)
		if err != nil {
			return nil, err
		}
		services := obj(patched["services"])
		for _, raw := range list(checked["services"]) {
			item := obj(raw)
			after := obj(services[str(item["service"])])
			if isTrue(item["built"]) && (str(after["image"]) != str(item["image"]) || after["build"] != nil) {
				return nil, Public("Compose override did not disable implicit builds")
			}
		}
	}
	return checked, nil
}

func childDigest(p string) (M, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxImageBytes+1))
	if err != nil || n > maxImageBytes {
		return nil, Public("OCI archive exceeds per-service artifact quota")
	}
	return M{"sha256": hex.EncodeToString(h.Sum(nil)), "bytes": n}, nil
}

// exportRootfs flattens the built image (vfs: mount is a plain directory) into
// a deterministic tar: sorted members, root ownership, no special files.
func exportRootfs(storage []string, image, name string) (string, error) {
	container := "nixus-export-" + name
	if _, err := childExec(append(append([]string{}, storage...), "from", "--signature-policy", childPolicyPath, "--pull=never",
		"--name", container, image), 300*time.Second, childContext); err != nil {
		return "", err
	}
	out, err := childExec(append(append([]string{}, storage...), "mount", container), 60*time.Second, childContext)
	if err != nil {
		return "", err
	}
	mount := strings.TrimSpace(string(out))
	storageRoot := filepath.Join(childWork, "storage-"+name)
	if !filepath.IsAbs(mount) || !strings.HasPrefix(mount, storageRoot+"/") || isSymlink(mount) {
		return "", Public("Buildah returned an unexpected rootfs location")
	}
	archive := filepath.Join(childOutput, name+".rootfs.tar")
	f, err := os.Create(archive)
	if err != nil {
		return "", err
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	inodes := map[uint64]string{}
	walkErr := filepath.WalkDir(mount, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(mount, p)
		name := "."
		if rel != "." {
			name = "./" + filepath.ToSlash(rel)
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st := info.Sys().(*syscall.Stat_t)
		h := &tar.Header{Name: name, Mode: int64(info.Mode().Perm() | info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky)>>0),
			ModTime: info.ModTime(), Format: tar.FormatPAX}
		h.Mode = int64(st.Mode & 0o7777)
		switch {
		case info.IsDir():
			h.Typeflag = tar.TypeDir
		case info.Mode()&os.ModeSymlink != 0:
			h.Typeflag = tar.TypeSymlink
			h.Linkname, _ = os.Readlink(p)
		case info.Mode().IsRegular():
			if st.Nlink > 1 {
				if first, ok := inodes[st.Ino]; ok {
					h.Typeflag, h.Linkname = tar.TypeLink, first
					return tw.WriteHeader(h)
				}
				inodes[st.Ino] = name
			}
			h.Typeflag, h.Size = tar.TypeReg, info.Size()
		default:
			return Public("Built image contains device nodes, FIFOs or sockets")
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if h.Typeflag == tar.TypeReg {
			in, err := os.Open(p)
			if err != nil {
				return err
			}
			defer in.Close()
			_, err = io.Copy(tw, in)
			return err
		}
		return nil
	})
	if walkErr != nil {
		return "", walkErr
	}
	if err := tw.Close(); err != nil {
		return "", err
	}
	return archive, nil
}

func childBuild(spec M) (M, error) {
	checked, err := childModel(spec)
	if err != nil {
		return nil, err
	}
	if str(checked["intentHash"]) != str(spec["intentHash"]) {
		return nil, Public("Source-qualified Compose review differs inside the sandbox")
	}
	raw, _ := json.Marshal(childPolicy)
	os.WriteFile(childPolicyPath, raw, 0o600)
	tool := os.Getenv("NIXUS_OCI_BUILDAH_BIN")
	records := []any{}
	for _, rawSvc := range list(checked["services"]) {
		svc := obj(rawSvc)
		if !isTrue(svc["built"]) {
			continue
		}
		name := str(svc["service"])
		if !fullmatch(composeServiceName, name) {
			return nil, Public("Unsafe service identity")
		}
		storage := []string{tool, "--root", "/work/storage-" + name, "--runroot", "/work/run-" + name, "--storage-driver", "vfs"}
		dockerfile := childContext + "/" + str(svc["dockerfile"])
		if bases := list(spec["bases"]); len(bases) > 0 {
			for _, rawBase := range bases {
				b := obj(rawBase)
				if !fullmatch(re(`/work/bases/[0-9a-f]{64}\.tar`), str(b["archive"])) || !fullmatch(re(`localhost/nixus-base-[0-9a-f]{16}:pinned`), str(b["local"])) {
					return nil, Public("Invalid pinned base image record")
				}
				out, err := childExec(append(append([]string{}, storage...), "pull", "--signature-policy", childPolicyPath, "--quiet",
					"oci-archive:"+str(b["archive"])), 600*time.Second, childContext)
				if err != nil {
					return nil, err
				}
				if _, err := childExec(append(append([]string{}, storage...), "tag", strings.TrimSpace(string(out)), str(b["local"])), 60*time.Second, childContext); err != nil {
					return nil, err
				}
			}
			original, err := os.ReadFile(dockerfile)
			if err != nil {
				return nil, Public("Reviewed Dockerfile is unreadable in the sandbox")
			}
			dockerfile = "/work/Dockerfile-" + name
			if err := os.WriteFile(dockerfile, []byte(rewriteBases(string(original), bases)), 0o600); err != nil {
				return nil, err
			}
		}
		if _, err := childExec(append(append([]string{}, storage...), "bud", "--signature-policy", childPolicyPath, "--isolation", "chroot",
			"--network=host", "--pull=never", "--layers=false", "-f", dockerfile, "--tag", str(svc["image"]),
			childContext+"/"+str(svc["context"])), 1200*time.Second, childContext); err != nil {
			return nil, err
		}
		archive := filepath.Join(childOutput, name+".oci.tar")
		if _, err := childExec(append(append([]string{}, storage...), "push", "--signature-policy", childPolicyPath, "--format", "oci",
			str(svc["image"]), "oci-archive:"+archive+":"+str(svc["image"])), 300*time.Second, childContext); err != nil {
			return nil, err
		}
		record, err := childDigest(archive)
		if err != nil {
			return nil, err
		}
		flat, err := exportRootfs(storage, str(svc["image"]), name)
		if err != nil {
			return nil, err
		}
		rootfs, err := childDigest(flat)
		if err != nil {
			return nil, err
		}
		records = append(records, M{"service": name, "image": svc["image"], "artifact": name + ".oci.tar", "sha256": record["sha256"],
			"bytes": record["bytes"], "rootfs": name + ".rootfs.tar", "rootfsSha256": rootfs["sha256"], "rootfsBytes": rootfs["bytes"]})
	}
	if len(records) == 0 {
		return nil, Public("No locally built services in the reviewed source")
	}
	output := M{"format": 1, "project": spec["project"], "revision": spec["revision"], "intentHash": checked["intentHash"], "artifacts": records}
	return output, os.WriteFile(filepath.Join(childOutput, "build-result.json"), []byte(canonicalSpaced(output)), 0o600)
}

// ociChildMain is `nixus oci-child {inspect|build} /work/intent.json`.
func ociChildMain(args []string) int {
	err := func() error {
		if len(args) != 2 || (args[0] != "inspect" && args[0] != "build") {
			return Public("Expected isolated OCI inspect or build operation")
		}
		raw, err := os.ReadFile(args[1])
		if err != nil || len(raw) > maxManifestJSON {
			return Public("OCI build intent exceeds bounded source quota")
		}
		spec, err := parseObject(raw)
		if err != nil {
			return err
		}
		if v, _ := num(spec["format"]); v != 1 || !fullmatch(composeServiceName, str(spec["project"])) ||
			!fullmatch(hex64, str(spec["revision"])) || list(spec["sourceFiles"]) == nil {
			return Public("Invalid immutable OCI source intent")
		}
		if args[0] == "inspect" {
			plan, err := childModel(spec)
			if err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(childOutput, "intent.json"), []byte(canonicalSpaced(plan)), 0o600)
		}
		_, err = childBuild(spec)
		return err
	}()
	if err != nil {
		if os.Getenv("NIXUS_OCI_VM_TEST") == "1" {
			fmt.Fprintln(os.Stderr, "OCI-VM-CHILD-FAILURE:", err)
		} else {
			fmt.Fprintln(os.Stderr, "Isolated OCI operation refused; inspect the reviewed source and policy")
		}
		return 1
	}
	return 0
}
