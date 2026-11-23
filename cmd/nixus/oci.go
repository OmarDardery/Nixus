package main

// OCI source planning, Compose secret classification and model validation,
// and the pinned incus-compose parse of a reviewed source.

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
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
			return Public("Move " + k + " to the app's Env tab; secret-like variables are not allowed in compose.yaml")
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
			lines = append(lines, "    image: "+jsonString(str(svc["image"])))
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

const maxManifestJSON = 1024 * 1024

const imageOwnerKey = "user.nixus.owner"
const imageBackendKey = "user.nixus.backend"
const composeBackend = "incus-compose"

func incusProjectName(name string) (string, error) {
	value := regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(name), "-")
	value = strings.Trim(regexp.MustCompile(`-+`).ReplaceAllString(value, "-"), "-")
	if value == "" {
		return "", Public("Project name has no Incus equivalent")
	}
	return value, nil
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

// --- Compose model (parsed by the pinned incus-compose, then validated) --------

// composeExec runs the pinned compose binary for parsing only; it never talks
// to Incus and gets a minimal environment.
func composeExec(argv []string, cwd string) ([]byte, error) {
	res, err := run(argv, nil, 30*time.Second, []string{"PATH=" + os.Getenv("NIXUS_OCI_PATH"), "HOME=" + cwd}, cwd)
	if err != nil || res.Code != 0 {
		fmt.Fprintln(os.Stderr, "nixus: compose parse failed:", string(res.Stderr))
		return nil, Public("The Compose file could not be parsed: " + lastLine(string(res.Stderr)))
	}
	if len(res.Stdout) > maxManifestJSON {
		return nil, Public("Compose validation result is too large")
	}
	return res.Stdout, nil
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	if len(last) > 240 {
		last = last[:240]
	}
	return last
}

// composeJSON renders the canonical model of the reviewed source in dir.
func composeJSON(spec M, dir, scratch, extra string) (M, error) {
	compose := os.Getenv("NIXUS_OCI_COMPOSE_BIN")
	if compose == "" {
		compose = "incus-compose"
	}
	var flags []string
	if e := str(spec["entrypoint"]); e != "" {
		flags = []string{"-f", filepath.Join(dir, e)}
	}
	if g := str(spec["generatedCompose"]); g != "" {
		original := path.Dir(str(spec["entrypoint"]))
		relative, absolute := "./"+original, dir+"/"+original
		if original == "." {
			relative, absolute = ".", dir
		}
		expected := "context: " + jsonString(relative)
		if strings.Count(g, expected) != 1 {
			return nil, Public("Reviewed Dockerfile context differs from generated launch manifest")
		}
		generated := filepath.Join(scratch, "generated.yaml")
		if err := os.WriteFile(generated, []byte(strings.Replace(g, expected, "context: "+jsonString(absolute), 1)), 0o600); err != nil {
			return nil, err
		}
		flags = []string{"-f", generated}
	}
	if extra != "" {
		flags = append(flags, "-f", extra)
	}
	base := append([]string{compose, "-p", str(spec["project"]), "-P", dir}, flags...)
	if _, err := composeExec(append(append([]string{}, base...), "config", "--quiet"), dir); err != nil {
		return nil, err
	}
	out, err := composeExec(append(append([]string{}, base...), "config", "--format", "json"), dir)
	if err != nil {
		return nil, err
	}
	// The model names paths under the materialised source; validation expects
	// them under the fixed /context root.
	m, err := parseObject([]byte(strings.ReplaceAll(string(out), dir, "/context")))
	if err != nil {
		return nil, Public("Pinned Compose parser produced an invalid model")
	}
	return m, nil
}

// composeModel parses and validates the reviewed source materialised in dir.
func composeModel(spec M, dir, scratch string) (M, error) {
	original, err := composeJSON(spec, dir, scratch, "")
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
	return validateComposeModel(original, str(spec["project"]), str(spec["revision"]), composePath, files)
}
