package main

// Environment variables per app, Portainer style. Values live in the app's
// SOPS file (encrypted at rest and in backups) and are injected as real
// container environment variables through the Incus local socket, so they
// never appear in process arguments. A container restarts when its values
// change; /run/secrets files are still written for *_FILE images.

import (
	"sort"
	"strings"
	"time"
)

const envKeysConfig = "user.nixus.env-keys"

// envAPI calls the local Incus REST API and returns metadata and ETag.
var envAPI = func(method, path string, body any, etag string) (M, string, error) {
	payload, tag, err := reconcileAPI(method, path, body, etag)
	if err != nil {
		return nil, "", Public("Incus refused the environment change")
	}
	// PUT is asynchronous; a restart before it finishes is refused as busy.
	if err := waitOperation(payload); err != nil {
		return nil, "", Public("Incus did not apply the environment change")
	}
	return obj(payload["metadata"]), tag, nil
}

// envPatch computes the instance config change that makes Nixus-managed
// environment variables equal to values. Image/Compose-defined variables are
// left alone; variables Nixus set earlier and no longer has are removed.
func envPatch(config M, values M) (M, bool) {
	previous := map[string]bool{}
	for _, k := range strings.Split(str(config[envKeysConfig]), ",") {
		if k != "" {
			previous[k] = true
		}
	}
	patch := M{}
	changed := false
	names := keys(values)
	for _, k := range names {
		if str(config["environment."+k]) != str(values[k]) || config["environment."+k] == nil {
			patch["environment."+k] = values[k]
			changed = true
		}
	}
	for k := range previous {
		if _, ok := values[k]; !ok {
			patch["environment."+k] = ""
			changed = true
		}
	}
	sort.Strings(names)
	if joined := strings.Join(names, ","); joined != str(config[envKeysConfig]) {
		patch[envKeysConfig] = joined
		changed = true
	}
	return patch, changed
}

// injectEnv applies values to one instance, restarting a running container
// when anything changed.
var injectEnv = func(incusProject, instance string, values M) (bool, error) {
	path := instancePath(incusProject, instance)
	current, etag, err := envAPI("GET", path, nil, "")
	if err != nil {
		return false, err
	}
	patch, changed := envPatch(obj(current["config"]), values)
	if !changed {
		return false, nil
	}
	config := cloneM(obj(current["config"]))
	for k, v := range patch {
		if str(v) == "" && strings.HasPrefix(k, "environment.") {
			delete(config, k)
		} else {
			config[k] = v
		}
	}
	current["config"] = config
	put := M{}
	for _, k := range []string{"architecture", "config", "devices", "ephemeral", "profiles", "stateful", "description"} {
		if v, ok := current[k]; ok {
			put[k] = v
		}
	}
	if _, _, err := envAPI("PUT", path, put, etag); err != nil {
		return false, err
	}
	if str(current["status"]) == "Running" && str(current["type"]) == "container" {
		if _, err := updateIncus(3*time.Minute, "restart", instance, "--project", incusProject); err != nil {
			return true, Public("Could not restart " + instance + " to apply its environment")
		}
	}
	return true, nil
}

// --- console API -----------------------------------------------------------------------

func envNames(project any) (M, error) {
	s := NewSecrets("", "", "")
	dir, err := s.project(project)
	if err != nil {
		return M{"keys": []any{}}, nil
	}
	index, err := s.metadata(str(project))
	if err != nil {
		return nil, err
	}
	_ = dir
	return M{"keys": index["keys"], "revision": index["revision"]}, nil
}

// readEnv returns an app's variables with values (reauthenticated).
func readEnv(project any) (M, error) {
	s := NewSecrets("", "", "")
	dir, err := s.project(project)
	if err != nil {
		return nil, Public("Deploy the app before adding environment variables")
	}
	ciphertext, err := s.cipher(dir)
	if err != nil {
		return nil, err
	}
	values, err := s.decode(ciphertext, "")
	if err != nil {
		return nil, err
	}
	return M{"vars": values, "revision": hashOrNil(ciphertext)}, nil
}

// saveEnv replaces an app's variables, publishes the ciphertext and applies it.
func saveEnv(actor string, project, vars, revision any) (M, error) {
	m, ok := vars.(M)
	if !ok {
		return nil, Public("Invalid variables")
	}
	if _, err := NewSecrets("", "", "").recipient(); err != nil {
		return nil, Public("Create the secrets encryption key first: Backups → Encryption key & recovery kit")
	}
	result, err := lockedValue(false, func() (M, error) {
		s := NewSecrets("", "", "")
		review, err := s.review(actor, project, nil, "replace", m, revision)
		if err != nil {
			return nil, err
		}
		return s.publish(actor, review["reviewId"], true)
	})
	if err != nil {
		return nil, err
	}
	result["delivery"] = deliverPublishedSecrets(str(project))
	return result, nil
}
