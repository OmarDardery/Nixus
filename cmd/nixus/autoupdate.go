package main

// Image update transactions (#61). An update re-pins the newer digests in the
// published source, rebuilds offline, snapshots the project's custom volumes,
// deploys through a reviewed project revision and health-gates the result.
// Any failure after publication rolls back: the previous source is published
// again, volumes are restored from the snapshot, the previous images are
// redeployed and the failed digests are held so they are not retried.

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

var updateWindowRe = re(`([01][0-9]|2[0-3]):([0-5][0-9])-([01][0-9]|2[0-3]):([0-5][0-9])`)

// validateUpdatePolicy checks the optional per-project `updates` declaration.
func validateUpdatePolicy(raw any) error {
	if raw == nil {
		return nil
	}
	p := obj(raw)
	fail := Public("Invalid project image update policy")
	if !exactKeys(p, "policy", "window", "healthSeconds") {
		return fail
	}
	switch str(p["policy"]) {
	case "manual", "notify", "auto":
	default:
		return fail
	}
	if p["window"] != nil && !fullmatch(updateWindowRe, str(p["window"])) {
		return fail
	}
	if n, ok := intValue(p["healthSeconds"]); !ok || n < 5 || n > 3600 {
		return fail
	}
	return nil
}

func projectUpdatePolicy(project M) M {
	if u := obj(project["updates"]); u != nil {
		return u
	}
	return M{"policy": "manual", "window": nil, "healthSeconds": 60}
}

// inWindow reports whether t (local time) falls inside "HH:MM-HH:MM"; windows
// may wrap midnight. An empty window means any time.
func inWindow(window string, t time.Time) bool {
	m := updateWindowRe.FindStringSubmatch(window)
	if window == "" || m == nil {
		return window == ""
	}
	minutes := func(h, mm string) int { a, _ := strconv.Atoi(h); b, _ := strconv.Atoi(mm); return a*60 + b }
	start, end, at := minutes(m[1], m[2]), minutes(m[3], m[4]), t.Hour()*60+t.Minute()
	if start <= end {
		return at >= start && at < end
	}
	return at >= start || at < end
}

// --- holds ---------------------------------------------------------------------------

var imageHoldsPath = func() string { return filepath.Join(STATE, "image-update-holds.json") }

func heldDigests(project string) map[string]bool {
	out := map[string]bool{}
	for digest := range obj(obj(readObj(imageHoldsPath())[project])) {
		out[digest] = true
	}
	return out
}

func setHold(actor string, projectArg, digestArg any, hold bool, reason string) (M, error) {
	project, ok1 := projectArg.(string)
	digest, ok2 := digestArg.(string)
	if !ok1 || !ok2 || !fullmatch(projectName, project) || !digestRe.MatchString(digest) {
		return nil, Public("Choose a project and an image digest")
	}
	return lockedValue(false, func() (M, error) {
		holds := readObj(imageHoldsPath())
		if holds == nil {
			holds = M{}
		}
		entries := obj(holds[project])
		if entries == nil {
			entries = M{}
		}
		if hold {
			entries[digest] = M{"reason": reason, "actor": actor, "at": now()}
		} else {
			delete(entries, digest)
		}
		holds[project] = entries
		if err := writeJSONMode(imageHoldsPath(), holds, 0o640, ""); err != nil {
			return nil, err
		}
		audit("image-update-hold", M{"principal": actor, "project": project, "digest": digest, "hold": hold, "reason": reason})
		return M{"project": project, "digest": digest, "held": hold}, nil
	})
}

// --- journal ---------------------------------------------------------------------------

func updateJournalPath(project string) string {
	return filepath.Join(STATE, "image-update-"+project+".json")
}

func updateJournal(project string) M { return readObj(updateJournalPath(project)) }

// --- helpers ---------------------------------------------------------------------------

// publishStaged reviews and publishes sealed staged source as the project's
// current revision.
func publishStaged(actor string, staged M) (string, error) {
	out, err := lockedValue(false, func() (M, error) {
		staging, err := NewImportStaging("")
		if err != nil {
			return nil, err
		}
		publisher := NewPublishedSources("")
		review, err := publisher.review(staging, staged["id"], actor, staged["manifestHash"])
		if err != nil {
			return nil, err
		}
		return publisher.publish(staging, staged["id"], actor, review["reviewId"], true)
	})
	if err != nil {
		return "", err
	}
	return str(out["revision"]), nil
}

// republish makes a retained earlier revision current again through the
// normal stage, review and publish path.
func republish(actor, project, revision string) error {
	publisher := NewPublishedSources("")
	folder := filepath.Join(publisher.root, project, "revisions", revision)
	files, err := checkFiles(readObj(filepath.Join(folder, "manifest.json"))["files"])
	if err != nil {
		return err
	}
	contents := map[string][]byte{}
	entries := []any{}
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(folder, "source", f.Path))
		if err != nil || sha256hex(data) != f.SHA256 {
			return Public("The previous source revision is damaged; restore it from backup")
		}
		contents[f.Path] = data
		entries = append(entries, f.M())
	}
	staged, err := stageFiles(actor, project, entries, files, contents)
	if err != nil {
		return err
	}
	got, err := publishStaged(actor, staged)
	if err != nil {
		return err
	}
	if got != revision {
		return Public("Republished source does not match the previous revision")
	}
	return nil
}

func stageFiles(actor, project string, entries []any, files []sourceEntry, contents map[string][]byte) (M, error) {
	return lockedValue(false, func() (M, error) {
		staging, err := NewImportStaging("")
		if err != nil {
			return nil, err
		}
		candidate, err := staging.prepare(actor, project, entries, false)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			data := contents[f.Path]
			for off := 0; off < len(data); off += importMaxChunk {
				end := min(off+importMaxChunk, len(data))
				if _, err := staging.chunk(candidate["id"], actor, f.Path, float64(off), b64(data[off:end])); err != nil {
					return nil, err
				}
			}
		}
		return staging.finish(candidate["id"], actor, candidate["manifestHash"])
	})
}

var updatePoll = 3 * time.Second

// buildRevision reviews a published revision so it can be deployed. Images are
// pulled or built by incus-compose when the project is brought up.
func buildRevision(actor, project, revision string) (string, error) {
	builds := NewOCIBuilds("", nil)
	if builds.imported(project, revision) != nil {
		return "", nil
	}
	review, err := builds.review(project, revision, actor)
	if err != nil {
		return "", err
	}
	return str(review["id"]), nil
}

// deployRevision binds the project to a published source revision through a
// reviewed project transaction and waits for the deployment to verify.
func deployRevision(actor, project, revision string) (string, error) {
	return deployChange(actor, M{}, M{project: revision})
}

// healthy waits healthSeconds, then requires every service to run the
// reviewed images and not report unhealthy via ic-healthd.
var healthy = func(project, incusProject, revision string, seconds int) error {
	time.Sleep(time.Duration(seconds) * time.Second)
	observed, err := composeAdapterFactory().observe(project, incusProject, revision)
	if err != nil {
		return err
	}
	if str(observed["action"]) != "noop" {
		return Public("Services are not all running the updated images after the health period")
	}
	for _, raw := range obj(observed["instances"]) {
		if health := strings.ToLower(str(obj(raw)["health"])); health == "unhealthy" {
			return Public("One or more services reported unhealthy after the update")
		}
	}
	return nil
}

type volumeSnapshot struct{ Pool, Volume, Name string }

// updateIncus runs Incus for update transactions and logs the hidden stderr of
// a failing call to the root-only journal.
var updateIncus incusFunc = func(timeout time.Duration, args ...string) (string, error) {
	if timeout == 0 {
		timeout = 600 * time.Second
	}
	out, err := incusRun(args, timeout, 2000)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nixus: incus", strings.Join(args, " "), "failed:", err)
		return "", Public("Incus operation failed")
	}
	return out, nil
}

func customVolumes(incus incusFunc, project string) ([]volumeSnapshot, error) {
	out, err := incus(0, "storage", "list", "--format=json")
	if err != nil {
		return nil, Failed("Could not list storage pools", err)
	}
	var vols []volumeSnapshot
	for _, rawPool := range list(must(parseJSON([]byte(out)))) {
		pool := str(obj(rawPool)["name"])
		listed, err := incus(0, "storage", "volume", "list", pool, "--project", project, "--format=json")
		if err != nil {
			return nil, Failed("Could not list the volumes of pool "+pool, err)
		}
		for _, raw := range list(must(parseJSON([]byte(listed)))) {
			v := obj(raw)
			if str(v["type"]) == "custom" && !strings.Contains(str(v["name"]), "/") {
				vols = append(vols, volumeSnapshot{Pool: pool, Volume: str(v["name"])})
			}
		}
	}
	sort.Slice(vols, func(i, j int) bool { return vols[i].Pool+"/"+vols[i].Volume < vols[j].Pool+"/"+vols[j].Volume })
	return vols, nil
}

func snapshotVolumes(incus incusFunc, project, name string) ([]volumeSnapshot, error) {
	vols, err := customVolumes(incus, project)
	if err != nil {
		return nil, err
	}
	for i := range vols {
		vols[i].Name = name
		if _, err := incus(0, "storage", "volume", "snapshot", "create", vols[i].Pool, vols[i].Volume, name, "--project", project); err != nil {
			fmt.Fprintln(os.Stderr, "nixus: volume snapshot failed:", err)
			return nil, Public("Could not snapshot volume " + vols[i].Volume + "; nothing was changed")
		}
	}
	return vols, nil
}

func restoreVolumes(incus incusFunc, project string, snaps []volumeSnapshot) error {
	if len(snaps) == 0 {
		return nil
	}
	for _, inst := range appInstances(incus, project) {
		if err := setComposeStopped(incus, project, str(inst["name"]), true); err != nil {
			return err
		}
		if str(inst["status"]) == "Running" {
			if _, err := incus(0, "stop", str(inst["name"]), "--project", project, "--force"); err != nil {
				return Public("Could not stop the app before restoring its volumes")
			}
		}
	}
	for _, s := range snaps {
		if _, err := incus(0, "storage", "volume", "snapshot", "restore", s.Pool, s.Volume, s.Name, "--project", project); err != nil {
			fmt.Fprintln(os.Stderr, "nixus: volume restore failed:", err)
			return Failed("Could not restore volume "+s.Volume+" from snapshot "+s.Name, err)
		}
	}
	return nil
}

// --- the transaction -----------------------------------------------------------------

// applyImageUpdate runs one update for a Compose project, rolling back on
// failure. It is long-running and meant for a worker unit, not the broker.
func applyImageUpdate(actor, project string) (M, error) {
	if !fullmatch(projectName, project) {
		return nil, Public("Choose a project")
	}
	if s := str(updateJournal(project)["status"]); s != "" && s != "updated" && s != "rolled-back" && s != "failed" {
		return nil, Public("An update for this project is already in progress or needs recovery")
	}
	_, inventory, err := publishedProjectPolicy(NewProjectTransactions("", ""))
	if err != nil {
		return nil, err
	}
	declared := obj(obj(inventory["projects"])[project])
	if declared == nil || str(declared["backend"]) != "incus-compose" || !isTrue(declared["enable"]) {
		return nil, Public("Image updates apply to enabled, published Compose projects")
	}
	incusProject := str(declared["incusProject"])
	policy := projectUpdatePolicy(declared)
	seconds, _ := intValue(policy["healthSeconds"])
	current, err := NewPublishedSources("").current(project)
	if err != nil || current == nil {
		return nil, Public("The project has no published source")
	}
	previous := str(current["revision"])
	if NewOCIBuilds("", nil).imported(project, previous) == nil {
		return nil, Public("Deploy the current revision before updating it, so there is a known-good image to roll back to")
	}
	journal := M{"format": 1, "project": project, "status": "preparing", "from": previous, "actor": actor, "startedAt": now()}
	save := func(status string, extra M) {
		journal["status"], journal["updatedAt"] = status, now()
		for k, v := range extra {
			journal[k] = v
		}
		writeJSONMode(updateJournalPath(project), journal, 0o640, "")
	}
	save("preparing", nil)
	audit("image-update-started", M{"principal": actor, "project": project, "from": previous})
	fail := func(err error) (M, error) {
		fmt.Fprintln(os.Stderr, "nixus: image update stopped before changing the project:", err)
		save("failed", M{"error": publicError(err)})
		audit("image-update-failed", M{"project": project, "phase": "before-change"})
		return journal, err
	}
	staged, err := prepareImageUpdate(actor, project)
	if err != nil {
		return fail(err)
	}
	changes := list(staged["imageChanges"])
	journal["changes"] = changes
	next, err := publishStaged(actor, staged)
	if err != nil {
		return fail(err)
	}
	save("building", M{"to": next})
	var snaps []volumeSnapshot
	var failedDeployment string
	rollback := func(cause error) (M, error) {
		save("rolling-back", M{"error": publicError(cause)})
		fmt.Fprintln(os.Stderr, "nixus: image update failed, rolling back:", cause)
		t := NewProjectTransactions("", "")
		steps := []func() error{
			func() error {
				if failedDeployment == "" {
					return nil
				}
				if s, _ := t.status(failedDeployment); str(s["deployment"]) == "verified" {
					return nil
				}
				return t.abandonDeployment(failedDeployment, "image update rollback")
			},
			// Pause upstream restart intent before stopping the failed app so
			// its state holds still while the rollback is planned.
			func() error {
				done, err := composeProjectCommand(project, "down", "--timeout", "30s")
				if err != nil {
					return err
				}
				if done {
					return nil
				}
				return stopApp(updateIncus, incusProject)
			},
			func() error { return republish(actor, project, previous) },
			func() error { return restoreVolumes(updateIncus, incusProject, snaps) },
			func() error { _, err := deployRevision(actor, project, previous); return err },
		}
		for _, step := range steps {
			if err := step(); err != nil {
				fmt.Fprintln(os.Stderr, "nixus: image update rollback needs attention:", err)
				save("rollback-failed", M{"rollbackError": publicError(err)})
				audit("image-update-rollback-failed", M{"project": project})
				return journal, Public("Update failed and rollback needs attention: " + publicError(err))
			}
		}
		for _, raw := range changes {
			setHold("nixus", project, obj(raw)["to"], true, "automatic rollback: "+publicError(cause))
		}
		save("rolled-back", M{"completedAt": now()})
		audit("image-update-rolled-back", M{"project": project, "from": next, "to": previous})
		return journal, Public("Update failed and was rolled back: " + publicError(cause))
	}
	if _, err := buildRevision(actor, project, next); err != nil {
		// Nothing was deployed; only the published pointer moved.
		if rerr := republish(actor, project, previous); rerr != nil {
			save("rollback-failed", M{"error": publicError(err), "rollbackError": publicError(rerr)})
			return journal, err
		}
		for _, raw := range changes {
			setHold("nixus", project, obj(raw)["to"], true, "rebuild failed: "+publicError(err))
		}
		save("rolled-back", M{"error": publicError(err), "completedAt": now()})
		return journal, Public("Update build failed; the running project was not changed: " + publicError(err))
	}
	snapName := "nixus-update-" + strconv.FormatInt(time.Now().UTC().Unix(), 10)
	save("snapshotting", nil)
	if snaps, err = snapshotVolumes(updateIncus, incusProject, snapName); err != nil {
		republish(actor, project, previous)
		return fail(err)
	}
	snapshotNames := []any{}
	for _, s := range snaps {
		snapshotNames = append(snapshotNames, s.Pool+"/"+s.Volume+"@"+s.Name)
	}
	save("deploying", M{"snapshots": snapshotNames})
	id, err := deployRevision(actor, project, next)
	failedDeployment = id
	if err != nil {
		return rollback(err)
	}
	save("health-check", nil)
	if err := healthy(project, incusProject, next, int(seconds)); err != nil {
		return rollback(err)
	}
	save("updated", M{"completedAt": now()})
	audit("image-update-applied", M{"project": project, "from": previous, "to": next, "changes": len(changes)})
	return journal, nil
}

// autoImageUpdates applies available, unheld updates for projects whose
// policy is "auto" and whose window is open, one project at a time.
func autoImageUpdates() (M, error) {
	_, inventory, err := publishedProjectPolicy(NewProjectTransactions("", ""))
	if err != nil {
		return nil, err
	}
	status := obj(readObj(imageUpdatesPath())["projects"])
	results := M{}
	var failed []string
	for _, name := range keys(obj(inventory["projects"])) {
		declared := obj(obj(inventory["projects"])[name])
		policy := projectUpdatePolicy(declared)
		if str(declared["backend"]) != "incus-compose" || str(policy["policy"]) == "manual" {
			continue
		}
		if str(policy["policy"]) == "notify" {
			if n, _ := num(obj(status[name])["updates"]); n > 0 {
				results[name] = "update available; notify policy"
				failed = append(failed, name+" (update available)")
			}
			continue
		}
		if !inWindow(str(policy["window"]), time.Now()) {
			results[name] = "outside maintenance window"
			continue
		}
		if n, _ := num(obj(status[name])["updates"]); n == 0 {
			results[name] = "no unheld update available"
			continue
		}
		journal, err := applyImageUpdate("nixus-auto", name)
		results[name] = M{"status": journal["status"], "error": journal["error"]}
		if err != nil {
			failed = append(failed, name)
		}
	}
	out := M{"projects": results}
	if len(failed) > 0 {
		return out, Public("Image updates need attention for: " + strings.Join(failed, ", "))
	}
	return out, nil
}

// imageUpdatesView joins the last check with holds and update journals.
func imageUpdatesView() M {
	view := readObj(imageUpdatesPath())
	if view == nil {
		view = M{"projects": M{}}
	}
	holds := readObj(imageHoldsPath())
	for name, raw := range obj(view["projects"]) {
		entry := obj(raw)
		entry["holds"] = holds[name]
		if j := updateJournal(name); j != nil {
			entry["lastUpdate"] = j
		}
	}
	return view
}

// startImageUpdate launches applyImageUpdate in its own worker unit so the
// broker never blocks on a rebuild or deployment.
func startImageUpdate(actor string, projectArg any) (M, error) {
	project, ok := projectArg.(string)
	if !ok || !fullmatch(projectName, project) {
		return nil, Public("Choose a project")
	}
	if s := str(updateJournal(project)["status"]); s != "" && s != "updated" && s != "rolled-back" && s != "failed" {
		return nil, Public("An update for this project is already in progress or needs recovery")
	}
	if n, _ := num(obj(obj(readObj(imageUpdatesPath())["projects"])[project])["updates"]); n == 0 {
		return nil, Public("No unheld image update is available for this project")
	}
	if _, err := check([]string{"systemd-run", "--quiet", "--collect", "--no-block", "--unit=nixus-image-update-" + project,
		"--property=RuntimeMaxSec=7200", "--setenv=NIXUS_STATE=" + STATE, "--setenv=PATH=" + os.Getenv("PATH"), "--setenv=INCUS_COMPOSE_HEALTHD_IMAGE=" + os.Getenv("INCUS_COMPOSE_HEALTHD_IMAGE"), "--setenv=INCUS_COMPOSE_DNS_IMAGE=" + os.Getenv("INCUS_COMPOSE_DNS_IMAGE"), "--setenv=INCUS_COMPOSE_SLEEP_IMAGE=" + os.Getenv("INCUS_COMPOSE_SLEEP_IMAGE"),
		"--setenv=NIXUS_OCI_VM_TEST=" + os.Getenv("NIXUS_OCI_VM_TEST"),
		adminLauncher(), "admin", "image-updates", "apply", project}, nil, 20*time.Second); err != nil {
		return nil, Public("Could not start the update worker")
	}
	audit("image-update-requested", M{"principal": actor, "project": project})
	return M{"project": project, "status": "started"}, nil
}

// applyAllImageUpdates updates every app with an unheld update, one at a time,
// regardless of its policy. Each update keeps its own snapshot and rollback.
func applyAllImageUpdates(actor string) (M, error) {
	status := obj(readObj(imageUpdatesPath())["projects"])
	results := M{}
	var failed []string
	for _, name := range keys(status) {
		if n, _ := num(obj(status[name])["updates"]); n == 0 {
			continue
		}
		journal, err := applyImageUpdate(actor, name)
		results[name] = M{"status": journal["status"], "error": journal["error"]}
		if err != nil {
			failed = append(failed, name)
		}
	}
	out := M{"projects": results}
	if len(failed) > 0 {
		return out, Public("Updates failed for: " + strings.Join(failed, ", "))
	}
	return out, nil
}

// startAllImageUpdates runs applyAllImageUpdates in a worker unit.
func startAllImageUpdates(actor string) (M, error) {
	pending := 0
	for _, raw := range obj(readObj(imageUpdatesPath())["projects"]) {
		if n, _ := num(obj(raw)["updates"]); n > 0 {
			pending++
		}
	}
	if pending == 0 {
		return nil, Public("All apps are up to date")
	}
	if _, err := check([]string{"systemd-run", "--quiet", "--collect", "--no-block", "--unit=nixus-image-update-all",
		"--property=RuntimeMaxSec=21600", "--setenv=NIXUS_STATE=" + STATE, "--setenv=PATH=" + os.Getenv("PATH"), "--setenv=INCUS_COMPOSE_HEALTHD_IMAGE=" + os.Getenv("INCUS_COMPOSE_HEALTHD_IMAGE"), "--setenv=INCUS_COMPOSE_DNS_IMAGE=" + os.Getenv("INCUS_COMPOSE_DNS_IMAGE"), "--setenv=INCUS_COMPOSE_SLEEP_IMAGE=" + os.Getenv("INCUS_COMPOSE_SLEEP_IMAGE"),
		"--setenv=NIXUS_OCI_VM_TEST=" + os.Getenv("NIXUS_OCI_VM_TEST"),
		adminLauncher(), "admin", "image-updates", "apply-all"}, nil, 20*time.Second); err != nil {
		return nil, Public("App updates are already running")
	}
	audit("image-update-all-requested", M{"principal": actor, "apps": pending})
	return M{"started": true, "apps": pending}, nil
}

// stopApp pauses Compose restart intent before force-stopping an app for rollback.
// Failed inventory, marker writes and stops must leave rollback incomplete.
func stopApp(incus incusFunc, incusProject string) error {
	raw, err := incus(0, "query", "/1.0/instances?recursion=1&project="+url.QueryEscape(incusProject))
	if err != nil {
		return Public("Could not verify app instances before rollback")
	}
	payload, err := parseJSON([]byte(raw))
	instances, ok := payload.([]any)
	if err != nil || !ok {
		return Public("Invalid app inventory before rollback")
	}
	for _, raw := range instances {
		inst := obj(raw)
		name := str(inst["name"])
		if name == "" {
			return Public("Invalid app instance before rollback")
		}
		if str(jget(inst, "config", composeServiceLabel)) != "" {
			if err := setComposeStopped(incus, incusProject, name, true); err != nil {
				return Public("Could not pause the app restart policy before rollback")
			}
		}
		if str(inst["status"]) != "Stopped" {
			if _, err := incus(0, "stop", name, "--project", incusProject, "--force"); err != nil {
				return Public("Could not stop the failed app before rollback")
			}
		}
	}
	return nil
}
