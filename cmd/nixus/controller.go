package main

// Restricted root broker: typed settings, fixed host configuration
// transactions (review -> build -> apply -> confirm/rollback) and enrollment.

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Manager struct{ root, state string }

func NewManager(root, state string) *Manager {
	if root == "" {
		root = ROOT
	}
	if state == "" {
		state = STATE
	}
	os.MkdirAll(state, 0o755)
	os.MkdirAll(filepath.Join(state, "jobs"), 0o700)
	return &Manager{root, state}
}

func (m *Manager) settings() (M, error) { return readSettings(m.root) }

func (m *Manager) effectiveSettings(desired M) (M, error) {
	if desired == nil {
		var err error
		if desired, err = m.settings(); err != nil {
			return nil, err
		}
	}
	return mergeSettings(desired, readObj("/etc/nixus/effective-settings.json")), nil
}

func (m *Manager) jobPath(id string) (string, error) {
	return jobDirectory(filepath.Join(m.state, "jobs"), id, "transaction")
}

func (m *Manager) job(id string) (M, error) {
	directory, err := m.jobPath(id)
	if err != nil {
		return nil, err
	}
	job, err := readJobRecord(filepath.Join(directory, "job.json"), nil)
	if err != nil {
		return nil, err
	}
	log, err := tailLog(filepath.Join(directory, "build.log"), 65536)
	if err != nil {
		return nil, err
	}
	job["log"] = publicProgress(log)
	for _, field := range []string{"error", "rollbackError"} {
		if v := job[field]; v != nil && v != "" && v != false {
			job[field] = "Transaction did not complete; inspect host status before retrying"
		}
	}
	return job, nil
}

func (m *Manager) pruneJobs(apply bool, keep int) (M, error) {
	if keep < 1 || keep > 1000 {
		return nil, Public("Keep between 1 and 1000 recent jobs")
	}
	return lockedValue(false, func() (M, error) {
		protected := map[string]bool{}
		for _, name := range []string{"active.json", "pending.json", "last-confirmed.json", "deployment-active.json"} {
			protected[str(readObj(filepath.Join(m.state, name))["id"])] = true
		}
		type entry struct {
			mtime time.Time
			path  string
		}
		var jobs []entry
		entries, _ := os.ReadDir(filepath.Join(m.state, "jobs"))
		for _, e := range entries {
			p := filepath.Join(m.state, "jobs", e.Name())
			if isSymlink(p) || !isDir(p) || !fullmatch(jobID, e.Name()) {
				continue
			}
			job, _ := readJobRecord(filepath.Join(p, "job.json"), M{})
			switch str(job["status"]) {
			case "confirmed", "rolled-back", "failed", "cancelled":
				info, _ := os.Stat(p)
				jobs = append(jobs, entry{info.ModTime(), p})
			}
		}
		sort.Slice(jobs, func(i, j int) bool { return jobs[i].mtime.After(jobs[j].mtime) })
		candidates := []any{}
		if len(jobs) > keep {
			for _, j := range jobs[keep:] {
				if !protected[filepath.Base(j.path)] {
					candidates = append(candidates, filepath.Base(j.path))
				}
			}
		}
		if apply {
			for _, c := range candidates {
				os.RemoveAll(filepath.Join(m.state, "jobs", str(c)))
			}
			audit("configuration-history-pruned", M{"count": len(candidates)})
		}
		return M{"applied": apply, "keep": keep, "jobs": candidates}, nil
	})
}

func (m *Manager) status() (M, error) {
	active := readObj(filepath.Join(m.state, "active.json"))
	var job M
	if id := str(active["id"]); id != "" {
		var err error
		if job, err = m.job(id); err != nil {
			return nil, err
		}
		status := str(job["status"])
		started, ok := num(job["appliedAt"])
		if !ok {
			started, _ = num(job["created"])
		}
		if (status == "building" || status == "applying") && now()-started > 30 {
			phase := "build"
			if status == "applying" {
				phase = "apply"
			}
			running, err := workerActive("nixus-" + phase + "-" + id)
			if err != nil {
				return nil, err
			}
			if !running {
				latest, err := m.job(id)
				if err == nil && str(latest["status"]) == status {
					delete(latest, "log")
					latest["status"] = "failed"
					latest["error"] = strings.ToUpper(phase[:1]) + phase[1:] + " worker stopped; rerun the installer to recover and retry"
					dir, _ := m.jobPath(id)
					writeJSON(filepath.Join(dir, "job.json"), latest)
				}
				job, _ = m.job(id)
			}
		}
	}
	current, _ := filepath.EvalSymlinks("/run/current-system")
	var last any = must(readJSON(filepath.Join(m.state, "last-confirmed.json"), nil))
	if l := obj(last); l != nil {
		dir, err := m.jobPath(str(l["id"]))
		if err != nil {
			last = nil
		} else if record, err := readJobRecord(filepath.Join(dir, "job.json"), nil); err != nil || str(record["status"]) != "confirmed" {
			last = nil
		}
	}
	desired, err := m.settings()
	if err != nil {
		return nil, err
	}
	stored := readObj(machinePath(m.root, "settings"))
	effective, _ := m.effectiveSettings(desired)
	var observed any
	if a, err := managementAddress(effective); err == nil {
		observed = a
	}
	booted, _ := filepath.EvalSymlinks("/run/booted-system/kernel")
	running, _ := filepath.EvalSymlinks("/run/current-system/kernel")
	reboot := booted != "" && running != "" && booted != running
	schemaStored, ok := stored["schemaVersion"]
	if !ok {
		schemaStored = 0
	}
	schemaDesired, ok := desired["schemaVersion"]
	if !ok {
		schemaDesired = 0
	}
	var jobValue any
	if job != nil {
		jobValue = job
	}
	return M{"release": upgradeMetadata(m.root), "managementAddress": observed, "rebootRequired": reboot,
		"effectiveSettings": effective, "codeOverrides": differences(desired, effective, ""), "settings": desired,
		"job": jobValue, "lastConfirmed": last, "pending": must(readJSON(filepath.Join(m.state, "pending.json"), nil)),
		"moduleDirectory": machinePath(m.root, "modules"), "currentSystem": current,
		"setupComplete": desired["ready"], "settingsSchema": M{"stored": schemaStored, "desired": schemaDesired}}, nil
}

func (m *Manager) hostInventory() M {
	data := hostInventory()
	var networks []netip.Prefix
	for _, r := range list(data["routes"]) {
		dst := str(obj(r)["dst"])
		if dst == "" || dst == "default" {
			continue
		}
		if !strings.Contains(dst, "/") {
			dst += "/32"
		}
		if p, err := netip.ParsePrefix(dst); err == nil {
			networks = append(networks, p.Masked())
		}
	}
	for _, c := range []string{"10.77.0.0/24", "10.78.0.0/24", "172.30.77.0/24", "192.168.240.0/24"} {
		candidate := netip.MustParsePrefix(c)
		overlap := false
		for _, n := range networks {
			if candidate.Overlaps(n) {
				overlap = true
			}
		}
		if !overlap {
			prefix := c[:strings.LastIndex(strings.TrimSuffix(c, "/24"), ".")]
			data["suggestedGuests"] = M{"cidr": c, "gatewayCIDR": prefix + ".1/24", "dhcpRange": prefix + ".100-" + prefix + ".199"}
			break
		}
	}
	present := M{}
	for k, p := range SECRET_PATHS {
		present[k] = exists(p)
	}
	data["secretPresent"] = present
	return data
}

// spawn starts a transient systemd worker for one transaction phase.
func (m *Manager) spawn(phase, id string) error {
	dir, err := m.jobPath(id)
	if err != nil {
		return err
	}
	if err := pinWorkerRuntime(dir); err != nil {
		return err
	}
	_, err = check([]string{"systemd-run", "--quiet", "--collect", "--no-block", "--unit=nixus-" + phase + "-" + id,
		"--property=RuntimeMaxSec=10800", "--setenv=NIXUS_ROOT=" + m.root, "--setenv=NIXUS_STATE=" + m.state,
		"--setenv=PATH=" + os.Getenv("PATH"), adminLauncher(), "admin", "job", phase, id}, nil, time.Minute)
	return err
}

type ReviewOptions struct {
	Secrets        M
	UpdateInputs   bool
	Modules        M
	Revision       any
	Principal      string
	HostRole       string
	StagedSource   string
	ExpectedDigest string
}

func (m *Manager) review(changes M, o ReviewOptions) (M, error) {
	if o.Principal == "" {
		o.Principal = "root"
	}
	if o.HostRole == "" {
		o.HostRole = "hypervisor"
	}
	if o.HostRole != "hypervisor" && o.HostRole != "bootstrap" {
		return nil, Public("Unsupported host role")
	}
	if o.HostRole == "bootstrap" && (o.Principal != "root-wizard-install" || o.UpdateInputs || len(o.Modules) > 0 || o.Revision != nil || len(o.Secrets) > 0) {
		return nil, Public("Bootstrap review is reserved for initial local installer onboarding")
	}
	if o.StagedSource != "" && ((o.Principal != "root-direct-install" && o.Principal != "root-wizard-install") ||
		o.Revision != nil || o.UpdateInputs || len(o.Modules) > 0 || o.ExpectedDigest == "") {
		return nil, Public("Staged source is reserved for the local installer")
	}
	return lockedValue(false, func() (M, error) { return m.reviewLocked(changes, o) })
}

func (m *Manager) reviewLocked(changes M, o ReviewOptions) (M, error) {
	if o.StagedSource != "" {
		d, err := digestSource(m.root)
		if err != nil {
			return nil, err
		}
		if d != o.ExpectedDigest {
			return nil, Public("Installed source changed during planning; restart review")
		}
	}
	if err := checkIdle(m.state, ""); err != nil {
		return nil, err
	}
	if activeProjectDeployment(m.state) != "" {
		return nil, Public("Finish or recover the project deployment before rebuilding the host")
	}
	if o.Revision != nil && !fullmatch(re(`[0-9a-f]{40}`), str(o.Revision)) {
		return nil, Public("Specify the full reviewed platform commit SHA")
	}
	modules := o.Modules
	if modules == nil {
		modules = M{}
	}
	if _, err := validateModules(modules); err != nil {
		return nil, err
	}
	if v, _ := readJSON(filepath.Join(m.state, "pending.json"), nil); v != nil && !equalJSON(v, M{}) {
		return nil, Public("Finish the pending activation or its recovery before starting another review")
	}
	active := readObj(filepath.Join(m.state, "active.json"))
	var previous M
	if id := str(active["id"]); id != "" {
		var err error
		if previous, err = m.job(id); err != nil {
			return nil, err
		}
		switch str(previous["status"]) {
		case "building", "applying", "awaiting-confirmation", "rolling-back":
			return nil, Public("Finish the active transaction first")
		}
	}
	if changes == nil {
		return nil, Public("Settings must be an object")
	}
	current, err := m.settings()
	if err != nil {
		return nil, err
	}
	effectiveCurrent, _ := m.effectiveSettings(current)
	if o.HostRole == "bootstrap" && (isTrue(current["ready"]) || isTrue(effectiveCurrent["ready"])) {
		return nil, Public("Bootstrap cannot replace an already configured host")
	}
	stored := readObj(machinePath(m.root, "settings"))
	requested := mergeSettings(current, changes)
	host := hostInventory()
	var candidate M
	if o.HostRole == "bootstrap" {
		if !equalJSON(requested, current) {
			return nil, Public("Bootstrap review cannot change settings; use the full host review")
		}
		candidate = requested
		if err := validateBootstrap(candidate, host); err != nil {
			return nil, err
		}
	} else if candidate, err = validateSettings(requested, current, host, true); err != nil {
		return nil, err
	}
	for _, k := range list(candidate["adminKeys"]) {
		f, err := os.CreateTemp(m.state, "key")
		if err != nil {
			return nil, err
		}
		f.WriteString(str(k) + "\n")
		f.Close()
		_, err = command([]string{"ssh-keygen", "-l", "-f", f.Name()}, 0)
		os.Remove(f.Name())
		if err != nil {
			return nil, err
		}
	}
	install := readObj(machinePath(m.root, "installation"))
	wifi := obj(jget(candidate, "radios", "wifi"))
	if isTrue(install["legacyWpaProfiles"]) && isTrue(wifi["enable"]) && !isTrue(wifi["manageProfile"]) {
		return nil, Public("This host used Nix wpa_supplicant profiles. Declare its SSID/password when moving Wi-Fi to NetworkManager/iwd")
	}
	encoded, err := encodeSecrets(o.Secrets, candidate)
	if err != nil {
		return nil, err
	}
	sops := isTrue(jget(candidate, "secrets", "enable"))
	kept := func(field string) bool {
		if sops {
			return hostSecretPresent(m.root, field)
		}
		return exists(SECRET_PATHS[field])
	}
	if isTrue(wifi["manageProfile"]) && isTrue(wifi["enable"]) {
		if _, ok := encoded["wifiPassword"]; !ok && !kept("wifiPassword") {
			return nil, Public("Provide the WPA password for the managed Wi-Fi profile")
		}
	}
	runtimeSettings := current
	if exists("/var/lib/incus/database") && !isTrue(current["ready"]) && str(active["id"]) != "" && previous["previousSystem"] != nil {
		runtimeSettings = obj(previous["settings"])
	}
	if o.HostRole == "hypervisor" {
		guestNet, err := parseNetwork(jget(candidate, "guests", "cidr"))
		if err != nil {
			return nil, err
		}
		bridge := "incusbr0"
		if b, ok := obj(candidate["guests"])["bridge"]; ok {
			bridge = str(b)
		}
		for _, raw := range list(host["routes"]) {
			route := obj(raw)
			dst := str(route["dst"])
			if dst == "" || dst == "default" || str(route["dev"]) == bridge {
				continue
			}
			if !strings.Contains(dst, "/") {
				dst += "/32"
			}
			if p, err := netip.ParsePrefix(dst); err == nil && guestNet.Overlaps(p.Masked()) {
				return nil, Public("Guest address space overlaps an existing host/LAN/VPN route")
			}
		}
	}
	stagedChanges := []string{}
	if o.StagedSource != "" {
		if !isFile(machinePath(o.StagedSource, "installation")) {
			return nil, Public("Installer source lacks installation inventory")
		}
		digestFiles := func(root string) (map[string]string, error) {
			files, err := sourceFiles(root)
			if err != nil {
				return nil, err
			}
			out := map[string]string{}
			for _, f := range files {
				data, err := os.ReadFile(f.path)
				if err != nil {
					return nil, err
				}
				h := sha256.Sum256(data)
				out[f.name] = hex.EncodeToString(h[:])
			}
			return out, nil
		}
		base, err := digestFiles(m.root)
		if err != nil {
			return nil, err
		}
		proposed, err := digestFiles(o.StagedSource)
		if err != nil {
			return nil, err
		}
		settingsRel, _ := filepath.Rel(m.root, machinePath(m.root, "settings"))
		installRel, _ := filepath.Rel(m.root, machinePath(m.root, "installation"))
		names := map[string]bool{}
		for n := range base {
			names[n] = true
		}
		for n := range proposed {
			names[n] = true
		}
		for name := range names {
			differ := base[name] != proposed[name]
			if !platformPath(name) && name != settingsRel && name != installRel && name != ".nixus-files.json" && differ {
				return nil, Public("Installer source modifies unreviewed local machine files")
			}
			if platformPath(name) && differ {
				stagedChanges = append(stagedChanges, name)
			}
		}
		sort.Strings(stagedChanges)
	}
	id := tokenHex(16)
	directory := filepath.Join(m.state, "jobs", id)
	sourceRoot := m.root
	if o.StagedSource != "" {
		sourceRoot = o.StagedSource
	}
	if err := snapshot(filepath.Join(directory, "source"), sourceRoot); err != nil {
		return nil, err
	}
	for _, name := range keys(modules) {
		if err := atomicString(filepath.Join(machinePath(filepath.Join(directory, "source"), "modules"), name), str(modules[name]), 0o644); err != nil {
			return nil, err
		}
	}
	if err := writeJSON(machinePath(filepath.Join(directory, "source"), "settings"), candidate); err != nil {
		return nil, err
	}
	encrypted := []string{}
	if sops && len(encoded) > 0 {
		if encrypted, err = hostSecretsWrite(filepath.Join(directory, "source"), encoded, str(jget(candidate, "secrets", "ageKeyFile"))); err != nil {
			return nil, err
		}
		encoded = M{}
	}
	before := runtimeSettings
	if isTrue(current["ready"]) {
		before = effectiveCurrent
	}
	if err := writeJSON(filepath.Join(directory, "impact-base.json"), impactBaseline(before)); err != nil {
		return nil, err
	}
	baseDigest, err := digestSource(m.root)
	if err != nil {
		return nil, err
	}
	moduleChanges := []any{}
	for _, name := range keys(modules) {
		var beforeText any
		if raw, err := os.ReadFile(filepath.Join(machinePath(m.root, "modules"), name)); err == nil {
			beforeText = string(raw)
		}
		moduleChanges = append(moduleChanges, M{"path": name, "before": beforeText, "after": modules[name]})
	}
	platformChanges := []any{}
	for _, name := range stagedChanges {
		platformChanges = append(platformChanges, M{"path": name, "kind": "staged-installer-update"})
	}
	fromSchema, ok := stored["schemaVersion"]
	if !ok {
		fromSchema = 0
	}
	toSchema, ok := candidate["schemaVersion"]
	if !ok {
		toSchema = 0
	}
	job := M{"id": id, "status": "building", "created": now(), "baseDigest": baseDigest, "hostRole": o.HostRole,
		"settingsMigration": M{"from": fromSchema, "to": toSchema}, "settings": candidate,
		"changes": differences(current, candidate, ""), "principal": o.Principal, "moduleChanges": moduleChanges,
		"secretChanges": strings2any(keys(encoded)), "encryptedSecretChanges": strings2any(encrypted),
		"updateInputs": o.UpdateInputs, "platformRevision": o.Revision, "sourceStaged": o.StagedSource != "",
		"sourcePlatformUpdated": len(stagedChanges) > 0, "platformChanges": platformChanges}
	if err := writeJSON(filepath.Join(directory, "job.json"), job); err != nil {
		return nil, err
	}
	if err := writeJSON(filepath.Join(m.state, "active.json"), M{"id": id}); err != nil {
		return nil, err
	}
	if prev := str(active["id"]); prev != "" {
		switch str(previous["status"]) {
		case "ready", "failed", "cancelled":
			obsolete, _ := m.jobPath(prev)
			record, err := readJobRecord(filepath.Join(obsolete, "job.json"), nil)
			if err == nil {
				record["status"] = "superseded"
				writeJSON(filepath.Join(obsolete, "job.json"), record)
			}
			removeStagedSecrets(obsolete)
			durableUnlink(filepath.Join(obsolete, "system"))
		}
	}
	audit("review", M{"job": id, "changes": len(list(job["changes"])), "secrets": strings2any(append(keys(encoded), encrypted...))})
	if len(encoded) > 0 {
		err = stageSecrets(directory, encoded)
	}
	if err == nil {
		err = m.spawn("build", id)
	}
	if err != nil {
		job["status"] = "failed"
		job["error"] = "Could not stage credentials or start the build service"
		writeJSON(filepath.Join(directory, "job.json"), job)
		return nil, err
	}
	return M{"id": id}, nil
}

func (m *Manager) noProjectDeploy() error {
	if activeProjectDeployment(m.state) != "" {
		return Public("Finish or recover the project deployment before rebuilding the host")
	}
	return nil
}

func (m *Manager) apply(id string) (M, error) {
	return lockedValue(false, func() (M, error) {
		if err := checkIdle(m.state, ""); err != nil {
			return nil, err
		}
		if err := m.noProjectDeploy(); err != nil {
			return nil, err
		}
		directory, err := m.jobPath(id)
		if err != nil {
			return nil, err
		}
		job, err := readJobRecord(filepath.Join(directory, "job.json"), nil)
		if err != nil {
			return nil, err
		}
		if str(readObj(filepath.Join(m.state, "active.json"))["id"]) != id {
			return nil, Public("This candidate was superseded; review the active transaction")
		}
		if str(job["status"]) != "ready" {
			return nil, Public("Build and review this transaction before activation")
		}
		if err := requireFreshStagedSecrets(job); err != nil {
			return nil, err
		}
		if d, err := digestSource(m.root); err != nil || d != str(job["baseDigest"]) {
			return nil, Public("Source/settings changed since review; build a new transaction")
		}
		if d, err := digestSource(filepath.Join(directory, "source")); err != nil || d != str(job["candidateDigest"]) {
			return nil, Public("Reviewed snapshot changed; refusing activation")
		}
		if err := impactRecheck(directory); err != nil {
			return nil, err
		}
		job, err = readJobRecord(filepath.Join(directory, "job.json"), nil)
		if err != nil {
			return nil, err
		}
		job["status"] = "applying"
		job["appliedAt"] = now()
		if err := writeJSON(filepath.Join(directory, "job.json"), job); err != nil {
			return nil, err
		}
		if err := m.spawn("apply", id); err != nil {
			job["status"], job["error"] = "failed", "Could not start the activation worker"
			writeJSON(filepath.Join(directory, "job.json"), job)
			return nil, err
		}
		audit("apply-requested", M{"job": id})
		return M{"id": id}, nil
	})
}

func (m *Manager) confirm(id string) (M, error) {
	return lockedValue(false, func() (M, error) {
		pending := readObj(filepath.Join(m.state, "pending.json"))
		directory, err := m.jobPath(id)
		if err != nil {
			return nil, err
		}
		job, err := readJobRecord(filepath.Join(directory, "job.json"), nil)
		if err != nil {
			return nil, err
		}
		if len(pending) == 0 || str(pending["id"]) != id || str(job["status"]) != "awaiting-confirmation" {
			return nil, Public("No completed activation is awaiting confirmation")
		}
		if deadline, _ := num(pending["deadline"]); now() >= deadline {
			return nil, Public("Confirmation window expired; recovery is required")
		}
		running, _ := filepath.EvalSymlinks("/run/current-system")
		reviewed, _ := filepath.EvalSymlinks(filepath.Join(directory, "system"))
		if running == "" || running != reviewed {
			return nil, Public("The running generation differs from the reviewed build")
		}
		job["status"], job["confirmedAt"] = "confirmed", now()
		if err := writeJSON(filepath.Join(directory, "job.json"), job); err != nil {
			return nil, err
		}
		last := readObj(filepath.Join(m.state, "last-confirmed.json"))
		if lid := str(last["id"]); lid != "" && lid != id {
			if old, err := m.jobPath(lid); err == nil {
				durableUnlink(filepath.Join(old, "system"))
				durableUnlink(filepath.Join(old, "previous-system"))
				os.RemoveAll(filepath.Join(old, "recovery"))
			}
		}
		if err := writeJSON(filepath.Join(m.state, "last-confirmed.json"), M{"id": id}); err != nil {
			return nil, err
		}
		durableUnlink(filepath.Join(m.state, "pending.json"))
		removeStagedSecrets(directory)
		audit("confirmed", M{"job": id})
		return M{"ok": true}, nil
	})
}

func (m *Manager) rollback(id string) (M, error) {
	return lockedValue(false, func() (M, error) {
		if err := checkIdle(m.state, ""); err != nil {
			return nil, err
		}
		if err := m.noProjectDeploy(); err != nil {
			return nil, err
		}
		job, err := m.job(id)
		if err != nil {
			return nil, err
		}
		switch str(job["status"]) {
		case "awaiting-confirmation", "confirmed", "failed":
		default:
			return nil, Public("This transaction has no recoverable previous generation")
		}
		if job["previousSystem"] == nil {
			return nil, Public("This transaction has no recoverable previous generation")
		}
		active := readObj(filepath.Join(m.state, "active.json"))
		if str(active["id"]) != id {
			pending, _ := readJSON(filepath.Join(m.state, "pending.json"), nil)
			if str(readObj(filepath.Join(m.state, "last-confirmed.json"))["id"]) != id || (pending != nil && !equalJSON(pending, M{})) {
				return nil, Public("Only the current or last confirmed transaction can be rolled back")
			}
			if aid := str(active["id"]); aid != "" {
				other, err := m.job(aid)
				if err != nil {
					return nil, err
				}
				switch str(other["status"]) {
				case "applying", "awaiting-confirmation", "rolling-back":
					return nil, Public("Finish the active activation first")
				case "building":
					if _, err := check([]string{"systemctl", "stop", "nixus-build-" + aid}, nil, 30*time.Second); err != nil {
						return nil, err
					}
				}
				dir, _ := m.jobPath(aid)
				record, err := readJobRecord(filepath.Join(dir, "job.json"), nil)
				if err == nil {
					record["status"] = "superseded"
					writeJSON(filepath.Join(dir, "job.json"), record)
				}
				removeStagedSecrets(dir)
				durableUnlink(filepath.Join(dir, "system"))
			}
			if err := writeJSON(filepath.Join(m.state, "active.json"), M{"id": id}); err != nil {
				return nil, err
			}
		}
		if err := m.spawn("rollback", id); err != nil {
			return nil, err
		}
		audit("rollback-requested", M{"job": id})
		return M{"ok": true}, nil
	})
}

func (m *Manager) cancel(id string) (M, error) {
	return lockedValue(false, func() (M, error) {
		directory, err := m.jobPath(id)
		if err != nil {
			return nil, err
		}
		job, err := readJobRecord(filepath.Join(directory, "job.json"), nil)
		if err != nil {
			return nil, err
		}
		if str(readObj(filepath.Join(m.state, "pending.json"))["id"]) == id {
			return nil, Public("Recover the pending activation before discarding its candidate")
		}
		status := str(job["status"])
		if status != "building" && status != "ready" && status != "failed" {
			return nil, Public("Only an unapplied candidate can be discarded")
		}
		if status == "building" {
			if _, err := check([]string{"systemctl", "stop", "nixus-build-" + id}, nil, 30*time.Second); err != nil {
				return nil, err
			}
		}
		job["status"] = "cancelled"
		if err := writeJSON(filepath.Join(directory, "job.json"), job); err != nil {
			return nil, err
		}
		removeStagedSecrets(directory)
		durableUnlink(filepath.Join(directory, "system"))
		audit("candidate-discarded", M{"job": id})
		return M{"ok": true}, nil
	})
}
