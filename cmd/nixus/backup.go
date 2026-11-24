package main

// Complete offline backup generations with durable restart intent, coverage
// and capacity planning, and scheduled-backup health interpretation.
// Only members of one consistency group stop together; incomplete generations
// are never published.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var backupRoot = envPath("NIXUS_EXPORT_DIRECTORY", "/var/lib/nixus/exports")

var backupPending = "/var/lib/nixus/restart-pending.json"

var generationRe = re(`[0-9]+-[0-9a-f]{32}`)
var archiveRe = re(`(instance|volume)-[0-9a-f]{64}\.tar(?:\.gz)?`)

var backupIncus = func(timeout time.Duration, args ...string) (string, error) {
	if timeout == 0 {
		timeout = 43200 * time.Second
	}
	return incusRun(args, timeout, 0)
}

func backupQuery(p string) (M, error) {
	out, err := backupIncus(0, "query", p)
	if err != nil {
		return nil, err
	}
	return parseObject([]byte(out))
}

func backupList(args ...string) ([]any, error) {
	out, err := backupIncus(0, args...)
	if err != nil {
		return nil, err
	}
	v, err := parseJSON([]byte(out))
	if err != nil {
		return nil, err
	}
	return list(v), nil
}

func saveRestartPending(pending []any) error {
	if pending == nil {
		pending = []any{}
	}
	os.MkdirAll(filepath.Dir(backupPending), 0o755)
	raw, _ := json.Marshal(pending)
	return atomic(backupPending, raw, 0o600, "")
}

func instanceIdentity(guest M) M {
	return M{"project": guest["project"], "name": guest["name"], "uuid": jget(guest, "config", "volatile.uuid"),
		"compose": str(jget(guest, "config", composeServiceLabel)) != "", "healthStopped": jget(guest, "config", composeStoppedKey)}
}

func verifyIdentity(guest M) error {
	if str(guest["uuid"]) == "" {
		return nil
	}
	out, err := backupIncus(15*time.Second, "query", instancePath(str(guest["project"]), str(guest["name"])))
	if err != nil {
		return err
	}
	current, err := parseObject([]byte(out))
	if err != nil || str(jget(current, "config", "volatile.uuid")) != str(guest["uuid"]) {
		return Hidden("Guest identity changed after inventory; refusing backup lifecycle changes")
	}
	return nil
}

// backupRecover restarts guests a backup or export stopped.
func backupRecover() error {
	var pending []any
	if raw, err := os.ReadFile(backupPending); err == nil {
		json.Unmarshal(raw, &pending)
	}
	failed := []any{}
	for _, raw := range pending {
		guest := obj(raw)
		err := func() error {
			if err := verifyIdentity(guest); err != nil {
				return err
			}
			state, err := backupQuery("/1.0/instances/" + url.PathEscape(str(guest["name"])) + "/state?project=" + url.QueryEscape(str(guest["project"])))
			if err != nil {
				return err
			}
			switch str(state["status"]) {
			case "Stopped":
				if _, err = backupIncus(0, "start", str(guest["name"]), "--project", str(guest["project"])); err != nil {
					return err
				}
			case "Running":
			default:
				return Hidden("Guest is neither stopped nor running")
			}
			return restoreComposeStopped(backupIncus, guest)
		}()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Recovery failed for %s/%s: %v\n", str(guest["project"]), str(guest["name"]), err)
			failed = append(failed, guest)
		}
	}
	if err := saveRestartPending(failed); err != nil {
		return err
	}
	if len(failed) > 0 {
		return Hidden("Some formerly running guests could not be restarted; see restart-pending.json")
	}
	return nil
}

func backupArtifact(kind string, identity ...string) string {
	raw, _ := json.Marshal(identity)
	return kind + "-" + sha256hex([]byte(canonicalSpacedRaw(raw))) + ".tar"
}

func backupExport(args []string, filename, destination string) error {
	f, err := os.CreateTemp(destination, ".export-*.tar")
	if err != nil {
		return err
	}
	temporary := f.Name()
	f.Close()
	os.Remove(temporary)
	defer os.Remove(temporary)
	// Export uncompressed tar so restic can deduplicate and compress (zstd)
	// across daily snapshots without gzip breaking chunk boundaries.
	if _, err := backupIncus(0, append(args, temporary, "--compression", "none")...); err != nil {
		return err
	}
	info, err := os.Stat(temporary)
	if err != nil || info.Size() == 0 {
		return Hidden("Export is empty")
	}
	os.Chmod(temporary, 0o600)
	if f, err := os.Open(temporary); err == nil {
		f.Sync()
		f.Close()
	}
	return os.Rename(temporary, filepath.Join(destination, filename))
}

func backupProgress(phase string, fields M) {
	status := filepath.Join(filepath.Dir(backupPending), "backup-status.json")
	os.MkdirAll(filepath.Dir(status), 0o755)
	record := M{}
	if phase == "failed" {
		previous := readObj(status)
		for _, k := range []string{"generation", "coverage", "capacity", "excluded"} {
			if v, ok := previous[k]; ok {
				record[k] = v
			}
		}
	}
	for k, v := range fields {
		record[k] = v
	}
	record["phase"] = phase
	record["updated"] = now()
	atomic(status, jsonFile(record), 0o600, "")
}

type volumeKey struct{ project, pool, name string }

func backupDevices(guest M) M {
	if d := obj(guest["expanded_devices"]); d != nil {
		return d
	}
	return obj(guest["devices"])
}

func consistencyGroups(guests []M, volumes []M, configured []any, namespaces map[string]string) ([]M, error) {
	type key struct{ project, name string }
	byID := map[key]M{}
	parents := map[key]key{}
	for _, g := range guests {
		k := key{str(g["project"]), str(g["name"])}
		byID[k] = g
		parents[k] = k
	}
	find := func(k key) key {
		for parents[k] != k {
			parents[k] = parents[parents[k]]
			k = parents[k]
		}
		return k
	}
	join := func(ks []key) {
		for _, k := range ks[1:] {
			parents[find(k)] = find(ks[0])
		}
	}
	ns := func(p string) string {
		if v, ok := namespaces[p]; ok {
			return v
		}
		return p
	}
	consumers := map[volumeKey][]key{}
	writable := map[volumeKey]bool{}
	for k, g := range byID {
		for _, raw := range backupDevices(g) {
			d := obj(raw)
			if str(d["type"]) != "disk" || str(d["path"]) == "/" || str(d["pool"]) == "" || str(d["source"]) == "" {
				continue
			}
			id := volumeKey{ns(k.project), str(d["pool"]), strings.TrimPrefix(str(d["source"]), "custom/")}
			consumers[id] = append(consumers[id], k)
			if str(d["readonly"]) != "true" {
				writable[id] = true
			}
		}
	}
	for id := range writable {
		join(consumers[id])
	}
	for _, raw := range configured {
		members, _ := anyStrings(raw)
		var ks []key
		for _, m := range members {
			p, n, _ := strings.Cut(m, "/")
			k := key{p, n}
			if _, ok := byID[k]; !ok {
				return nil, Public("Backup group references an absent project/guest")
			}
			ks = append(ks, k)
		}
		if len(ks) > 0 {
			join(ks)
		}
	}
	result := map[key]M{}
	var order []key
	for _, g := range guests {
		k := key{str(g["project"]), str(g["name"])}
		root := find(k)
		if result[root] == nil {
			result[root] = M{"guests": []any{}, "volumes": []any{}}
			order = append(order, root)
		}
		result[root]["guests"] = append(list(result[root]["guests"]), g)
	}
	standalone := []any{}
	for _, v := range volumes {
		id := volumeKey{str(v["project"]), str(v["pool"]), str(v["name"])}
		ks := consumers[id]
		if len(ks) > 0 && writable[id] {
			sort.Slice(ks, func(i, j int) bool {
				if ks[i].project != ks[j].project {
					return ks[i].project < ks[j].project
				}
				return ks[i].name < ks[j].name
			})
			root := find(ks[0])
			result[root]["volumes"] = append(list(result[root]["volumes"]), v)
		} else {
			standalone = append(standalone, v)
		}
	}
	var groups []M
	for _, k := range order {
		groups = append(groups, result[k])
	}
	if len(standalone) > 0 {
		groups = append(groups, M{"guests": []any{}, "volumes": standalone})
	}
	return groups, nil
}

// redactGuest returns a copy of an Incus guest record without the values of the
// environment variables Nixus delivers. The inventory is staged on disk before
// restic encrypts it, and restore never reads these values from it: the
// instance archives carry the configuration (#110).
func redactGuest(g M) M {
	out := cloneM(g)
	for _, section := range []string{"config", "expanded_config"} {
		cfg := obj(out[section])
		if cfg == nil {
			continue
		}
		redacted := M{}
		for k, v := range cfg {
			if strings.HasPrefix(k, "environment.") {
				v = "REDACTED"
			}
			redacted[k] = v
		}
		out[section] = redacted
	}
	return out
}

func redactGuests(guests []M) []M {
	out := make([]M, len(guests))
	for i, g := range guests {
		out[i] = redactGuest(g)
	}
	return out
}

func previousSizes() map[string]int64 {
	out := map[string]int64{}
	pointer := readObj(filepath.Join(backupRoot, "latest.json"))
	generation := str(pointer["generation"])
	if !fullmatch(generationRe, generation) {
		return out
	}
	directory := filepath.Join(backupRoot, "generations", generation)
	if resolved, _ := filepath.EvalSymlinks(directory); resolved != directory {
		return out
	}
	inventory := readObj(filepath.Join(directory, "inventory.json"))
	for name := range obj(inventory["archiveSHA256"]) {
		p := filepath.Join(directory, name)
		if fullmatch(archiveRe, name) && isFile(p) && !isSymlink(p) {
			info, _ := os.Stat(p)
			out[name] = info.Size()
		}
	}
	return out
}

type capacityItem struct {
	identity        string
	usage, previous any
}

func backupCapacity(objects []capacityItem, free, reserve, recoveryBytes int64) M {
	items := []any{}
	predicted := recoveryBytes
	unknown := []any{}
	for _, o := range objects {
		var sizes []int64
		usageOK := false
		if u, ok := intValue(o.usage); ok && u >= 0 {
			sizes = append(sizes, int64(u))
			usageOK = true
		}
		if p, ok := intValue(o.previous); ok && p >= 0 {
			sizes = append(sizes, int64(p))
		}
		var estimate any
		basis := "unknown"
		if len(sizes) > 0 {
			maxSize := sizes[0]
			for _, s := range sizes {
				maxSize = max(maxSize, s)
			}
			e := int64(math.Ceil(float64(maxSize)*1.25)) + 16<<20
			estimate = e
			predicted += e
			basis = "previous-archive"
			if usageOK {
				basis = "observed-usage"
			}
		}
		if basis != "observed-usage" {
			unknown = append(unknown, o.identity)
		}
		items = append(items, M{"identity": o.identity, "estimatedBytes": estimate, "basis": basis})
	}
	return M{"format": 1, "availableBytes": free, "reserveBytes": reserve, "estimatedNewBytes": predicted,
		"requiredBytes": reserve + predicted, "unknown": unknown, "items": items, "sufficientForEstimate": free >= reserve+predicted}
}

func backupCoverage(guests, volumes, selectedGuests, selectedVolumes []M, namespaces map[string]string) M {
	selected := map[string]bool{}
	for _, g := range selectedGuests {
		selected[str(g["project"])+"/"+str(g["name"])] = true
	}
	exported := map[volumeKey]bool{}
	for _, v := range selectedVolumes {
		exported[volumeKey{str(v["project"]), str(v["pool"]), str(v["name"])}] = true
	}
	rows := []any{}
	for _, g := range guests {
		identity := str(g["project"]) + "/" + str(g["name"])
		included := selected[identity]
		status := "excluded"
		if included {
			status = "included"
		}
		rows = append(rows, M{"kind": "instance", "identity": identity, "status": status})
		if !included {
			continue
		}
		devices := backupDevices(g)
		for _, name := range keys(devices) {
			d := obj(devices[name])
			switch str(d["type"]) {
			case "unix-block", "usb", "pci":
				rows = append(rows, M{"kind": "passthrough", "identity": identity + "/" + name, "status": "external"})
				continue
			}
			if str(d["type"]) != "disk" || str(d["path"]) == "/" || str(d["source"]) == "" {
				continue
			}
			status := "external"
			if pool := str(d["pool"]); pool != "" {
				ns, ok := namespaces[str(g["project"])]
				if !ok {
					ns = str(g["project"])
				}
				status = "missing"
				if exported[volumeKey{ns, pool, strings.TrimPrefix(str(d["source"]), "custom/")}] {
					status = "included"
				}
			}
			rows = append(rows, M{"kind": "attached-disk", "identity": identity + "/" + name, "status": status})
		}
	}
	for _, v := range volumes {
		k := volumeKey{str(v["project"]), str(v["pool"]), str(v["name"])}
		status := "excluded"
		if exported[k] {
			status = "included"
		}
		rows = append(rows, M{"kind": "custom-volume", "identity": k.project + "/" + k.pool + "/" + k.name, "status": status})
	}
	complete := true
	for _, r := range rows {
		if str(obj(r)["status"]) != "included" {
			complete = false
		}
	}
	return M{"format": 1, "items": rows, "complete": complete,
		"applicationConsistency": "cold exports; external writers and application recovery require independent verification",
		"restore":                "unverified"}
}

func freeBytes(p string) int64 {
	var st syscall.Statfs_t
	if syscall.Statfs(p, &st) != nil {
		return 0
	}
	return int64(st.Bavail) * int64(st.Bsize)
}

func stagingPlan(guests, volumes []M, reserve int64) M {
	previous := previousSizes()
	var objects []capacityItem
	for _, g := range guests {
		p := "/1.0/instances/" + url.PathEscape(str(g["name"])) + "/state?project=" + url.QueryEscape(str(g["project"]))
		var usage any
		if out, err := backupIncus(15*time.Second, "query", p); err == nil {
			if state, err := parseObject([]byte(out)); err == nil {
				usage = jget(state, "disk", "root", "usage")
			}
		}
		var prev any
		if v, ok := previous[str(g["archive"])]; ok {
			prev = v
		}
		objects = append(objects, capacityItem{str(g["archive"]), usage, prev})
	}
	for _, v := range volumes {
		p := "/1.0/storage-pools/" + url.PathEscape(str(v["pool"])) + "/volumes/custom/" + url.PathEscape(str(v["name"])) +
			"/state?project=" + url.QueryEscape(str(v["project"]))
		var usage any
		if out, err := backupIncus(15*time.Second, "query", p); err == nil {
			if state, err := parseObject([]byte(out)); err == nil {
				usage = jget(state, "usage", "used")
			}
		}
		var prev any
		if pv, ok := previous[str(v["archive"])]; ok {
			prev = pv
		}
		objects = append(objects, capacityItem{str(v["archive"]), usage, prev})
	}
	return backupCapacity(objects, freeBytes(backupRoot), reserve, 0)
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	f.Sync()
	return hex.EncodeToString(h.Sum(nil)), nil
}

// scopeGroups keeps only the consistency groups that belong to the selected
// Incus projects. A group that mixes selected and unselected guests (a shared
// writable volume) is refused before anything is stopped (#109).
func scopeGroups(groups []M, only map[string]bool, namespaces map[string]string) ([]M, error) {
	selectedNS := map[string]bool{}
	for project := range only {
		ns, ok := namespaces[project]
		if !ok {
			ns = project
		}
		selectedNS[ns] = true
	}
	var kept []M
	for _, group := range groups {
		inside, outside := []string{}, []string{}
		for _, raw := range list(group["guests"]) {
			g := obj(raw)
			name := str(g["project"]) + "/" + str(g["name"])
			if only[str(g["project"])] {
				inside = append(inside, name)
			} else {
				outside = append(outside, name)
			}
		}
		switch {
		case len(inside) > 0 && len(outside) > 0:
			return nil, Public("These guests share a writable volume, but only some are selected for backup: " +
				strings.Join(append(inside, outside...), ", ") + ". Select all of them or none.")
		case len(inside) > 0:
			kept = append(kept, group)
		case len(outside) == 0:
			// Standalone volumes: keep those in the selected namespaces.
			var vols []any
			for _, raw := range list(group["volumes"]) {
				if selectedNS[str(obj(raw)["project"])] {
					vols = append(vols, raw)
				}
			}
			if len(vols) > 0 {
				kept = append(kept, M{"guests": []any{}, "volumes": vols})
			}
		}
	}
	return kept, nil
}

// runBackup stages exports of every guest and volume, or only those of the
// given Incus projects when only is not nil. consistency optionally maps
// Incus project name -> "stop" | "quiesce" | "none" (default "stop").
func runBackup(only []string, consistency map[string]string) error {
	if err := os.MkdirAll(backupRoot, 0o700); err != nil {
		return err
	}
	info, _ := os.Stat(backupRoot)
	resolved, _ := filepath.EvalSymlinks(backupRoot)
	st := info.Sys().(*syscall.Stat_t)
	if resolved != backupRoot || int(st.Uid) != os.Geteuid() || info.Mode().Perm()&0o022 != 0 {
		return Public("Backup staging must be owned by root and cannot traverse symlinks or be writable by others")
	}
	if err := backupRecover(); err != nil {
		return err
	}
	backupProgress("inventory", nil)
	projects, err := backupList("project", "list", "--format=json")
	if err != nil {
		return err
	}
	trusted, err := backupList("config", "trust", "list", "--format=json")
	if err != nil {
		return err
	}
	serverInfo, err := backupQuery("/1.0")
	if err != nil {
		return err
	}
	server := serverInfo["config"]
	pools, err := backupList("storage", "list", "--format=json")
	if err != nil {
		return err
	}
	namespaces := map[string]string{}
	for _, p := range projects {
		pm := obj(p)
		ns := "default"
		if str(jget(pm, "config", "features.storage.volumes")) == "true" {
			ns = str(pm["name"])
		}
		namespaces[str(pm["name"])] = ns
	}
	var guests, volumes []M
	profiles, networks := M{}, M{}
	seen := map[volumeKey]bool{}
	for _, p := range projects {
		project := str(obj(p)["name"])
		if profiles[project], err = backupList("profile", "list", "--project", project, "--format=json"); err != nil {
			return err
		}
		if networks[project], err = backupList("network", "list", "--project", project, "--format=json"); err != nil {
			return err
		}
		instances, err := backupList("list", "--project", project, "--format=json")
		if err != nil {
			return err
		}
		for _, raw := range instances {
			g := obj(raw)
			if isComposeSidecar(project, str(g["name"])) {
				continue // recreated by the next deployment
			}
			g["project"] = project
			if s := str(g["status"]); s != "Running" && s != "Stopped" {
				return Hidden("Refusing backup of frozen/error-state guest: " + str(g["name"]))
			}
			g["archive"] = backupArtifact("instance", project, str(g["name"]))
			guests = append(guests, g)
		}
		for _, pool := range pools {
			poolName := str(obj(pool)["name"])
			vols, err := backupList("storage", "volume", "list", poolName, "--project", project, "--format=json")
			if err != nil {
				return err
			}
			for _, raw := range vols {
				v := obj(raw)
				if str(v["type"]) != "custom" {
					continue
				}
				ns := namespaces[project]
				k := volumeKey{ns, poolName, str(v["name"])}
				if seen[k] {
					continue
				}
				seen[k] = true
				volumes = append(volumes, M{"project": ns, "pool": poolName, "name": v["name"],
					"archive": backupArtifact("volume", ns, poolName, str(v["name"]))})
			}
		}
	}
	// Guests sharing a writable volume stop together; an instance can opt out
	// with user.nixus.backup=manual.
	groups, err := consistencyGroups(guests, volumes, nil, namespaces)
	if err != nil {
		return err
	}
	if only != nil {
		wanted := map[string]bool{}
		for _, p := range only {
			wanted[p] = true
		}
		if groups, err = scopeGroups(groups, wanted, namespaces); err != nil {
			return err
		}
	}
	skipped := []any{}
	var selected []M
	for _, group := range groups {
		protected := false
		var members []any
		for _, raw := range list(group["guests"]) {
			g := obj(raw)
			member := str(g["project"]) + "/" + str(g["name"])
			members = append(members, member)
			config := obj(g["expanded_config"])
			if config == nil {
				config = obj(g["config"])
			}
			if str(config["user.nixus.backup"]) == "manual" {
				protected = true
			}
		}
		if protected {
			skipped = append(skipped, members...)
		} else {
			selected = append(selected, group)
		}
	}
	var selectedGuests, selectedVolumes []M
	for _, group := range selected {
		for _, g := range list(group["guests"]) {
			selectedGuests = append(selectedGuests, obj(g))
		}
		for _, v := range list(group["volumes"]) {
			selectedVolumes = append(selectedVolumes, obj(v))
		}
	}
	coverage := backupCoverage(guests, volumes, selectedGuests, selectedVolumes, namespaces)
	reserveMiB := int64(1024)
	capacity := stagingPlan(selectedGuests, selectedVolumes, reserveMiB<<20)
	backupProgress("preflight", M{"coverage": coverage, "capacity": capacity})
	if !isTrue(capacity["sufficientForEstimate"]) {
		return Public("Insufficient free backup staging space for estimated exports plus reserve; no guests stopped")
	}
	generation := strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + tokenHex(16)
	incomplete := filepath.Join(backupRoot, ".incomplete")
	published := filepath.Join(backupRoot, "generations")
	os.MkdirAll(incomplete, 0o700)
	os.MkdirAll(published, 0o700)
	if isSymlink(incomplete) || isSymlink(published) {
		return Public("Backup generation directories cannot be symlinks")
	}
	destination := filepath.Join(incomplete, generation)
	if err := os.Mkdir(destination, 0o700); err != nil {
		return err
	}
	defer func() {
		backupRecover()
		os.RemoveAll(destination)
	}()
	windows, err := backupGroups(selected, destination, generation, consistency)
	if err != nil {
		return err
	}
	coverageName := "selected"
	if isTrue(coverage["complete"]) {
		coverageName = "all"
	}
	manifest := M{"format": 2, "generation": generation, "created": now(), "consistencyGroups": windows,
		"excluded": skipped, "coverage": coverageName, "coverageDetails": coverage, "capacity": capacity,
		"guests": redactGuests(selectedGuests), "projects": projects, "pools": pools, "customVolumes": selectedVolumes,
		"profiles": profiles, "networks": networks, "trustedCertificates": trusted, "serverConfiguration": server}
	archives, _ := filepath.Glob(filepath.Join(destination, "*.tar"))
	gzArchives, _ := filepath.Glob(filepath.Join(destination, "*.tar.gz"))
	archives = append(archives, gzArchives...)
	sort.Strings(archives)
	checksums, sizes := M{}, M{}
	for _, p := range archives {
		digest, err := fileSHA256(p)
		if err != nil {
			return err
		}
		checksums[filepath.Base(p)] = digest
		info, _ := os.Stat(p)
		sizes[filepath.Base(p)] = info.Size()
	}
	manifest["archiveSHA256"] = checksums
	manifest["archiveBytes"] = sizes
	if err := atomic(filepath.Join(destination, "inventory.json"), jsonFile(manifest), 0o600, ""); err != nil {
		return err
	}
	if err := os.Rename(destination, filepath.Join(published, generation)); err != nil {
		return err
	}
	fsyncDir(incomplete)
	fsyncDir(published)
	if err := atomic(filepath.Join(backupRoot, "latest.json"), jsonFile(M{"format": 2, "generation": generation}), 0o600, ""); err != nil {
		return err
	}
	entries, _ := os.ReadDir(published)
	var complete []string
	for _, e := range entries {
		p := filepath.Join(published, e.Name())
		if e.IsDir() && !isSymlink(p) && fullmatch(generationRe, e.Name()) && isFile(filepath.Join(p, "inventory.json")) {
			complete = append(complete, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(complete)))
	for _, old := range complete[min(2, len(complete)):] {
		os.RemoveAll(filepath.Join(published, old))
	}
	phase := "complete-with-exclusions"
	if isTrue(coverage["complete"]) {
		phase = "complete"
	}
	backupProgress(phase, M{"generation": generation, "guests": len(selectedGuests), "groups": len(selected),
		"excluded": skipped, "coverage": coverage, "capacity": capacity, "restore": "unverified"})
	return nil
}

// backupMain: `nixus backup [--recover]`; --recover restarts guests a cancelled export stopped.
func backupMain(args []string) int {
	syscall.Umask(0o077)
	release, err := lockFile(incusLock, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer release()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	done := make(chan error, 1)
	go func() {
		recoverOnly := false
		for _, a := range args {
			recoverOnly = recoverOnly || a == "--recover"
		}
		if recoverOnly {
			done <- backupRecover()
		} else {
			done <- runBackup(nil, nil)
		}
	}()
	select {
	case err = <-done:
	case <-signals:
		err = Hidden("Backup cancelled; recovering guests")
		backupRecover()
	}
	if err != nil {
		backupProgress("failed", M{"error": err.Error()})
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// groupConsistency picks the strictest consistency policy across all guests in
// a group ("stop" > "quiesce" > "none"), defaulting to "stop".
func groupConsistency(group M, consistency map[string]string) string {
	if len(consistency) == 0 {
		return "stop"
	}
	rank := map[string]int{"none": 1, "quiesce": 2, "stop": 3}
	mode, best := "stop", 0
	for _, raw := range list(group["guests"]) {
		m := consistency[str(obj(raw)["project"])]
		if m == "" {
			m = "stop"
		}
		if r := rank[m]; r > best {
			best, mode = r, m
		}
	}
	return mode
}

// backupGroups exports one consistency group at a time according to each
// project's declared backup.consistency ("stop", "quiesce", or "none").
// In "stop" mode, guests stop before export and restart immediately after;
// a group whose guests cannot all be restarted stops the backup with their
// identities still in restart-pending.json (#107).
func backupGroups(selected []M, destination, generation string, consistency map[string]string) ([]any, error) {
	windows := []any{}
	for index, group := range selected {
		mode := groupConsistency(group, consistency)
		var members []any
		pending := []any{}
		for _, raw := range list(group["guests"]) {
			g := obj(raw)
			members = append(members, str(g["project"])+"/"+str(g["name"]))
			if mode == "stop" && str(g["status"]) == "Running" {
				pending = append(pending, instanceIdentity(g))
			}
		}
		if err := saveRestartPending(pending); err != nil {
			return nil, err
		}
		started := now()
		err := func() (err error) {
			defer func() {
				if len(pending) > 0 {
					backupProgress("recovering", M{"generation": generation, "members": members})
					if recoverErr := backupRecover(); recoverErr != nil && err == nil {
						err = recoverErr
					}
				}
			}()
			backupProgress("exporting", M{"generation": generation, "group": index + 1, "groups": len(selected), "members": members, "consistency": mode})
			for _, raw := range pending {
				g := obj(raw)
				if err := verifyIdentity(g); err != nil {
					return err
				}
				if isTrue(g["compose"]) {
					if err := setComposeStopped(backupIncus, str(g["project"]), str(g["name"]), true); err != nil {
						return err
					}
				}
				if _, err := backupIncus(0, "stop", str(g["name"]), "--project", str(g["project"]), "--timeout", "180"); err != nil {
					return err
				}
			}
			var tempSnaps [][3]string
			defer func() {
				for _, snap := range tempSnaps {
					backupIncus(60*time.Second, "snapshot", "delete", snap[1], snap[2], "--project", snap[0])
				}
			}()
			if mode == "quiesce" {
				snapName := "nixus-backup-quiesce"
				for _, raw := range list(group["guests"]) {
					g := obj(raw)
					proj, name := str(g["project"]), str(g["name"])
					if _, err := backupIncus(120*time.Second, "snapshot", "create", name, snapName, "--project", proj); err != nil {
						return err
					}
					tempSnaps = append(tempSnaps, [3]string{proj, name, snapName})
				}
			}
			for _, raw := range list(group["guests"]) {
				g := obj(raw)
				if err := verifyIdentity(instanceIdentity(g)); err != nil {
					return err
				}
				if err := backupExport([]string{"export", str(g["name"]), "--project", str(g["project"]), "--instance-only"}, str(g["archive"]), destination); err != nil {
					return err
				}
			}
			for _, raw := range list(group["volumes"]) {
				v := obj(raw)
				if err := backupExport([]string{"storage", "volume", "export", str(v["pool"]), str(v["name"]), "--project", str(v["project"]), "--volume-only"},
					str(v["archive"]), destination); err != nil {
					return err
				}
			}
			return nil
		}()
		if err != nil {
			return nil, err
		}
		windows = append(windows, M{"members": members, "consistency": mode, "started": started, "finished": now()})
	}
	return windows, nil
}
