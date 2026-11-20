package main

// Read-only impact planning using the same ownership decisions as
// activation. Public plans expose identities and changed field names only.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const impactVersion = 1
const impactLimit = 256
const impactMaxBytes = 2 * 1024 * 1024

var impactBlocking = map[string]bool{"migration-required": true, "ownership-conflict": true}
var recoveryBoundaries = []any{
	"OS rollback restores host code/settings, not guest disks, databases or Incus schema.",
	"Incus owns native guests, consoles, networks and volumes; declared project source owns stacks.",
	"Router routes, external DNS, Cloudflare accounts and physical switches require separate review.",
	"Unit changes may reload or restart services; exact activation behavior remains in dry-activation output.",
	"The plan covers modeled declarations and observed consumers; arbitrary Nix code can have additional effects.",
}

// ReviewRequired means runtime drift refreshed the impact plan.
type ReviewRequired struct{ msg string }

func (e *ReviewRequired) Error() string { return e.msg }

func changedFields(before, after any, prefix string) []string {
	bm, ok1 := before.(M)
	am, ok2 := after.(M)
	if ok1 && ok2 {
		all := map[string]bool{}
		for k := range bm {
			all[k] = true
		}
		for k := range am {
			all[k] = true
		}
		names := make([]string, 0, len(all))
		for k := range all {
			names = append(names, k)
		}
		sort.Strings(names)
		var fields []string
		for _, k := range names {
			name := k
			if prefix != "" {
				name = prefix + "." + k
			}
			bv, bok := bm[k]
			av, aok := am[k]
			if !bok || !aok {
				value := av
				if !aok {
					value = bv
				}
				if vm, ok := value.(M); ok && len(vm) > 0 {
					fields = append(fields, changedFields(M{}, vm, name)...)
				} else {
					fields = append(fields, name)
				}
			} else {
				fields = append(fields, changedFields(bv, av, name)...)
			}
		}
		return fields
	}
	if !equalJSON(before, after) {
		return []string{prefix}
	}
	return nil
}

func declarations(preseed M) map[string]M {
	out := map[string]M{}
	for _, o := range infraObjects(preseed) {
		out[o.identity] = o.declaration
	}
	return out
}

func impactBaseline(settings M) M {
	owned := readObj(infrastructureState)
	if len(owned) == 0 {
		owned = M{"objects": M{}, "declarations": M{}}
	}
	preseedRaw, _ := readJSON("/etc/nixus/owned-infrastructure.json", nil)
	preseed := obj(preseedRaw)
	if preseedRaw == nil {
		preseed = M{}
		for identity, value := range obj(owned["declarations"]) {
			kind, rest, _ := strings.Cut(identity, ":")
			project, name, _ := strings.Cut(rest, "/")
			item := cloneM(obj(value))
			item["name"] = name
			if kind == "profiles" {
				item["project"] = project
			}
			preseed[kind] = append(list(preseed[kind]), item)
		}
	}
	system, _ := filepath.EvalSymlinks("/run/current-system")
	effective := readObj("/etc/nixus/effective-settings.json")
	instances, _ := readJSON("/etc/nixus/desired-instances.json", []any{})
	return M{"settings": settings, "hostSystem": system, "hostSettingsDigest": digestJSON(effective),
		"expectedIncus": isTrue(effective["ready"]), "disks": readObj("/etc/nixus/effective-disks.json"),
		"instances": instances, "preseed": preseed}
}

type impactReader struct{ deadline time.Time }

func (r impactReader) read(p string, allowMissing bool) (any, string, error) {
	remaining := time.Until(r.deadline)
	if remaining <= 0 {
		return nil, "", Hidden("Inventory deadline exceeded")
	}
	if remaining > 5*time.Second {
		remaining = 5 * time.Second
	}
	payload, etag, status, err := incusAPI("GET", p, nil, "", remaining, impactMaxBytes)
	if err != nil {
		if status == 404 && allowMissing {
			return nil, "", nil
		}
		return nil, "", err
	}
	if status == 404 && allowMissing {
		return nil, "", nil
	}
	if status != 200 || str(payload["type"]) == "error" {
		return nil, "", Hidden("Incus inventory unavailable")
	}
	md, ok := payload["metadata"]
	if !ok {
		return nil, "", Hidden("Invalid Incus response")
	}
	return md, etag, nil
}

func (r impactReader) listing(p string) ([]M, error) {
	v, _, err := r.read(p, false)
	if err != nil {
		return nil, err
	}
	l, ok := v.([]any)
	if !ok || len(l) > impactLimit {
		return nil, Hidden("Inventory limit exceeded")
	}
	out := make([]M, 0, len(l))
	for _, item := range l {
		m := obj(item)
		if m == nil || !isStr(m["name"]) {
			return nil, Hidden("Invalid inventory shape")
		}
		for _, k := range []string{"config", "devices"} {
			if v, ok := m[k]; ok && obj(v) == nil && v != nil {
				return nil, Hidden("Invalid configuration shape")
			}
		}
		out = append(out, m)
	}
	return out, nil
}

func impactCapture(candidate M) M {
	system, _ := filepath.EvalSymlinks("/run/current-system")
	owned := readObj(infrastructureState)
	if len(owned) == 0 {
		owned = M{"objects": M{}, "declarations": M{}}
	}
	snapshot := M{"state": "absent", "system": system, "settingsDigest": digestJSON(readObj("/etc/nixus/effective-settings.json")),
		"owned": owned, "objects": M{}, "guests": []any{}, "resources": M{}, "projects": M{}, "server": M{}}
	if !exists(incusSocket) {
		if exists("/var/lib/incus/database") {
			snapshot["state"] = "unavailable"
		}
		return snapshot
	}
	r := impactReader{time.Now().Add(30 * time.Second)}
	err := func() error {
		server, _, err := r.read("/1.0", false)
		if err != nil || obj(server) == nil {
			return Hidden("Invalid server metadata")
		}
		config := obj(server)["config"]
		if config != nil && obj(config) == nil {
			return Hidden("Invalid server configuration")
		}
		if config == nil {
			config = M{}
		}
		snapshot["server"] = config
		guests, err := r.listing("/1.0/instances?all-projects=true&recursion=1")
		if err != nil {
			return err
		}
		projects, err := r.listing("/1.0/projects?recursion=1")
		if err != nil {
			return err
		}
		if len(projects) > 16 {
			return Hidden("Project inventory limit exceeded")
		}
		projectConfigs := M{}
		for _, p := range projects {
			c := obj(p["config"])
			if c == nil {
				c = M{}
			}
			projectConfigs[str(p["name"])] = c
		}
		snapshot["projects"] = projectConfigs
		resources := obj(snapshot["resources"])
		for _, pair := range [][2]string{{"storage_pools", "storage-pools"}, {"networks", "networks"}, {"projects", "projects"}} {
			values := projects
			if pair[0] != "projects" {
				if values, err = r.listing("/1.0/" + pair[1] + "?recursion=1"); err != nil {
					return err
				}
			}
			for _, item := range values {
				resources[pair[0]+":default/"+str(item["name"])] = item
			}
		}
		for _, project := range projects {
			name := str(project["name"])
			pc := obj(project["config"])
			if name != "default" && str(pc["features.networks"]) == "true" {
				items, err := r.listing("/1.0/networks?recursion=1&project=" + url.QueryEscape(name))
				if err != nil {
					return err
				}
				for _, item := range items {
					resources["networks:"+name+"/"+str(item["name"])] = item
				}
			}
			if name != "default" && str(pc["features.profiles"]) == "false" {
				continue
			}
			items, err := r.listing("/1.0/profiles?recursion=1&project=" + url.QueryEscape(name))
			if err != nil {
				return err
			}
			for _, item := range items {
				resources["profiles:"+name+"/"+str(item["name"])] = item
			}
		}
		objects := obj(snapshot["objects"])
		for _, o := range infraObjects(obj(candidate["preseed"])) {
			value, etag, err := r.read(o.path, true)
			if err != nil {
				return err
			}
			var e any = etag
			if value == nil {
				e = nil
			}
			objects[o.identity] = M{"value": value, "etag": e}
		}
		guestList := []any{}
		for _, guest := range guests {
			project := "default"
			if p, ok := guest["project"]; ok {
				project = str(p)
			}
			if str(jget(guest, "config", OWNER)) == "true" {
				value, etag, err := r.read(instancePath(project, str(guest["name"])), false)
				if err != nil {
					return err
				}
				for k, v := range obj(value) {
					guest[k] = v
				}
				guest["_etag"] = etag
			}
			guestList = append(guestList, guest)
		}
		snapshot["guests"] = guestList
		if len(resources)+len(objects) > impactLimit {
			return Hidden("Resource inventory limit exceeded")
		}
		snapshot["state"] = "observed"
		return nil
	}()
	if err != nil {
		snapshot["state"] = "unavailable"
	}
	return snapshot
}

func impactFingerprint(snapshot M) string {
	guests := []any{}
	for _, raw := range list(snapshot["guests"]) {
		item := obj(raw)
		value := M{}
		for _, k := range []string{"name", "project", "type", "profiles", "devices", "expanded_devices"} {
			value[k] = item[k]
		}
		if str(jget(item, "config", OWNER)) == "true" {
			config := M{}
			for k, v := range obj(item["config"]) {
				if !strings.HasPrefix(k, "volatile.") {
					config[k] = v
				}
			}
			value["config"] = config
		}
		guests = append(guests, value)
	}
	sort.Slice(guests, func(i, j int) bool {
		a, b := obj(guests[i]), obj(guests[j])
		pa, pb := str(a["project"]), str(b["project"])
		if pa == "" {
			pa = "default"
		}
		if pb == "" {
			pb = "default"
		}
		if pa != pb {
			return pa < pb
		}
		return str(a["name"]) < str(b["name"])
	})
	objects := M{}
	for k, v := range obj(snapshot["objects"]) {
		value := obj(obj(v)["value"])
		if value == nil {
			value = M{}
		}
		objects[k] = M{"value": infraStable(value), "etag": obj(v)["etag"]}
	}
	resources := M{}
	for k, v := range obj(snapshot["resources"]) {
		resources[k] = infraStable(obj(v))
	}
	server := snapshot["server"]
	if server == nil {
		server = M{}
	}
	return digestJSON(M{"state": snapshot["state"], "system": snapshot["system"], "settingsDigest": snapshot["settingsDigest"],
		"owned": snapshot["owned"], "projects": snapshot["projects"], "server": server, "objects": objects,
		"resources": resources, "guests": guests})
}

var unitSuffix = map[string]bool{".service": true, ".socket": true, ".timer": true, ".target": true, ".mount": true}

func impactUnits(system string) (M, error) {
	root := filepath.Join(system, "etc/systemd/system")
	result := M{}
	entries, err := os.ReadDir(root)
	if err != nil {
		return result, nil
	}
	for _, e := range entries {
		if !unitSuffix[filepath.Ext(e.Name())] {
			continue
		}
		if len(result) >= 1024 {
			return nil, Hidden("Unit inventory limit exceeded")
		}
		files := []string{filepath.Join(root, e.Name())}
		dropins, _ := filepath.Glob(filepath.Join(root, e.Name()+".d", "*.conf"))
		sort.Strings(dropins)
		files = append(files, dropins...)
		var content []any
		for _, f := range files {
			if info, err := os.Stat(f); err == nil && info.Mode().IsRegular() {
				if info.Size() > impactMaxBytes {
					return nil, Hidden("Unit exceeds size limit")
				}
				data, _ := os.ReadFile(f)
				h := sha256.Sum256(data)
				content = append(content, hex.EncodeToString(h[:]))
			} else {
				resolved, _ := filepath.EvalSymlinks(f)
				if resolved == "" {
					resolved, _ = filepath.Abs(f)
				}
				content = append(content, resolved)
			}
		}
		result[e.Name()] = digestJSON(content)
	}
	return result, nil
}

func impactConsumers(identity string, snapshot M) []string {
	kind, rest, _ := strings.Cut(identity, ":")
	project, name, _ := strings.Cut(rest, "/")
	projects := obj(snapshot["projects"])
	if kind == "profiles" && str(obj(projects[project])["features.profiles"]) == "false" {
		project = "default"
	}
	var result []string
	for _, raw := range list(snapshot["guests"]) {
		guest := obj(raw)
		namespace := "default"
		if p, ok := guest["project"]; ok {
			namespace = str(p)
		}
		config := obj(projects[namespace])
		profileNS := namespace
		if str(config["features.profiles"]) == "false" {
			profileNS = "default"
		}
		networkNS := "default"
		if str(config["features.networks"]) == "true" {
			networkNS = namespace
		}
		devices := obj(guest["expanded_devices"])
		if devices == nil {
			devices = obj(guest["devices"])
		}
		used := false
		switch kind {
		case "profiles":
			if project == profileNS {
				for _, p := range list(guest["profiles"]) {
					if str(p) == name {
						used = true
					}
				}
			}
		case "storage_pools":
			for _, d := range devices {
				if str(obj(d)["pool"]) == name {
					used = true
				}
			}
		case "networks":
			if project == networkNS {
				for _, d := range devices {
					if str(obj(d)["network"]) == name || str(obj(d)["parent"]) == name {
						used = true
					}
				}
			}
		case "projects":
			used = namespace == name
		}
		if used {
			result = append(result, namespace+"/"+str(guest["name"]))
		}
	}
	sort.Strings(result)
	return result
}

func configuredBridgePorts(settings M) map[string]string {
	out := map[string]string{}
	for _, b := range list(jget(settings, "connectivity", "bridges")) {
		bridge := obj(b)
		for _, p := range list(bridge["interfaces"]) {
			out[str(p)] = str(bridge["name"])
		}
	}
	return out
}

type impactPlanner struct {
	changes, ownership []any
}

func (p *impactPlanner) add(scope, identity, kind, message string, affected, fields []string, blocked bool, resolution any) {
	p.changes = append(p.changes, M{"scope": scope, "identity": identity, "kind": kind, "message": message,
		"affected": strings2any(nonNil(affected)), "fields": strings2any(nonNil(fields)),
		"blocked": blocked || impactBlocking[kind], "resolution": resolution})
}

func makeImpactPlan(before, after, snapshot M, unitChanges []string, opaque, transitionError bool, original M) M {
	p := &impactPlanner{changes: []any{}, ownership: []any{}}
	state := str(snapshot["state"])
	if state == "unavailable" {
		p.add("runtime", "incus", "unknown", "Runtime inventory is incomplete or unavailable.", nil, nil, true,
			"Restore local Incus access and build a new review; an empty inventory is not assumed.")
	}
	expected := isTrue(jget(before, "settings", "ready"))
	if v, ok := before["expectedIncus"]; ok {
		expected = isTrue(v)
	}
	if state == "absent" && expected {
		p.add("runtime", "missing-incus-state", "unknown", "This host previously expected Incus, but its database/socket are absent.", nil, nil, true,
			"Check backing storage and recover Incus state. Do not initialize empty replacement guests as a recovery shortcut.")
	}
	if original != nil {
		for _, k := range []string{"system", "settingsDigest", "state"} {
			if !equalJSON(snapshot[k], original[k]) {
				p.add("host", "active-generation", "unknown", "The active host generation, settings or Incus availability changed.", nil, nil, true,
					"Build a new candidate against the active host.")
				break
			}
		}
	}
	serverBefore := obj(jget(before, "preseed", "config"))
	serverAfter := obj(jget(after, "preseed", "config"))
	if len(serverAfter) > 0 {
		p.ownership = append(p.ownership, M{"identity": "incus-server", "owner": "Nix declared keys; other keys remain Incus",
			"fields": strings2any(keys(serverAfter)), "consumers": []any{}})
	}
	if f := changedFields(nilM(serverBefore), nilM(serverAfter), ""); len(f) > 0 {
		p.add("infrastructure", "incus-server", "restart-required", "Source-owned server settings change.", nil, f, false, nil)
	}
	if state == "observed" {
		server := obj(snapshot["server"])
		for key, value := range serverAfter {
			actual := server[key]
			if !equalJSON(actual, serverBefore[key]) && !equalJSON(actual, value) {
				p.add("infrastructure", "incus-server", "ownership-conflict", "Runtime server settings differ from their source-owned values.", nil, nil, false,
					"Inspect the declared server keys locally; restore their declared values or explicitly adopt them in source before reviewing another change.")
				break
			}
		}
	}
	old, newDecl := declarations(obj(before["preseed"])), declarations(obj(after["preseed"]))
	observed := map[string]M{}
	for k, v := range obj(snapshot["objects"]) {
		if value := obj(obj(v)["value"]); value != nil {
			observed[k] = value
		}
	}
	conflictSet := map[string]bool{}
	if state == "observed" {
		for _, c := range infraConflicts(obj(after["preseed"]), obj(snapshot["owned"]), observed) {
			conflictSet[c] = true
		}
	}
	identities := map[string]bool{}
	for k := range old {
		identities[k] = true
	}
	for k := range newDecl {
		identities[k] = true
	}
	for _, identity := range sortedKeys(identities) {
		fields := changedFields(nilM(old[identity]), nilM(newDecl[identity]), "")
		affected := impactConsumers(identity, snapshot)
		if decl, ok := newDecl[identity]; ok {
			p.ownership = append(p.ownership, M{"identity": identity, "owner": "Nixus / Nix", "fields": strings2any(nonNil(changedFields(M{}, decl, ""))),
				"consumers": strings2any(nonNil(affected))})
		}
		if conflictSet[identity] {
			p.add("infrastructure", identity, "ownership-conflict", "Native edits conflict with source-owned infrastructure.", affected, nil, false,
				"Inspect this object in Incus. Restore its declared fields or explicitly review the corresponding Nix declaration; do not delete the ownership ledger.")
		}
		if len(fields) == 0 {
			continue
		}
		if _, ok := newDecl[identity]; !ok {
			p.add("infrastructure", identity, "configuration", "Declaration removed; native resource is retained, never deleted.", affected, fields, false, nil)
			continue
		}
		kind := "configuration"
		if _, ok := old[identity]; ok {
			kind = "restart-required"
		}
		immutable := false
		for _, f := range fields {
			switch {
			case strings.HasPrefix(identity, "storage_pools:") && (f == "driver" || f == "config.source"):
				immutable = true
			case strings.HasPrefix(identity, "networks:") && (f == "type" || f == "config.ipv4.address" || f == "config.ipv6.address"):
				immutable = true
			case strings.HasPrefix(identity, "profiles:") && strings.HasPrefix(f, "devices."):
				last := f[strings.LastIndex(f, ".")+1:]
				switch last {
				case "type", "pool", "source", "path", "network", "parent", "nictype":
					immutable = true
				}
			}
		}
		_, inResources := obj(snapshot["resources"])[identity]
		existsNow := observed[identity] != nil || inResources
		if existsNow && immutable && (len(affected) > 0 || strings.HasPrefix(identity, "storage_pools:") || strings.HasPrefix(identity, "networks:")) {
			kind = "migration-required"
		}
		var resolution any
		if kind == "migration-required" {
			resolution = "Migrate consumers and backing resources explicitly, then rebuild the review."
		}
		p.add("infrastructure", identity, kind, "Changed source-owned fields may affect every listed consumer.", affected, fields, false, resolution)
	}
	for _, identity := range keys(obj(snapshot["resources"])) {
		if _, ok := newDecl[identity]; ok {
			continue
		}
		p.ownership = append(p.ownership, M{"identity": identity, "owner": "Incus", "fields": []any{},
			"consumers": strings2any(nonNil(impactConsumers(identity, snapshot)))})
	}
	guests := map[string]M{}
	for _, raw := range list(snapshot["guests"]) {
		g := obj(raw)
		project := "default"
		if v, ok := g["project"]; ok {
			project = str(v)
		}
		guests[project+"/"+str(g["name"])] = g
	}
	previousPorts := configuredBridgePorts(obj(before["settings"]))
	changedPorts := map[string]string{}
	for port, bridge := range configuredBridgePorts(obj(after["settings"])) {
		if previousPorts[port] != bridge {
			changedPorts[port] = bridge
		}
	}
	if len(changedPorts) > 0 {
		for _, identity := range keys(mapToM(guests)) {
			guest := guests[identity]
			local := obj(guest["devices"])
			devices := obj(guest["expanded_devices"])
			if devices == nil {
				devices = local
			}
			for _, name := range keys(devices) {
				device := obj(devices[name])
				bridge := macvlanBridge(device, changedPorts)
				if bridge == "" {
					continue
				}
				origin := "Profile device"
				if _, ok := local[name]; ok {
					origin = "Instance device"
				}
				p.add("guest", identity, "migration-required",
					fmt.Sprintf("%s %s uses macvlan on %s, a port of the proposed %s bridge.", origin, name, str(device["parent"]), bridge),
					[]string{identity}, []string{"devices." + name + ".parent"}, false,
					"Review a bridged attachment in Incus before applying. Preserve other NICs and inspect every consumer of a shared profile.")
			}
		}
	}
	desired, prior := map[string]M{}, map[string]M{}
	for _, raw := range list(after["instances"]) {
		g := obj(raw)
		desired[str(g["project"])+"/"+str(g["name"])] = g
	}
	for _, raw := range list(before["instances"]) {
		g := obj(raw)
		prior[str(g["project"])+"/"+str(g["name"])] = g
	}
	handled := map[string]bool{}
	for _, identity := range keys(mapToM(desired)) {
		spec := desired[identity]
		current := guests[identity]
		owned := str(jget(current, "config", OWNER)) == "true"
		if isTrue(spec["manageExistingOnly"]) && (current == nil || !owned) {
			continue
		}
		handled[identity] = true
		owner := "Nix declared fields; other fields remain Incus"
		if current != nil && !owned {
			owner = "Incus; declaration conflicts"
		}
		var fields []string
		if state, err := desiredState(spec); err == nil {
			for _, f := range changedFields(M{}, state, "") {
				if f != "version" {
					fields = append(fields, f)
				}
			}
		}
		p.ownership = append(p.ownership, M{"identity": "instance:" + identity, "owner": owner, "fields": strings2any(nonNil(fields)),
			"consumers": []any{identity}})
		if current == nil {
			p.add("guest", identity, "configuration", "New guest initialized once; future image changes do not replace its disk.", []string{identity}, nil, false, nil)
			continue
		}
		updated, err := reconcilePlan(current, spec)
		if err != nil {
			msg := strings.ToLower(publicError(err))
			kind := "ownership-conflict"
			if strings.Contains(msg, "migration") || strings.Contains(msg, "immutable") || strings.Contains(msg, "backing") {
				kind = "migration-required"
			}
			p.add("guest", identity, kind, "Guest reconciliation refuses these fields: "+publicError(err), []string{identity}, nil, false,
				"Inspect this guest in Incus and its Nix declaration. Resolve the named conflict or perform an explicit migration; no automatic adoption or deletion occurs.")
			continue
		}
		if updated != nil {
			sub := M{}
			for k := range updated {
				sub[k] = current[k]
			}
			var fields []string
			for _, f := range changedFields(sub, updated, "") {
				if f != "config."+LAST_APPLIED {
					fields = append(fields, f)
				}
			}
			p.add("guest", identity, "restart-required", "Declared guest fields change; inspect live/hotplug and restart requirements in Incus.", []string{identity}, fields, false, nil)
		}
		if isTrue(spec["stop"]) || isTrue(spec["start"]) {
			p.add("guest", identity, "restart-required", "The declaration explicitly requests a guest start or stop.", []string{identity}, nil, false, nil)
		}
	}
	for _, identity := range keys(mapToM(prior)) {
		if _, ok := desired[identity]; !ok {
			p.add("guest", identity, "configuration", "Declaration removed; guest and persistent disks remain untouched.", []string{identity}, nil, false, nil)
		}
	}
	for _, identity := range keys(mapToM(guests)) {
		if !handled[identity] {
			p.ownership = append(p.ownership, M{"identity": "instance:" + identity, "owner": "Incus; not adopted by this review", "fields": []any{}, "consumers": []any{}})
		}
	}
	oldMounts, newMounts := M{}, M{}
	for _, m := range list(jget(before, "settings", "mounts")) {
		oldMounts[str(obj(m)["name"])] = m
	}
	for k, v := range obj(before["disks"]) {
		oldMounts[k] = v
	}
	for _, m := range list(jget(after, "settings", "mounts")) {
		newMounts[str(obj(m)["name"])] = m
	}
	for k, v := range obj(after["disks"]) {
		newMounts[k] = v
	}
	allMounts := map[string]bool{}
	for k := range oldMounts {
		allMounts[k] = true
	}
	for k := range newMounts {
		allMounts[k] = true
	}
	for _, name := range sortedKeys(allMounts) {
		a, b := obj(oldMounts[name]), obj(newMounts[name])
		fields := changedFields(nilM(a), nilM(b), "")
		if len(fields) == 0 {
			continue
		}
		mpath := str(a["path"])
		onMount := func(source string) bool {
			return mpath != "" && (source == mpath || strings.HasPrefix(source, strings.TrimRight(mpath, "/")+"/"))
		}
		all := M{}
		for k, v := range obj(snapshot["resources"]) {
			all[k] = v
		}
		for k, v := range obj(snapshot["objects"]) {
			value := obj(obj(v)["value"])
			if value == nil {
				value = M{}
			}
			all[k] = value
		}
		var pools []string
		for _, key := range keys(all) {
			if strings.HasPrefix(key, "storage_pools:") && onMount(str(jget(obj(all[key]), "config", "source"))) {
				pools = append(pools, key)
			}
		}
		affected := map[string]bool{}
		for _, pool := range pools {
			affected[pool] = true
			for _, c := range impactConsumers(pool, snapshot) {
				affected[c] = true
			}
		}
		for identity, guest := range guests {
			devices := obj(guest["expanded_devices"])
			if devices == nil {
				devices = obj(guest["devices"])
			}
			for _, d := range devices {
				if onMount(str(obj(d)["source"])) {
					affected[identity] = true
				}
			}
		}
		role := str(a["role"])
		_, inDisks := obj(before["disks"])[name]
		critical := len(a) > 0 && (len(affected) > 0 || role == "guests" || role == "pool" || inDisks)
		criticalField := false
		for _, f := range fields {
			if f == "uuid" || f == "path" || f == "fsType" || f == "role" {
				criticalField = true
			}
		}
		critical = critical && criticalField
		if isTrue(a["required"]) {
			affected["nixus-storage.target"] = true
		}
		incusMount := len(pools) > 0 || role == "guests" || role == "pool"
		if incusMount {
			affected["incus.service"], affected["incus-preseed.service"], affected["nixus-instances.service"] = true, true, true
		}
		backup := obj(jget(before, "settings", "backup"))
		if isTrue(backup["enable"]) && (incusMount || role == "backup" || onMount(str(backup["stagingDirectory"]))) {
			affected["restic-backups-nixus.service"] = true
		}
		kind := "restart-required"
		var resolution any
		if critical {
			kind = "migration-required"
			resolution = "Move dependent data/consumers before remapping or removing this filesystem."
		}
		p.add("mount", name, kind, "Backing filesystem changes require reviewing dependent pools, guests and backup services.",
			sortedKeys(affected), fields, false, resolution)
	}
	if transitionError {
		p.add("storage/network", "initialized-state", "migration-required", "An existing disk, pool or guest subnet cannot be remapped by this activation.",
			nil, nil, false, "Complete an explicit storage/network migration, then build a new review.")
	}
	if f := changedFields(before["settings"], after["settings"], ""); len(f) > 0 {
		p.add("host", "effective-settings", "restart-required", "Host service, access or maintenance settings change.", nil, f, false, nil)
	}
	for _, unit := range unitChanges {
		p.add("service", unit, "restart-required", "Unit definition added, changed or removed; activation may reload/restart it.", nil, nil, false, nil)
	}
	if opaque {
		p.add("source", "Nix-modules/platform", "unknown", "Arbitrary Nix code and package effects are not completely modeled. Review code and dry-activation output.", nil, nil, false, nil)
	}
	p.ownership = append(p.ownership,
		M{"identity": "applications", "owner": "Declared Incus project or Compose source", "fields": []any{}, "consumers": []any{}},
		M{"identity": "external-network-and-data", "owner": "Router, DNS, Cloudflare and application administrators", "fields": []any{}, "consumers": []any{}})
	blocked := false
	for _, c := range p.changes {
		if isTrue(obj(c)["blocked"]) {
			blocked = true
		}
	}
	return M{"format": impactVersion, "generatedAt": time.Now().Unix(), "runtimeDigest": impactFingerprint(snapshot),
		"blocked": blocked, "changes": p.changes, "ownership": p.ownership, "boundaries": recoveryBoundaries,
		"runtimeState": state, "preconditionCount": len(obj(snapshot["objects"])) + len(list(snapshot["guests"]))}
}

func nilM(m M) M {
	if m == nil {
		return M{}
	}
	return m
}

func mapToM[T any](in map[string]T) M {
	out := M{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func impactSave(directory string, bundle, plan M) error {
	if len(jsonFile(bundle)) > 8*impactMaxBytes {
		return Public("Impact inventory exceeds size limit")
	}
	if err := writeJSON(filepath.Join(directory, "impact.json"), bundle); err != nil {
		return err
	}
	job, err := readJobRecord(filepath.Join(directory, "job.json"), nil)
	if err != nil {
		return err
	}
	job["impactPlan"] = plan
	job["impactDigest"] = digestJSON(bundle)
	return writeJSON(filepath.Join(directory, "job.json"), job)
}

func impactPrepare(directory string, before, after M, opaque, transitionError bool) error {
	snapshot := impactCapture(after)
	live, err := impactUnits(str(snapshot["system"]))
	if err != nil {
		return err
	}
	target, err := impactUnits(filepath.Join(directory, "system"))
	if err != nil {
		return err
	}
	all := map[string]bool{}
	for k := range live {
		all[k] = true
	}
	for k := range target {
		all[k] = true
	}
	var changed []string
	for _, k := range sortedKeys(all) {
		if !equalJSON(live[k], target[k]) {
			changed = append(changed, k)
		}
	}
	system := before["hostSystem"]
	if system == nil {
		system = snapshot["system"]
	}
	settingsDigest := before["hostSettingsDigest"]
	if settingsDigest == nil {
		settingsDigest = snapshot["settingsDigest"]
	}
	original := M{"system": system, "settingsDigest": settingsDigest, "state": snapshot["state"]}
	bundle := M{"format": impactVersion, "before": before, "after": after, "snapshot": snapshot, "originalHost": original,
		"units": strings2any(nonNil(changed)), "opaque": opaque, "transitionError": transitionError}
	plan := makeImpactPlan(before, after, snapshot, changed, opaque, transitionError, original)
	return impactSave(directory, normalize(bundle).(M), plan)
}

func impactRecheck(directory string) error {
	job, err := readJobRecord(filepath.Join(directory, "job.json"), nil)
	if err != nil {
		return err
	}
	p := filepath.Join(directory, "impact.json")
	info, err := os.Stat(p)
	if err != nil || !info.Mode().IsRegular() {
		return Public("Candidate has no impact plan; build a new review")
	}
	if info.Size() > 8*impactMaxBytes {
		return Public("Impact plan exceeds size limit")
	}
	bundle, err := mustReadObj(p)
	if err != nil {
		return err
	}
	if v, _ := num(bundle["format"]); v != impactVersion || str(job["impactDigest"]) != digestJSON(bundle) {
		return Public("Impact evidence changed; build a new review")
	}
	fresh := impactCapture(obj(bundle["after"]))
	units, _ := anyStrings(bundle["units"])
	plan := makeImpactPlan(obj(bundle["before"]), obj(bundle["after"]), fresh, units, isTrue(bundle["opaque"]),
		isTrue(bundle["transitionError"]), obj(bundle["originalHost"]))
	if impactFingerprint(normalize(fresh).(M)) != impactFingerprint(obj(bundle["snapshot"])) {
		bundle["snapshot"] = fresh
		plan["refreshedAfterDrift"] = true
		if err := impactSave(directory, normalize(bundle).(M), plan); err != nil {
			return err
		}
		return &ReviewRequired{"Runtime changed since review. The impact plan was refreshed; inspect it before applying again."}
	}
	if isTrue(plan["blocked"]) {
		impactSave(directory, normalize(bundle).(M), plan)
		return Public("Impact plan contains migration, ownership or observation blockers; resolve them and rebuild the review")
	}
	return impactSave(directory, normalize(bundle).(M), plan)
}
