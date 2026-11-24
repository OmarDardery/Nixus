package main

// Declared native Incus resources for incus-native projects: the owned Incus
// project, custom volumes and instance templates (image, network, storage
// and USB). Every resource has exactly one owner. Nothing is ever deleted,
// resized or stopped because a declaration disappeared.

import (
	"net/url"
	"strings"
	"time"
)

const nativeBackend = "incus-native"
const projectNameKey = "user.nixus.project"

var volumeSize = re(`[1-9][0-9]*(?:MiB|GiB|TiB)`)
var imageAlias = re(`images:[a-z0-9][a-z0-9._/-]{0,127}`)
var hex4 = re(`[0-9a-f]{4}`)
var guestPath = re(`/[A-Za-z0-9._/-]*`)
var poolName = re(`[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}`)

// nativeIncus and hostGuestDefaults are replaceable in tests.
var nativeIncus incusFunc = defaultIncus

var hostGuestDefaults = func() (string, string) {
	settings := effectiveSettingsFile()
	pool, bridge := str(jget(settings, "storage", "pool")), str(jget(settings, "guests", "bridge"))
	if pool == "" {
		pool = "default"
	}
	if bridge == "" {
		bridge = "incusbr0"
	}
	return pool, bridge
}

func validateNativeDeclarations(p M) error {
	fail := Public("Invalid declared native instance, volume or storage pool")
	if p["storagePool"] != nil && !fullmatch(poolName, str(p["storagePool"])) {
		return fail
	}
	volumes, instances := obj(p["volumes"]), obj(p["instances"])
	if volumes == nil || instances == nil || len(volumes) > 64 || len(instances) > 64 {
		return fail
	}
	if str(p["backend"]) == "incus-compose" && (len(volumes) > 0 || len(instances) > 0) {
		return Public("Compose projects cannot declare native instances or volumes")
	}
	for name, raw := range volumes {
		v := obj(raw)
		if !fullmatch(projectName, name) || !exactKeys(v, "size") || !fullmatch(volumeSize, str(v["size"])) {
			return fail
		}
	}
	for name, raw := range instances {
		i := obj(raw)
		if !fullmatch(projectName, name) || !exactKeys(i, "type", "image", "cpus", "memory", "autostart", "network", "disks", "usb", "serial") {
			return fail
		}
		if t := str(i["type"]); (t != "container" && t != "virtual-machine") || !fullmatch(imageAlias, str(i["image"])) {
			return fail
		}
		if i["cpus"] != nil {
			if n, ok := intValue(i["cpus"]); !ok || n < 1 || n > 128 {
				return fail
			}
		}
		if i["memory"] != nil && !fullmatch(memoryValue, str(i["memory"])) {
			return fail
		}
		if _, ok := i["autostart"].(bool); !ok {
			return fail
		}
		if i["network"] != nil && !fullmatch(re(`[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}`), str(i["network"])) {
			return fail
		}
		disks, usb, serial := obj(i["disks"]), obj(i["usb"]), obj(i["serial"])
		if disks == nil || usb == nil || len(disks) > 16 || len(usb) > 16 || (i["serial"] != nil && serial == nil) || len(serial) > 8 {
			return fail
		}
		for sname, sraw := range serial {
			sp := obj(sraw)
			if !fullmatch(projectName, sname) || !exactKeys(sp, "source", "path") || !fullmatch(serialSource, str(sp["source"])) ||
				!fullmatch(deviceTarget, str(sp["path"])) || strings.Contains(str(sp["source"]), "..") {
				return Public("Serial passthrough needs a /dev/serial/by-id/..., /dev/ttyACM* or /dev/ttyUSB* source and a /dev/ path")
			}
			if _, clash := disks[sname]; clash {
				return fail
			}
			if _, clash := usb[sname]; clash {
				return fail
			}
		}
		for dname, draw := range disks {
			d := obj(draw)
			if !fullmatch(projectName, dname) || dname == "root" || dname == "eth0" || !exactKeys(d, "volume", "path", "readOnly") ||
				volumes[str(d["volume"])] == nil || !fullmatch(guestPath, str(d["path"])) || str(d["path"]) == "/" ||
				strings.Contains("/"+str(d["path"])+"/", "/../") {
				return Public("Declared disks must attach a declared volume at a non-root guest path")
			}
			if _, ok := d["readOnly"].(bool); !ok {
				return fail
			}
		}
		for uname, uraw := range usb {
			u := obj(uraw)
			if !fullmatch(projectName, uname) || !exactKeys(u, "vendorId", "productId") ||
				!fullmatch(hex4, str(u["vendorId"])) || !fullmatch(hex4, str(u["productId"])) {
				return Public("USB passthrough needs four-digit hexadecimal vendor and product IDs")
			}
			if _, clash := disks[uname]; clash {
				return fail
			}
		}
	}
	return nil
}

func nativePool(project M) string {
	if p := str(project["storagePool"]); p != "" {
		return p
	}
	pool, _ := hostGuestDefaults()
	return pool
}

// declaredSpec is the complete desired Incus shape for a declared instance.
func declaredSpec(project M, name string) M {
	decl := obj(jget(project, "instances", name))
	pool := nativePool(project)
	_, bridge := hostGuestDefaults()
	if n := str(decl["network"]); n != "" {
		bridge = n
	}
	cpus, _ := intValue(jget(project, "resources", "cpus"))
	if v, ok := intValue(decl["cpus"]); ok && decl["cpus"] != nil {
		cpus = v
	}
	memory := str(jget(project, "resources", "memory"))
	if decl["memory"] != nil {
		memory = str(decl["memory"])
	}
	devices := M{
		"root": M{"type": "disk", "path": "/", "pool": pool},
		"eth0": M{"type": "nic", "name": "eth0", "network": bridge},
	}
	disks := obj(decl["disks"])
	for _, dname := range keys(disks) {
		d := obj(disks[dname])
		device := M{"type": "disk", "pool": pool, "source": d["volume"], "path": d["path"]}
		if isTrue(d["readOnly"]) {
			device["readonly"] = "true"
		}
		devices[dname] = device
	}
	usb := obj(decl["usb"])
	for _, uname := range keys(usb) {
		u := obj(usb[uname])
		devices[uname] = M{"type": "usb", "vendorid": u["vendorId"], "productid": u["productId"]}
	}
	serial := obj(decl["serial"])
	for _, sname := range keys(serial) {
		sp := obj(serial[sname])
		devices[sname] = M{"type": "unix-char", "source": sp["source"], "path": sp["path"], "required": "false", "mode": "0666"}
	}
	autostart := "false"
	if isTrue(decl["autostart"]) {
		autostart = "true"
	}
	return M{"project": project["incusProject"], "name": name, "type": decl["type"], "image": decl["image"],
		"config":  M{"limits.cpu": itoa(cpus), "limits.memory": memory, "boot.autostart": autostart},
		"devices": devices, "profiles": []any{}, "start": isTrue(decl["autostart"])}
}

func nativeQuery(p string) M { return incusQueryObj(nativeIncus, p) }

func projectConfigFingerprint(current M) string {
	return digestJSON(M{"config": current["config"], "description": current["description"]})
}

// nativeProjectObservation decides whether the Incus project must be created
// or explicitly claimed; Compose-owned, default and lab projects are refused.
func nativeProjectObservation(project M) (M, error) {
	incusProject := str(project["incusProject"])
	if incusProject == "default" || incusProject == "lab" {
		return nil, Public("Declared native resources never use the default or host-owned lab Incus project")
	}
	current := nativeQuery("/1.0/projects/" + url.PathEscape(incusProject))
	item := M{"kind": "native-project", "project": incusProject, "name": "project:" + incusProject, "sourceProject": project["name"]}
	if current == nil {
		item["action"], item["fingerprint"] = "create", nil
		item["before"], item["after"] = nil, M{"owner": "nixus", "backend": nativeBackend}
		return item, nil
	}
	config := obj(current["config"])
	switch {
	case str(config[imageBackendKey]) == composeBackend:
		return nil, Public("The native adapter never edits resources in a Compose-owned Incus project")
	case str(config[imageOwnerKey]) == "true" && str(config[imageBackendKey]) == nativeBackend:
		if owner := str(config[projectNameKey]); owner != "" && owner != str(project["name"]) {
			return nil, Public("The Incus project is owned by another Nixus project")
		}
		item["action"] = "noop"
	case str(config[imageOwnerKey]) != "":
		return nil, Public("The Incus project has a conflicting ownership marker; migrate it explicitly")
	default:
		item["action"] = "claim"
	}
	item["fingerprint"] = projectConfigFingerprint(current)
	item["before"] = M{"owner": nil}
	if item["action"] == "noop" {
		item["before"] = M{"owner": "nixus", "backend": nativeBackend}
	}
	item["after"] = M{"owner": "nixus", "backend": nativeBackend}
	return item, nil
}

func volumePath(pool, name, project string) string {
	return "/1.0/storage-pools/" + url.PathEscape(pool) + "/volumes/custom/" + url.PathEscape(name) + "?project=" + url.QueryEscape(project)
}

func nativeVolumeObservation(project M, name string, projectExists bool) (M, error) {
	pool, incusProject := nativePool(project), str(project["incusProject"])
	size := str(jget(project, "volumes", name, "size"))
	item := M{"kind": "native-volume", "project": incusProject, "name": "volume:" + name, "volume": name, "pool": pool,
		"sourceProject": project["name"], "after": M{"size": size}}
	var current M
	if projectExists {
		current = nativeQuery(volumePath(pool, name, incusProject))
	}
	if current == nil {
		item["action"], item["before"], item["fingerprint"] = "create", nil, nil
		return item, nil
	}
	config := obj(current["config"])
	if str(config[OWNER]) != "true" {
		return nil, Public("Custom volume " + name + " exists without Nixus ownership; refusing to adopt it")
	}
	if str(config["size"]) != size {
		return nil, Public("Volume " + name + " size differs from the declaration; resizing requires an explicit migration")
	}
	item["action"], item["before"], item["fingerprint"] = "noop", M{"size": config["size"]}, digestJSON(config)
	return item, nil
}

func nativeInstanceObservation(project M, name string, projectExists bool) (M, error) {
	incusProject := str(project["incusProject"])
	spec := declaredSpec(project, name)
	item := M{"kind": "native-instance", "project": incusProject, "name": name, "sourceProject": project["name"],
		"after": M{"cpus": jget(spec, "config", "limits.cpu"), "memory": jget(spec, "config", "limits.memory"), "image": spec["image"],
			"devices": sortedKeys(boolSet(obj(spec["devices"])))}, "desiredHash": digestJSON(spec)}
	if !projectExists || nativeQuery(instancePath(incusProject, name)) == nil {
		item["action"], item["before"], item["etag"], item["observedStatus"] = "create", nil, nil, "Absent"
		return item, nil
	}
	current, etag, err := readInstance(incusProject, name)
	if err != nil {
		return nil, err
	}
	update, err := reconcilePlan(current, spec)
	if err != nil {
		return nil, err
	}
	item["etag"], item["observedStatus"] = etag, truncate(str(current["status"]), 32)
	item["before"] = M{"cpus": jget(current, "config", "limits.cpu"), "memory": jget(current, "config", "limits.memory")}
	item["action"] = "noop"
	if update != nil {
		item["action"] = "update"
		item["updateHash"] = digestJSON(update)
	}
	return item, nil
}

// retainedInstances lists owned runtime instances the workspace no longer
// declares. They are reported and kept; nothing is stopped or deleted.
func retainedInstances(project M, declared map[string]bool) []any {
	incusProject := str(project["incusProject"])
	listing := incusQueryList(nativeIncus, "/1.0/instances?recursion=1&project="+url.QueryEscape(incusProject))
	retained := []any{}
	for _, raw := range listing {
		i := obj(raw)
		if str(jget(i, "config", OWNER)) == "true" && !declared[str(i["name"])] {
			retained = append(retained, M{"project": incusProject, "name": i["name"], "status": truncate(str(i["status"]), 32),
				"reason": "no longer declared; kept with its data until an explicit migration"})
		}
	}
	return retained
}

func incusQueryList(incus incusFunc, p string) []any {
	out, err := incus(30*time.Second, "query", p)
	if err != nil {
		return nil
	}
	v, err := parseJSON([]byte(out))
	if err != nil {
		return nil
	}
	return list(v)
}

// nativeDeclaredPlan returns ordered resources: project, volumes, instances.
func nativeDeclaredPlan(project M) ([]any, []any, error) {
	instances, volumes := obj(project["instances"]), obj(project["volumes"])
	if len(instances) == 0 && len(volumes) == 0 {
		return nil, nil, nil
	}
	projectItem, err := nativeProjectObservation(project)
	if err != nil {
		return nil, nil, err
	}
	exists := str(projectItem["action"]) != "create"
	items := []any{projectItem}
	for _, name := range keys(volumes) {
		v, err := nativeVolumeObservation(project, name, exists)
		if err != nil {
			return nil, nil, err
		}
		items = append(items, v)
	}
	declared := map[string]bool{}
	for _, name := range keys(instances) {
		declared[name] = true
		i, err := nativeInstanceObservation(project, name, exists)
		if err != nil {
			return nil, nil, err
		}
		items = append(items, i)
	}
	for _, claim := range list(project["claims"]) {
		if m := claimRe.FindStringSubmatch(str(claim)); m != nil && m[1] == "instance" {
			declared[m[2]] = true
		}
	}
	var retained []any
	if exists {
		retained = retainedInstances(project, declared)
	}
	return normalize(items).([]any), retained, nil
}

func nativeObserveAgain(project, resource M) (M, error) {
	switch str(resource["kind"]) {
	case "native-project":
		return nativeProjectObservation(project)
	case "native-volume":
		return nativeVolumeObservation(project, str(resource["volume"]), nativeQuery("/1.0/projects/"+url.PathEscape(str(project["incusProject"]))) != nil)
	}
	return nativeInstanceObservation(project, str(resource["name"]), nativeQuery("/1.0/projects/"+url.PathEscape(str(project["incusProject"]))) != nil)
}

// nativeApply rechecks one approved resource and applies exactly that change.
func nativeApply(project, approved M, verifyOnly bool) (M, error) {
	actual, err := nativeObserveAgain(project, approved)
	if err != nil {
		return nil, err
	}
	actual = normalize(actual).(M)
	verified := func(item M) (M, error) {
		status := str(item["observedStatus"])
		if status == "" {
			status = "present"
		}
		return M{"status": "verified", "newEtag": item["etag"], "health": status}, nil
	}
	if !equalJSON(actual, approved) {
		if verifyOnly && str(actual["action"]) == "noop" {
			return verified(actual)
		}
		return nil, Public("Incus state changed since project review; re-review before deployment")
	}
	if str(approved["action"]) == "noop" {
		return verified(approved)
	}
	incusProject := str(project["incusProject"])
	switch str(approved["kind"]) + "/" + str(approved["action"]) {
	case "native-project/create":
		_, err = nativeIncus(0, "project", "create", incusProject, "-c", "features.images=true", "-c", "features.profiles=true",
			"-c", "features.storage.volumes=true", "-c", "features.networks=false", "-c", imageOwnerKey+"=true",
			"-c", imageBackendKey+"="+nativeBackend, "-c", projectNameKey+"="+str(project["name"]))
	case "native-project/claim":
		for _, kv := range [][2]string{{imageOwnerKey, "true"}, {imageBackendKey, nativeBackend}, {projectNameKey, str(project["name"])}} {
			if _, err = nativeIncus(0, "project", "set", incusProject, kv[0]+"="+kv[1]); err != nil {
				break
			}
		}
	case "native-volume/create":
		_, err = nativeIncus(0, "storage", "volume", "create", str(approved["pool"]), str(approved["volume"]),
			"size="+str(jget(approved, "after", "size")), OWNER+"=true", "--project", incusProject)
	case "native-instance/create":
		spec := declaredSpec(project, str(approved["name"]))
		if digestJSON(spec) != str(approved["desiredHash"]) {
			return nil, Public("Declared instance differs from the approved plan")
		}
		err = createNativeInstance(spec)
	case "native-instance/update":
		current, etag, rerr := readInstance(incusProject, str(approved["name"]))
		if rerr != nil {
			return nil, rerr
		}
		if etag != str(approved["etag"]) {
			return nil, Public("Incus ETag drift during apply")
		}
		update, perr := reconcilePlan(current, declaredSpec(project, str(approved["name"])))
		if perr != nil {
			return nil, perr
		}
		if update == nil || digestJSON(update) != str(approved["updateHash"]) {
			return nil, Public("Incus update differs from approved plan")
		}
		err = writeInstance(incusProject, str(approved["name"]), update, etag)
	default:
		return nil, Public("Unsupported native project action")
	}
	if err != nil {
		return nil, Public("Incus rejected the approved native change; inspect the project and re-review")
	}
	after, err := nativeObserveAgain(project, approved)
	if err != nil {
		return nil, err
	}
	if str(after["action"]) != "noop" {
		return nil, Public("Incus resource did not reach declared desired state")
	}
	if str(approved["kind"]) == "native-instance" && isTrue(jget(project, "instances", str(approved["name"]), "autostart")) &&
		str(after["observedStatus"]) != "Running" {
		return nil, Public("Declared instance did not start; inspect it in Incus")
	}
	return verified(after)
}

// createNativeInstance initializes a declared incus-native instance, applies
// its config/devices via ETag-checked PUT, and starts it when requested.
func createNativeInstance(spec M) error {
	project, name := str(spec["project"]), str(spec["name"])
	if !fullmatch(incusIdent, project) || !fullmatch(incusIdent, name) {
		return Public("Invalid instance or project name")
	}
	args := []string{"init", str(spec["image"]), name, "--project", project, "--config", OWNER + "=true", "--config", INITIALIZING + "=true"}
	switch str(spec["type"]) {
	case "virtual-machine":
		args = append(args, "--vm")
	case "container":
	default:
		return Public("Unknown instance type")
	}
	profiles, ok := anyStrings(spec["profiles"])
	if !ok || spec["profiles"] == nil {
		profiles = []string{"base"}
	}
	if len(profiles) == 0 {
		root, nic := obj(jget(spec, "devices", "root")), obj(jget(spec, "devices", "eth0"))
		if str(root["pool"]) == "" || str(nic["network"]) == "" {
			return Public("A profile-free instance needs explicit root storage and eth0 network")
		}
		args = append(args, "--no-profiles", "--storage", str(root["pool"]), "--network", str(nic["network"]))
	}
	for _, p := range profiles {
		args = append(args, "--profile", p)
	}
	if _, err := nativeIncus(30*time.Minute, args...); err != nil {
		return err
	}
	current, etag, err := readInstance(project, name)
	if err != nil {
		return err
	}
	update, err := reconcilePlan(current, spec)
	if err != nil {
		return err
	}
	if update != nil {
		if err := writeInstance(project, name, update, etag); err != nil {
			return err
		}
	}
	if isTrue(spec["start"]) {
		if _, err := nativeIncus(5*time.Minute, "start", name, "--project", project); err != nil {
			return err
		}
	}
	_, err = nativeIncus(0, "config", "unset", name, INITIALIZING, "--project", project)
	return err
}
