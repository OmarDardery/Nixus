package main

import (
	"strings"
	"testing"
	"time"
)

// fakeIncus answers queries from a map and records mutating commands.
type fakeIncus struct {
	objects  map[string]string
	commands [][]string
}

func (f *fakeIncus) run(_ time.Duration, args ...string) (string, error) {
	if len(args) == 2 && args[0] == "query" {
		if v, ok := f.objects[args[1]]; ok {
			return v, nil
		}
		return "", Public("not found")
	}
	f.commands = append(f.commands, args)
	return "", nil
}

func nativeFixture(t *testing.T) (*fakeIncus, M) {
	t.Helper()
	fake := &fakeIncus{objects: map[string]string{}}
	oldIncus, oldDefaults, oldClaims := nativeIncus, hostGuestDefaults, hostClaims
	nativeIncus = fake.run
	hostGuestDefaults = func() (string, string) { return "tank", "incusbr0" }
	hostClaims = func() (map[string]bool, error) { return map[string]bool{"lab/legacy": true}, nil }
	t.Cleanup(func() { nativeIncus, hostGuestDefaults, hostClaims = oldIncus, oldDefaults, oldClaims })
	project := M{"name": "beta", "enable": true, "backend": "incus-native", "incusProject": "beta",
		"resources": M{"cpus": float64(2), "memory": "2GiB"}, "secrets": M{"file": nil, "bindings": M{}},
		"backup": M{"enable": true, "consistency": "stop"}, "claims": []any{"instance/printer"}, "source": "beta", "modules": []any{},
		"storagePool": nil, "volumes": M{"printer-data": M{"size": "2GiB"}},
		"instances": M{"printer": M{"type": "container", "image": "images:debian/13", "cpus": float64(1), "memory": nil,
			"autostart": true, "network": nil, "disks": M{"data": M{"volume": "printer-data", "path": "/srv/data", "readOnly": false}},
			"usb": M{"board": M{"vendorId": "1d50", "productId": "614e"}}}}}
	return fake, project
}

func TestNativeDeclaredPlanCreatesProjectVolumeAndInstance(t *testing.T) {
	_, project := nativeFixture(t)
	if err := validateNativeDeclarations(project); err != nil {
		t.Fatal(err)
	}
	items, retained, err := nativeDeclaredPlan(project)
	if err != nil || len(items) != 3 || len(retained) != 0 {
		t.Fatalf("plan: %v %v %v", items, retained, err)
	}
	var kinds []string
	for _, i := range items {
		kinds = append(kinds, str(obj(i)["kind"])+"/"+str(obj(i)["action"]))
	}
	if strings.Join(kinds, ",") != "native-project/create,native-volume/create,native-instance/create" {
		t.Fatalf("order: %v", kinds)
	}
	spec := declaredSpec(project, "printer")
	devices := obj(spec["devices"])
	if str(jget(devices, "root", "pool")) != "tank" || str(jget(devices, "data", "source")) != "printer-data" ||
		str(jget(devices, "board", "vendorid")) != "1d50" || str(jget(spec, "config", "limits.cpu")) != "1" ||
		str(jget(spec, "config", "limits.memory")) != "2GiB" {
		t.Fatalf("spec: %v", spec)
	}
}

func TestNativeProjectOwnershipIsExclusive(t *testing.T) {
	fake, project := nativeFixture(t)
	fake.objects["/1.0/projects/beta"] = `{"name":"beta","config":{"user.nixus.owner":"true","user.nixus.backend":"incus-compose"}}`
	if _, err := nativeProjectObservation(project); err == nil {
		t.Fatal("native adapter adopted a Compose-owned project")
	}
	fake.objects["/1.0/projects/beta"] = `{"name":"beta","config":{"user.nixus.owner":"true","user.nixus.backend":"incus-native","user.nixus.project":"other"}}`
	if _, err := nativeProjectObservation(project); err == nil {
		t.Fatal("project owned by another Nixus project accepted")
	}
	fake.objects["/1.0/projects/beta"] = `{"name":"beta","config":{}}`
	item, err := nativeProjectObservation(project)
	if err != nil || item["action"] != "claim" {
		t.Fatalf("unowned project must need a reviewed claim: %v %v", item, err)
	}
	project["incusProject"] = "lab"
	if _, err := nativeProjectObservation(project); err == nil {
		t.Fatal("host-owned lab project accepted")
	}
}

func TestNativeVolumesAreNeverAdoptedOrResized(t *testing.T) {
	fake, project := nativeFixture(t)
	path := volumePath("tank", "printer-data", "beta")
	fake.objects[path] = `{"name":"printer-data","config":{"size":"2GiB"}}`
	if _, err := nativeVolumeObservation(project, "printer-data", true); err == nil {
		t.Fatal("unowned volume adopted")
	}
	fake.objects[path] = `{"name":"printer-data","config":{"size":"5GiB","user.nixus.managed":"true"}}`
	if _, err := nativeVolumeObservation(project, "printer-data", true); err == nil {
		t.Fatal("size drift silently accepted")
	}
	fake.objects[path] = `{"name":"printer-data","config":{"size":"2GiB","user.nixus.managed":"true"}}`
	if item, err := nativeVolumeObservation(project, "printer-data", true); err != nil || item["action"] != "noop" {
		t.Fatalf("owned volume: %v %v", item, err)
	}
}

func TestUndeclaredOwnedInstancesAreRetained(t *testing.T) {
	fake, project := nativeFixture(t)
	fake.objects["/1.0/projects/beta"] = `{"name":"beta","config":{"user.nixus.owner":"true","user.nixus.backend":"incus-native","user.nixus.project":"beta"}}`
	fake.objects["/1.0/instances?recursion=1&project=beta"] = `[{"name":"old","status":"Running","config":{"user.nixus.managed":"true"}},{"name":"manual","status":"Running","config":{}}]`
	retained := retainedInstances(project, map[string]bool{"printer": true})
	if len(retained) != 1 || str(obj(retained[0])["name"]) != "old" {
		t.Fatalf("retained: %v", retained)
	}
}

func TestNativeDeclarationValidation(t *testing.T) {
	_, project := nativeFixture(t)
	bad := cloneM(project)
	bad["instances"] = M{"x": M{"type": "container", "image": "docker:nginx", "cpus": nil, "memory": nil, "autostart": true,
		"network": nil, "disks": M{}, "usb": M{}}}
	if validateNativeDeclarations(bad) == nil {
		t.Fatal("non-images: remote accepted")
	}
	bad["instances"] = M{"x": M{"type": "container", "image": "images:alpine/3", "cpus": nil, "memory": nil, "autostart": true,
		"network": nil, "disks": M{"d": M{"volume": "missing", "path": "/srv", "readOnly": false}}, "usb": M{}}}
	if validateNativeDeclarations(bad) == nil {
		t.Fatal("undeclared volume accepted")
	}
	bad["backend"], bad["instances"] = "incus-compose", M{}
	if validateNativeDeclarations(bad) == nil {
		t.Fatal("Compose project declaring native volumes accepted")
	}
}
