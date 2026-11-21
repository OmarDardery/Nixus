package main

import (
	"os"
	"strings"
	"testing"
)

func TestComposeDevicesSerialAndUSB(t *testing.T) {
	d, err := composeDevices([]any{"/dev/serial/by-id/usb-Klipper_rp2040-if00:/dev/ttyACM0",
		M{"source": "/dev/ttyUSB0", "target": "/dev/ttyUSB0", "permissions": "rwm"}}, M{"usb": []any{"1d50:614e"}})
	if err != nil {
		t.Fatal(err)
	}
	s0 := obj(d["nixus-serial0"])
	if s0["type"] != "unix-char" || s0["source"] != "/dev/serial/by-id/usb-Klipper_rp2040-if00" || s0["path"] != "/dev/ttyACM0" || s0["required"] != "false" {
		t.Fatalf("serial %v", s0)
	}
	if u := obj(d["nixus-usb0"]); u["vendorid"] != "1d50" || u["productid"] != "614e" || u["type"] != "usb" {
		t.Fatalf("usb %v", u)
	}
}

func TestComposeDevicesRefusesOtherDevices(t *testing.T) {
	for _, bad := range []any{[]any{"/dev/sda"}, []any{"/dev/kvm"}, []any{"/dev/mem:/dev/ttyACM0"}, []any{"/dev/ttyUSB0:/etc/passwd"},
		[]any{"/dev/serial/by-id/../../sda"}, "x", []any{M{"source": "/dev/ttyUSB0", "cgroup": "x"}}} {
		if _, err := composeDevices(bad, nil); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
	for _, bad := range []any{M{"usb": []any{"1d50"}}, M{"usb": []any{"1d50:614e"}, "disk": "x"}, "x"} {
		if _, err := composeDevices(nil, bad); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
}

func TestComposeModelEmitsDeviceOverride(t *testing.T) {
	rev := strings.Repeat("a", 64)
	model := M{"services": M{"klipper": M{"image": "ghcr.io/x/klipper@sha256:" + rev,
		"devices": []any{M{"source": "/dev/ttyACM0", "target": "/dev/ttyACM0", "permissions": "rwm"}}, "x-nixus": M{"usb": []any{"0bda:2838"}}}}}
	checked, err := validateComposeModel(model, "printer", rev, "compose.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	o := str(checked["separateOverride"])
	for _, want := range []string{"  klipper:", "    x-incus-compose:", "        nixus-serial0:", `          type: "unix-char"`, `          vendorid: "0bda"`} {
		if !strings.Contains(o, want) {
			t.Fatalf("override missing %q:\n%s", want, o)
		}
	}
	if strings.Contains(o, "build:") {
		t.Fatal("image service got a build reset")
	}
	model["services"].(M)["klipper"].(M)["x-incus-compose"] = M{}
	if _, err := validateComposeModel(model, "printer", rev, "compose.yaml", nil); err == nil {
		t.Fatal("accepted raw x-incus-compose")
	}
}

func TestHostDevicesListsUSBWithoutRootHubs(t *testing.T) {
	old := usbRoot
	defer func() { usbRoot = old }()
	usbRoot = t.TempDir()
	for name, ids := range map[string][2]string{"1-1": {"1d50", "614e"}, "usb1": {"1d6b", "0002"}} {
		dir := usbRoot + "/" + name
		os.MkdirAll(dir, 0o755)
		os.WriteFile(dir+"/idVendor", []byte(ids[0]+"\n"), 0o644)
		os.WriteFile(dir+"/idProduct", []byte(ids[1]+"\n"), 0o644)
	}
	usb := list(hostDevices()["usb"])
	if len(usb) != 1 || obj(usb[0])["id"] != "1d50:614e" || !strings.Contains(str(obj(usb[0])["compose"]), "1d50:614e") {
		t.Fatalf("%v", usb)
	}
}

func TestPublishedPorts(t *testing.T) {
	ports := publishedPorts(M{"eth0": M{"type": "nic"}, "web": M{"type": "proxy", "listen": "tcp:0.0.0.0:3000", "connect": "tcp:127.0.0.1:3000"},
		"dns": M{"type": "proxy", "listen": "udp:0.0.0.0:53"}, "bad": M{"type": "proxy", "listen": "tcp:0.0.0.0:x"}})
	if len(ports) != 1 || ports[0] != 3000 {
		t.Fatalf("%v", ports)
	}
}
