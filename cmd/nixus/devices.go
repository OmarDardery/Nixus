package main

// Host device listing for passthrough: serial ports with their stable
// /dev/serial/by-id path and USB devices by vendor:product, each with the
// Compose and Nix lines that pass it through.

import (
	"os"
	"path/filepath"
	"sort"
)

var usbRoot = "/sys/bus/usb/devices"

func hostDevices() M {
	serial := []any{}
	for _, raw := range serialInventory("/sys/class/tty", "/dev") {
		d := obj(raw)
		source := str(d["path"])
		for _, s := range list(d["stablePaths"]) {
			if fullmatch(serialSource, str(s)) {
				source = str(s)
				break
			}
		}
		if !fullmatch(serialSource, source) {
			continue
		}
		serial = append(serial, M{"source": source, "product": d["product"], "id": str(d["vendorId"]) + ":" + str(d["productId"]),
			"compose": "devices: [\"" + source + ":/dev/ttyACM0\"]",
			"nix":     "serial.port = { source = \"" + source + "\"; path = \"/dev/ttyACM0\"; };"})
	}
	usb := []any{}
	entries, _ := os.ReadDir(usbRoot)
	seen := map[string]bool{}
	for _, e := range entries {
		dir := filepath.Join(usbRoot, e.Name())
		vendor, product := readTrim(filepath.Join(dir, "idVendor")), readTrim(filepath.Join(dir, "idProduct"))
		id := vendor + ":" + product
		if !fullmatch(usbID, id) || vendor == "1d6b" || seen[id] {
			continue // 1d6b: Linux root hubs
		}
		seen[id] = true
		name := readTrim(filepath.Join(dir, "product"))
		if m := readTrim(filepath.Join(dir, "manufacturer")); m != "" {
			name = m + " " + name
		}
		usb = append(usb, M{"id": id, "product": name, "compose": "x-nixus: { usb: [\"" + id + "\"] }",
			"nix": "usb.device = { vendorId = \"" + vendor + "\"; productId = \"" + product + "\"; };"})
	}
	sort.Slice(usb, func(i, j int) bool { return str(obj(usb[i])["id"]) < str(obj(usb[j])["id"]) })
	return M{"serial": serial, "usb": usb}
}
