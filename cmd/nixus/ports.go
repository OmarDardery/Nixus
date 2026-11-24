package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Published ports bind the server's own address, as with docker compose, so
// two apps cannot publish the same host port/protocol. portConflicts checks
// structured port entries normalized by `incus-compose config --format json`.

type hostPort struct {
	HostIP   string
	Port     int
	Protocol string
}

// composeHostPorts returns the host ports normalized by incus-compose config.
func composeHostPorts(services []any) []hostPort {
	seen := map[hostPort]bool{}
	var out []hostPort
	add := func(ip string, port int, proto string) {
		if proto == "" {
			proto = "tcp"
		}
		proto = strings.ToLower(proto)
		if proto != "tcp" && proto != "udp" {
			return
		}
		if port <= 0 || port >= 65536 {
			return
		}
		hp := hostPort{HostIP: ip, Port: port, Protocol: proto}
		if !seen[hp] {
			seen[hp] = true
			out = append(out, hp)
		}
	}
	addRange := func(ip, raw, proto string) {
		if loS, hiS, ok := strings.Cut(raw, "-"); ok {
			lo, err1 := strconv.Atoi(loS)
			hi, err2 := strconv.Atoi(hiS)
			if err1 == nil && err2 == nil && lo > 0 && hi >= lo && hi-lo < 256 {
				for p := lo; p <= hi; p++ {
					add(ip, p, proto)
				}
			}
			return
		}
		if n, err := strconv.Atoi(raw); err == nil {
			add(ip, n, proto)
		}
	}
	for _, raw := range services {
		for _, p := range list(obj(raw)["ports"]) {
			switch v := p.(type) {
			case M:
				proto := str(v["protocol"])
				ip := str(v["host_ip"])
				if f, ok := v["published"].(float64); ok {
					add(ip, int(f), proto)
				} else if s := str(v["published"]); s != "" {
					addRange(ip, s, proto)
				}
			case string:
				// Fallback for string specs in unit tests: "[ip:]host:container[/proto]"
				spec := strings.SplitN(v, "/", 2)
				proto := "tcp"
				if len(spec) == 2 && spec[1] != "" {
					proto = spec[1]
				}
				parts := strings.Split(spec[0], ":")
				if len(parts) >= 2 {
					ip := ""
					if len(parts) >= 3 {
						ip = strings.Join(parts[:len(parts)-2], ":")
					}
					addRange(ip, parts[len(parts)-2], proto)
				}
			}
		}
	}
	return out
}

type hostSocket struct {
	Protocol string
	Port     int
}

var hostListening = func() map[hostSocket]bool {
	out := map[hostSocket]bool{}
	res, err := run([]string{"ss", "-ltnuH"}, nil, 10*time.Second, nil, "")
	if err != nil || res.Code != 0 {
		return out
	}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		proto := strings.ToLower(fields[0])
		if proto != "tcp" && proto != "udp" {
			continue
		}
		local := fields[4]
		if i := strings.LastIndex(local, ":"); i >= 0 {
			if n, err := strconv.Atoi(local[i+1:]); err == nil {
				out[hostSocket{Protocol: proto, Port: n}] = true
			}
		}
	}
	return out
}

func publishedSockets(devices M) []hostSocket {
	var out []hostSocket
	for _, name := range keys(devices) {
		d := obj(devices[name])
		if str(d["type"]) != "proxy" {
			continue
		}
		parts := strings.Split(str(d["listen"]), ":")
		if len(parts) >= 3 && (parts[0] == "tcp" || parts[0] == "udp") {
			if n, err := strconv.Atoi(parts[len(parts)-1]); err == nil && n > 0 && n < 65536 {
				out = append(out, hostSocket{Protocol: parts[0], Port: n})
			}
		}
	}
	return out
}

// portConflicts returns a message for the first wanted port that another app
// or a program on the server already holds, or "".
func portConflicts(incus incusFunc, incusProject string, wanted []hostPort) string {
	if len(wanted) == 0 {
		return ""
	}
	owners := map[hostSocket]string{}
	out, err := incus(0, "query", "/1.0/instances?recursion=1&all-projects=true")
	var instances any
	if err == nil {
		instances, err = parseJSON([]byte(out))
	}
	if err == nil {
		for _, raw := range list(instances) {
			inst := obj(raw)
			project := str(inst["project"])
			for _, s := range publishedSockets(obj(inst["expanded_devices"])) {
				if _, taken := owners[s]; !taken || project == incusProject {
					owners[s] = project
				}
			}
		}
	}
	listening := hostListening()
	for _, hp := range wanted {
		sock := hostSocket{Protocol: hp.Protocol, Port: hp.Port}
		owner, held := owners[sock]
		switch {
		case held && owner != incusProject:
			return fmt.Sprintf("Port %d/%s is already published by app %s. Delete that app, or publish a different one here (for example \"%d:%d\" in compose.yaml). Services in one app reach each other by name, so publish a port only for access from outside the server.", hp.Port, hp.Protocol, owner, hp.Port+1, hp.Port)
		case !held && listening[sock]:
			return fmt.Sprintf("Port %d/%s is already used by a program on this server. Publish a different port in compose.yaml.", hp.Port, hp.Protocol)
		}
	}
	return ""
}

var bindInUse = regexp.MustCompile(`listen (tcp|udp) [^ ]*:([0-9]+): bind: address already in use`)

// explainBindError turns incus-compose's bind failure into the same message.
func explainBindError(incus incusFunc, incusProject, stderr string) string {
	m := bindInUse.FindStringSubmatch(stderr)
	if m == nil {
		return ""
	}
	n, _ := strconv.Atoi(m[2])
	if msg := portConflicts(incus, "", []hostPort{{Port: n, Protocol: m[1]}}); msg != "" {
		return msg
	}
	return fmt.Sprintf("Port %d/%s is already in use on this server. Publish a different port in compose.yaml.", n, m[1])
}
