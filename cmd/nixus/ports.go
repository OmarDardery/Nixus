package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Published ports bind the server's own address, as with docker compose, so
// two apps cannot publish the same one. portConflicts names who already holds
// a port this app wants, before incus-compose fails with a bare bind error.

// composeHostPorts returns the host TCP ports the reviewed services publish.
func composeHostPorts(services []any) []int {
	seen := map[int]bool{}
	var out []int
	add := func(n int) {
		if n > 0 && n < 65536 && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, raw := range services {
		for _, p := range list(obj(raw)["ports"]) {
			switch v := p.(type) {
			case M:
				if str(v["protocol"]) == "udp" {
					continue
				}
				if n, err := strconv.Atoi(str(v["published"])); err == nil {
					add(n)
				} else if f, ok := v["published"].(float64); ok {
					add(int(f))
				}
			case string:
				// "[ip:]host:container[/proto]"
				spec := strings.SplitN(v, "/", 2)
				if len(spec) == 2 && spec[1] == "udp" {
					continue
				}
				parts := strings.Split(spec[0], ":")
				if len(parts) >= 2 {
					if n, err := strconv.Atoi(parts[len(parts)-2]); err == nil {
						add(n)
					}
				}
			}
		}
	}
	return out
}

var hostListening = func() map[int]bool {
	out := map[int]bool{}
	res, err := run([]string{"ss", "-ltnH"}, nil, 10*time.Second, nil, "")
	if err != nil || res.Code != 0 {
		return out
	}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		local := fields[3]
		if i := strings.LastIndex(local, ":"); i >= 0 {
			if n, err := strconv.Atoi(local[i+1:]); err == nil {
				out[n] = true
			}
		}
	}
	return out
}

// portConflicts returns a message for the first wanted port that another app
// or a program on the server already holds, or "".
func portConflicts(incus incusFunc, incusProject string, wanted []int) string {
	if len(wanted) == 0 {
		return ""
	}
	owners := map[int]string{}
	out, err := incus(0, "query", "/1.0/instances?recursion=1&all-projects=true")
	var instances any
	if err == nil {
		instances, err = parseJSON([]byte(out))
	}
	if err == nil {
		for _, raw := range list(instances) {
			inst := obj(raw)
			project := str(inst["project"])
			for _, p := range publishedPorts(obj(inst["expanded_devices"])) {
				n := int(p.(int))
				if _, taken := owners[n]; !taken || project == incusProject {
					owners[n] = project
				}
			}
		}
	}
	listening := hostListening()
	for _, n := range wanted {
		owner, held := owners[n]
		switch {
		case held && owner != incusProject:
			return fmt.Sprintf("Port %d is already published by app %s. Delete that app, or publish a different one here (for example \"%d:%d\" in compose.yaml). Services in one app reach each other by name, so publish a port only for access from outside the server.", n, owner, n+1, n)
		case !held && listening[n]:
			return fmt.Sprintf("Port %d is already used by a program on this server. Publish a different port in compose.yaml.", n)
		}
	}
	return ""
}

var bindInUse = regexp.MustCompile(`listen tcp [^ ]*:([0-9]+): bind: address already in use`)

// explainBindError turns incus-compose's bind failure into the same message.
func explainBindError(incus incusFunc, incusProject, stderr string) string {
	m := bindInUse.FindStringSubmatch(stderr)
	if m == nil {
		return ""
	}
	n, _ := strconv.Atoi(m[1])
	if msg := portConflicts(incus, "", []int{n}); msg != "" {
		return msg
	}
	return fmt.Sprintf("Port %d is already in use on this server. Publish a different port in compose.yaml.", n)
}
