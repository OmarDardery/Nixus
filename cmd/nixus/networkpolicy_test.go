package main

import (
	"net/netip"
	"testing"
	"time"
)

func TestPublicEgressExcludesPrivateRanges(t *testing.T) {
	excluded := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16"}
	ranges := list(must(parseJSON(publicIPv4JSON)))
	for _, raw := range ranges {
		prefix := netip.MustParsePrefix(str(raw))
		for _, cidr := range excluded {
			if prefix.Overlaps(netip.MustParsePrefix(cidr)) {
				t.Fatalf("public allow %s overlaps %s", prefix, cidr)
			}
		}
	}
	for _, address := range []string{"1.1.1.1", "198.41.192.167", "203.0.113.1"} {
		found := false
		for _, raw := range ranges {
			found = found || netip.MustParsePrefix(str(raw)).Contains(netip.MustParseAddr(address))
		}
		if !found {
			t.Fatalf("public transport destination blocked: %s", address)
		}
	}
	policy := composeNetworkPolicy(M{"appnet": M{}, "lan": M{"external": true}}, M{"connectivity": M{"privateAccess": []any{M{"cidr": "192.168.1.1/32", "ports": []any{8443}, "protocol": "tcp"}}}}, "10.1.0.1/24")
	if policy["lan"] != nil {
		t.Fatal("external LAN network policy overwritten")
	}
	if str(jget(policy, "appnet", "x-incus", "security.acls.default.egress.action")) != "reject" {
		t.Fatal("private egress not restricted")
	}
	for _, direction := range []string{"ingress", "egress"} {
		for _, raw := range list(jget(policy, "appnet", "x-incus-compose", "acl", direction)) {
			if action := str(obj(raw)["action"]); action != "" && action != "allow" {
				t.Fatal("explicit denies override exceptions")
			}
		}
	}
}

func TestNativeACLApplyOwnershipAndETag(t *testing.T) {
	oldAPI, oldState := infraAPI, infrastructureState
	defer func() { infraAPI, infrastructureState = oldAPI, oldState }()
	infrastructureState = t.TempDir() + "/infra.json"
	declaration := M{"name": "guest-policy", "description": "test", "ingress": []any{}, "egress": []any{M{"action": "allow", "state": "enabled", "destination": "1.1.1.1/32"}}}
	spec := M{"network_acls": []any{declaration}}
	var current M
	writes := 0
	tag := "version-1"
	infraAPI = func(method, path string, data any, etag string, timeout time.Duration, max int64) (M, string, int, error) {
		if method == "GET" {
			if current == nil {
				return M{}, "", 404, nil
			}
			return M{"metadata": current}, tag, 200, nil
		}
		writes++
		if method == "PUT" && etag != tag {
			t.Fatal("ACL update lost ETag")
		}
		if method == "POST" && path != "/1.0/network-acls" {
			t.Fatal(path)
		}
		current = cloneM(obj(data))
		return M{"type": "sync"}, "", 200, nil
	}
	if err := infraApplyACLs(spec); err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Fatalf("create writes=%d", writes)
	}
	if err := infraApplyACLs(spec); err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Fatal("unchanged ACL rewritten")
	}
	if err := infraRecord(spec); err != nil {
		t.Fatal(err)
	}
	declaration["description"] = "reviewed change"
	if err := infraApplyACLs(spec); err != nil {
		t.Fatal(err)
	}
	if writes != 2 {
		t.Fatal("reviewed change not applied")
	}
	if err := infraRecord(spec); err != nil {
		t.Fatal(err)
	}
	current["description"] = "native drift"
	if err := infraApplyACLs(spec); err == nil {
		t.Fatal("native edits overwritten")
	}
	if writes != 2 {
		t.Fatal("drift caused write")
	}
	current["description"] = "reviewed change"
	declaration["description"] = "another change"
	tag = ""
	if err := infraApplyACLs(spec); err == nil {
		t.Fatal("missing ETag accepted")
	}
	if writes != 2 {
		t.Fatal("write without ETag")
	}
}
