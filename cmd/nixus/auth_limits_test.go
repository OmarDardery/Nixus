package main

import (
	"fmt"
	"testing"
	"time"
)

func TestLoginFailuresAreBoundedAndExpire(t *testing.T) {
	old := linuxVerify
	defer func() { linuxVerify = old }()
	checks := 0
	linuxVerify = func(string, any) (M, error) { checks++; return nil, Public("bad password") }
	a := NewAuth()
	a.failures["expired"] = []time.Time{time.Now().Add(-6 * time.Minute)}
	for range 100 {
		a.login("bad", "source", "admin")
	}
	if checks != 5 || len(a.failures["source"]) != 5 {
		t.Fatalf("checks=%d attempts=%d", checks, len(a.failures["source"]))
	}
	if _, exists := a.failures["expired"]; exists {
		t.Fatal("expired address was retained")
	}
	for i := 0; i < 1100; i++ {
		a.login("bad", fmt.Sprint(i), "admin")
	}
	if len(a.failures) != 1024 {
		t.Fatalf("address count=%d", len(a.failures))
	}
	a.failures["source"] = []time.Time{time.Now().Add(-6 * time.Minute)}
	a.login("bad", "source", "admin")
	if len(a.failures["source"]) != 1 {
		t.Fatal("lockout did not expire")
	}
}

func TestLoginEvictsOnlyOldestSession(t *testing.T) {
	old := linuxVerify
	defer func() { linuxVerify = old }()
	linuxVerify = func(string, any) (M, error) { return M{}, nil }
	a := NewAuth()
	for i := 0; i < 128; i++ {
		a.sessions[fmt.Sprint(i)] = &session{created: time.Now(), used: time.Now().Add(-time.Duration(i) * time.Second)}
	}
	token, _, err := a.login("pw", "source", "admin")
	if err != nil || len(a.sessions) != 128 || a.sessions[token] == nil {
		t.Fatalf("sessions=%d err=%v", len(a.sessions), err)
	}
	if a.sessions["127"] != nil || a.sessions["0"] == nil {
		t.Fatal("live sessions were cleared instead of evicting the oldest")
	}
}

func TestLinuxAccountCanBeAuditActor(t *testing.T) {
	for _, name := range []string{"operator", "_admin", "user-name", "user_2"} {
		if !fullmatch(hostUser, name) || !fullmatch(actorName, name) {
			t.Fatalf("signed-in Linux account cannot perform audited actions: %s", name)
		}
	}
}
