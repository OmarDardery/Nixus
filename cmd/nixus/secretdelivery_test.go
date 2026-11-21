package main

import (
	"strings"
	"testing"
)

func TestSecretTargetsDefaultToEveryRunningInstance(t *testing.T) {
	values := M{"DB_PASSWORD": "x", "API_TOKEN": "y"}
	instances := []M{{"name": "app-1", "service": "app", "status": "Running"}, {"name": "db-1", "service": "db", "status": "Stopped"}}
	got, err := secretTargets(M{"secrets": M{"bindings": M{}}}, values, instances)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Instance != "app-1" || got[0].Destination != "/run/secrets/API_TOKEN" || got[1].Destination != "/run/secrets/DB_PASSWORD" {
		t.Fatalf("got %+v", got)
	}
}

func TestSecretTargetsFollowBindings(t *testing.T) {
	values := M{"DB_PASSWORD": "x"}
	instances := []M{{"name": "web-1", "service": "web", "status": "Running"}, {"name": "db-1", "service": "db", "status": "Running"}}
	project := M{"secrets": M{"bindings": M{"db": M{"key": "DB_PASSWORD", "instance": "db", "destination": "/run/secrets/db_password"}}}}
	got, err := secretTargets(project, values, instances)
	if err != nil || len(got) != 1 || got[0].Instance != "db-1" || got[0].Destination != "/run/secrets/db_password" {
		t.Fatalf("got %+v %v", got, err)
	}
	project = M{"secrets": M{"bindings": M{"x": M{"key": "MISSING", "instance": "db", "destination": "/run/secrets/x"}}}}
	if _, err := secretTargets(project, values, instances); err == nil || !strings.Contains(publicError(err), "no value") {
		t.Fatalf("bound a missing key: %v", err)
	}
	project = M{"secrets": M{"bindings": M{"x": M{"key": "DB_PASSWORD", "instance": "ghost", "destination": "/run/secrets/x"}}}}
	if _, err := secretTargets(project, values, instances); err == nil {
		t.Fatal("bound to a missing instance")
	}
	project = M{"secrets": M{"bindings": M{"x": M{"key": "DB_PASSWORD", "instance": "db", "destination": "/etc/shadow"}}}}
	if _, err := secretTargets(project, values, instances); err == nil {
		t.Fatal("delivered outside /run/secrets")
	}
}
