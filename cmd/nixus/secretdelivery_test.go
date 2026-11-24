package main

import (
	"os"
	"path/filepath"
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

// With bindings, each instance receives only its own keys, as environment and
// as files; a binding change moves a key (#105).
func TestEnvDeliveryFollowsBindings(t *testing.T) {
	values := M{"DB_PASSWORD": "db-secret", "SESSION": "web-secret"}
	project := M{"secrets": M{"bindings": M{
		"db":  M{"key": "DB_PASSWORD", "instance": "db", "destination": "/run/secrets/DB_PASSWORD"},
		"web": M{"key": "SESSION", "instance": "web", "destination": "/run/secrets/SESSION"},
	}}}
	db := M{"name": "stack-db-1", "service": "db", "status": "Running"}
	web := M{"name": "stack-web-1", "service": "web", "status": "Running"}
	if got := envValuesFor(project, values, db); len(got) != 1 || got["DB_PASSWORD"] != "db-secret" {
		t.Fatalf("db environment: %v", got)
	}
	if got := envValuesFor(project, values, web); len(got) != 1 || got["SESSION"] != "web-secret" {
		t.Fatalf("web environment: %v", got)
	}
	targets, err := secretTargets(project, values, []M{db, web})
	if err != nil {
		t.Fatal(err)
	}
	for _, tg := range targets {
		if tg.Instance == "stack-web-1" && tg.Key != "SESSION" || tg.Instance == "stack-db-1" && tg.Key != "DB_PASSWORD" {
			t.Fatalf("file delivery leaks: %v", targets)
		}
	}
	// No bindings: every instance still gets every variable.
	if got := envValuesFor(M{}, values, web); len(got) != 2 {
		t.Fatalf("unbound app: %v", got)
	}
	// Rebinding DB_PASSWORD to web moves it.
	project["secrets"].(M)["bindings"].(M)["db"] = M{"key": "DB_PASSWORD", "instance": "web", "destination": "/run/secrets/DB_PASSWORD"}
	if got := envValuesFor(project, values, db); len(got) != 0 {
		t.Fatalf("db should lose the key after rebinding: %v", got)
	}
	if got := envValuesFor(project, values, web); len(got) != 2 {
		t.Fatalf("web should now have both: %v", got)
	}
}

func TestMaterializeProjectSecretsSyncsAndPrunes(t *testing.T) {
	old := secretMountRoot
	secretMountRoot = filepath.Join(t.TempDir(), "secrets")
	defer func() { secretMountRoot = old }()

	dir, err := materializeProjectSecrets("demo", M{"API_KEY": "secret-1", "DB_PASS": "secret-2"})
	if err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(dir, "API_KEY")); err != nil || string(data) != "secret-1" {
		t.Fatalf("API_KEY: %q %v", data, err)
	}
	// Updating secrets prunes removed keys cleanly.
	if _, err := materializeProjectSecrets("demo", M{"API_KEY": "rotated"}); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(dir, "API_KEY")); err != nil || string(data) != "rotated" {
		t.Fatalf("rotated API_KEY: %q %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "DB_PASS")); !os.IsNotExist(err) {
		t.Fatalf("removed secret should be pruned: %v", err)
	}
	removeProjectSecretsDir("demo")
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("secret directory should be removed on app delete: %v", err)
	}
}
