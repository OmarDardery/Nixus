package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

	dir, err := materializeInstanceSecrets("demo", nil, M{"API_KEY": "secret-1", "DB_PASS": "secret-2"}, M{"name": "web", "service": "web"})
	if err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(dir, "API_KEY")); err != nil || string(data) != "secret-1" {
		t.Fatalf("API_KEY: %q %v", data, err)
	}
	// Updating secrets prunes removed keys cleanly.
	if _, err := materializeInstanceSecrets("demo", nil, M{"API_KEY": "rotated"}, M{"name": "web", "service": "web"}); err != nil {
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

func TestMountedSecretsRespectBindingsAndDestinationNames(t *testing.T) {
	oldMask := syscall.Umask(0o077)
	defer syscall.Umask(oldMask)
	old := secretMountRoot
	secretMountRoot = filepath.Join(t.TempDir(), "secrets")
	defer func() { secretMountRoot = old }()
	project := M{"secrets": M{"bindings": M{"db": M{"key": "DB_PASSWORD", "instance": "db", "destination": "/run/secrets/password"}, "web": M{"key": "SESSION", "instance": "web", "destination": "/run/secrets/nested/session"}}}}
	values := M{"DB_PASSWORD": "database", "SESSION": "session", "UNBOUND": "private"}
	db, err := materializeInstanceSecrets("demo", project, values, M{"name": "db-1", "service": "db"})
	if err != nil {
		t.Fatal(err)
	}
	web, err := materializeInstanceSecrets("demo", project, values, M{"name": "web-1", "service": "web"})
	if err != nil {
		t.Fatal(err)
	}
	for file, want := range map[string]string{filepath.Join(db, "password"): "database", filepath.Join(web, "nested/session"): "session"} {
		got, err := os.ReadFile(file)
		if err != nil || string(got) != want {
			t.Fatalf("wrong scoped file: %s %v", file, err)
		}
	}
	for dir, want := range map[string]os.FileMode{web: 0o755, filepath.Join(web, "nested"): 0o755, secretMountRoot: 0o700, projectSecretsDir("demo"): 0o700} {
		info, err := os.Stat(dir)
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("wrong secret directory permissions under worker umask: %s %v", dir, err)
		}
	}
	for _, file := range []string{filepath.Join(web, "password"), filepath.Join(web, "DB_PASSWORD"), filepath.Join(db, "SESSION"), filepath.Join(db, "UNBOUND")} {
		if _, err := os.Stat(file); !os.IsNotExist(err) {
			t.Fatalf("sibling/unbound secret exposed: %s", file)
		}
	}
	if _, err := materializeInstanceSecrets("demo", nil, M{}, M{"name": "db-1", "service": "db"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(db, "password")); !os.IsNotExist(err) {
		t.Fatal("removed secret remains mounted")
	}
	if err := validateComposeSecretBindings(project, []string{"db", "web"}); err != nil {
		t.Fatal(err)
	}
	if err := validateComposeSecretBindings(project, []string{"db-1", "web-1"}); err == nil {
		t.Fatal("accepted generated-instance startup bindings")
	}
}
