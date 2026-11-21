package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRepoURL(t *testing.T) {
	for url, want := range map[string]string{
		"git@github.com:me/apps.git":             "github.com:22",
		"ssh://git@git.lan:2222/me/apps.git":     "git.lan:2222",
		"forgejo@code.example.org:team/apps.git": "code.example.org:22",
	} {
		host, port, err := parseRepoURL(url)
		if err != nil || host+":"+port != want {
			t.Fatalf("%s: %s:%s %v", url, host, port, err)
		}
	}
	for _, bad := range []string{"https://github.com/me/apps.git", "file:///srv/apps", "git@host:../etc", "git@host:-oProxyCommand=x",
		"ssh://git@host/a b", "/srv/apps.git", "git@host:me/apps.git;rm"} {
		if _, _, err := parseRepoURL(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func sh(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// repoFixture: a bare "remote", a workspace with one Compose app and the
// repository connected to it.
func repoFixture(t *testing.T) (remote, workspace string) {
	useState(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	base := t.TempDir()
	remote = filepath.Join(base, "remote.git")
	sh(t, base, "git", "init", "-q", "--bare", "-b", "main", remote)
	workspace = filepath.Join(base, "ws")
	writeFile(t, filepath.Join(workspace, "web", "default.nix"), defaultComposeDeclaration)
	writeFile(t, filepath.Join(workspace, "web", "secrets.enc.yaml"), "cipher-A")
	writeFile(t, filepath.Join(workspace, "backups.nix"), "{ ... }: { }\n")
	oldWS, oldCfg, oldSrc, oldNotify := projectsWorkspace, appsRepoConfigPath, repoSource, notifyAppsRepo
	projectsWorkspace = workspace
	appsRepoConfigPath = filepath.Join(base, "apps-repo.json")
	repoSource = func(name string) map[string][]byte {
		return map[string][]byte{"compose.yaml": []byte("services: {}\n"), "Dockerfile": []byte("FROM x\n")}
	}
	notifyAppsRepo = func() {}
	t.Cleanup(func() {
		projectsWorkspace, appsRepoConfigPath, repoSource, notifyAppsRepo = oldWS, oldCfg, oldSrc, oldNotify
	})
	writeJSON(appsRepoConfigPath, M{"url": remote, "branch": "main"})
	return remote, workspace
}

func TestAppsRepoFirstPushMirrorsServerState(t *testing.T) {
	remote, _ := repoFixture(t)
	out, err := exportAppsRepo("console")
	if err != nil || out["pushed"] != true {
		t.Fatalf("%v %v", out, err)
	}
	check := t.TempDir()
	sh(t, check, "git", "clone", "-q", remote, "c")
	for _, f := range []string{"web/compose.yaml", "web/Dockerfile", "web/default.nix", "web/secrets.enc.yaml", "backups.nix", "README.md"} {
		if !isFile(filepath.Join(check, "c", f)) {
			t.Fatalf("missing %s", f)
		}
	}
	// Nothing changed: no new commit.
	if out, err := exportAppsRepo("console"); err != nil || out["pushed"] != false {
		t.Fatalf("%v %v", out, err)
	}
}

func TestAppsRepoRemoteChangesWaitForReview(t *testing.T) {
	remote, workspace := repoFixture(t)
	if _, err := exportAppsRepo("console"); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	sh(t, work, "git", "clone", "-q", remote, "c")
	c := filepath.Join(work, "c")
	writeFile(t, filepath.Join(c, "web", "compose.yaml"), "services: {a: {}}\n")
	writeFile(t, filepath.Join(c, "notes", "compose.yaml"), "services: {}\n")
	writeFile(t, filepath.Join(c, "docs", "x.md"), "keep\n")
	sh(t, c, "git", "add", "-A")
	sh(t, c, "git", "commit", "-q", "-m", "add notes")
	sh(t, c, "git", "push", "-q", "origin", "main")
	view, err := checkAppsRepo()
	if err != nil {
		t.Fatal(err)
	}
	pending := obj(obj(view["status"])["pending"])
	if apps, _ := anyStrings(pending["apps"]); strings.Join(apps, ",") != "notes,web" || len(list(pending["commits"])) != 1 {
		t.Fatalf("pending %v", pending)
	}
	// A console change now must not overwrite the unreviewed remote commit.
	writeFile(t, filepath.Join(workspace, "web", "default.nix"), "{ ... }: { nixus.project.backend = \"incus-compose\"; }\n")
	if out, err := exportAppsRepo("console"); err != nil || out["pushed"] != false {
		t.Fatalf("%v %v", out, err)
	}
	if head := sh(t, c, "git", "ls-remote", remote, "main"); !strings.HasPrefix(head, str(pending["head"])) {
		t.Fatalf("remote moved: %s", head)
	}
}

func TestAppsRepoChangedAppsAndRemovals(t *testing.T) {
	remote, _ := repoFixture(t)
	if _, err := exportAppsRepo("console"); err != nil {
		t.Fatal(err)
	}
	base := str(appsRepoStatus()["deployedHead"])
	work := t.TempDir()
	sh(t, work, "git", "clone", "-q", remote, "c")
	c := filepath.Join(work, "c")
	sh(t, c, "git", "rm", "-rq", "web")
	writeFile(t, filepath.Join(c, "README.md"), "edited\n")
	sh(t, c, "git", "commit", "-qam", "drop web")
	sh(t, c, "git", "push", "-q", "origin", "main")
	if _, head, err := fetchAppsRepo(); err != nil || head == "" {
		t.Fatal(err)
	} else if changed, removed, err := changedApps(base, head); err != nil || len(changed) != 0 || strings.Join(removed, ",") != "web" {
		t.Fatalf("%v %v %v", changed, removed, err)
	} else if changed, _, _ := changedApps("0123456789012345678901234567890123456789", head); len(changed) != 1 || changed[0] != "backups.nix" {
		t.Fatalf("unknown base must list every app: %v", changed)
	}
}

func TestReadRepoAppSplitsNixSourceAndSecrets(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "default.nix"), "{ ... }: {}\n")
	writeFile(t, filepath.Join(dir, "modules", "net.nix"), "{ ... }: {}\n")
	writeFile(t, filepath.Join(dir, "secrets.enc.yaml"), "c")
	writeFile(t, filepath.Join(dir, ".sops.yaml"), "x")
	writeFile(t, filepath.Join(dir, "compose.yaml"), "services: {}\n")
	writeFile(t, filepath.Join(dir, "conf", "app.ini"), "a=1\n")
	app, err := readRepoApp(dir, "web")
	if err != nil {
		t.Fatal(err)
	}
	if len(app.nix) != 2 || app.nix["web/modules/net.nix"] == nil || string(app.secrets) != "c" || len(app.source) != 2 || app.source["conf/app.ini"] == nil {
		t.Fatalf("%+v", app)
	}
	os.Symlink("/etc/passwd", filepath.Join(dir, "link"))
	if _, err := readRepoApp(dir, "web"); err == nil {
		t.Fatal("followed a symlink")
	}
}

func TestAppsRepoUnconfiguredIsNil(t *testing.T) {
	useState(t)
	old := appsRepoConfigPath
	defer func() { appsRepoConfigPath = old }()
	appsRepoConfigPath = filepath.Join(t.TempDir(), "missing.json")
	if appsRepoConfig() != nil || appsRepoView()["configured"] != false {
		t.Fatal("a missing config must read as not connected")
	}
	if _, err := checkAppsRepo(); err == nil {
		t.Fatal("check without a repository must fail")
	}
}
