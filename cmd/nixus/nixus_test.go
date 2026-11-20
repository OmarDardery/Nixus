package main

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func useState(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := STATE
	STATE = dir
	t.Cleanup(func() { STATE = old })
	return dir
}

func writeFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalJSONMatchesPythonForms(t *testing.T) {
	v := M{"b": 1, "a": []any{"x", true, nil}, "é": "ü"}
	if got := canonical(v); got != `{"a":["x",true,null],"b":1,"é":"ü"}` {
		t.Fatalf("canonical: %s", got)
	}
	if got := canonicalSpaced(v); got != `{"a": ["x", true, null], "b": 1, "é": "ü"}` {
		t.Fatalf("spaced: %s", got)
	}
	bs := string(rune(92))
	want := "{\"k\": \"" + bs + "u00e9" + bs + "ud83d" + bs + "ude00\"}"
	if got := canonicalASCII(M{"k": "\u00e9\U0001F600"}); got != want {
		t.Fatalf("ascii: %s", got)
	}
}

func TestPublicErrorsOnlyExposeReviewedMessages(t *testing.T) {
	if publicError(Public("Shown")) != "Shown" {
		t.Fatal("public message hidden")
	}
	if publicError(Hidden("secret /path")) == "secret /path" {
		t.Fatal("hidden message leaked")
	}
	if publicError(Publicf("Value %d", 3)) != "Value 3" {
		t.Fatal("formatted message")
	}
}

func TestRecoveryGuardBlocksAutomationUntilReleased(t *testing.T) {
	state := useState(t)
	journal := filepath.Join(state, "replacement-recovery.json")
	writeFile(t, journal, `{"format": 1, "phase": "planned"}`)
	if err := requireNormal(); err == nil || !strings.Contains(publicError(err), "Unfinished recovery journal") {
		t.Fatalf("expected recovery block, got %v", err)
	}
	writeFile(t, journal, `{"format": 1, "phase": "complete"}`)
	if err := requireNormal(); err != nil {
		t.Fatalf("released journal still blocks: %v", err)
	}
}

func TestClockStatusRejectsImplausibleTimestamps(t *testing.T) {
	if s := clockStatus(1); s["state"] != "invalid-clock" || s["evidenceWarning"] != true {
		t.Fatalf("epoch accepted: %v", s)
	}
	if s := clockStatus(1800000000); s["state"] == "invalid-clock" {
		t.Fatalf("plausible time rejected: %v", s)
	}
}

func TestPlatformPathProtectsMachineState(t *testing.T) {
	for _, name := range []string{"machine/settings.json", "secrets/x", "local/a", ".git/config", "hardware-configuration.nix", "../x", "/etc/passwd"} {
		if platformPath(name) {
			t.Errorf("%s treated as platform code", name)
		}
	}
	for _, name := range []string{"flake.nix", "cmd/nixus/main.go", "modules/incus.nix"} {
		if !platformPath(name) {
			t.Errorf("%s not treated as platform code", name)
		}
	}
}

func TestProjectWorkspaceValidation(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "flake.nix"), "{ outputs = _: {}; }\n")
	writeFile(t, filepath.Join(root, "flake.lock"), `{"version": 7, "root": "root", "nodes": {"root": {}}}`)
	writeFile(t, filepath.Join(root, "alpha/default.nix"), "{ }\n")
	writeFile(t, filepath.Join(root, "alpha/modules/net.nix"), "{ }\n")
	writeFile(t, filepath.Join(root, "alpha/modules/_private.nix"), "{ }\n")
	manifest, err := validateWorkspace(root, true)
	if err != nil {
		t.Fatal(err)
	}
	alpha := obj(jget(manifest, "projects", "alpha"))
	if !equalJSON(alpha["modules"], []any{"alpha/modules/net.nix"}) || len(str(manifest["sourceHash"])) != 64 {
		t.Fatalf("unexpected manifest %v", manifest)
	}
	writeFile(t, filepath.Join(root, "alpha/.env"), "TOKEN=x\n")
	if _, err := validateWorkspace(root, true); err == nil || !strings.Contains(publicError(err), "plaintext credential") {
		t.Fatalf("plaintext credential accepted: %v", err)
	}
	os.Remove(filepath.Join(root, "alpha/.env"))
	os.Symlink("/etc/passwd", filepath.Join(root, "alpha/link"))
	if _, err := validateWorkspace(root, true); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestProjectPatchesRestrictTargets(t *testing.T) {
	if _, err := projectPatches(M{"alpha/default.nix": "{ }", "alpha/modules/x/y.nix": "{ }", "backups.nix": "{ }"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []M{{"alpha/../etc.nix": "x"}, {"alpha/modules/_x/y.nix": "x"}, {"alpha/default.nix": nil}, {"flake.nix": "x"}, {}} {
		if _, err := projectPatches(bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestInventoryRejectsOverlappingClaims(t *testing.T) {
	project := func(name, incus string) M {
		return M{"name": name, "enable": true, "backend": "incus-native", "incusProject": incus,
			"resources": M{"cpus": float64(2), "memory": "2GiB"}, "secrets": M{"file": nil, "bindings": M{}},
			"backup": M{"enable": true, "consistency": "stop"}, "claims": []any{"instance/web"}, "source": name, "modules": []any{}}
	}
	if _, err := validateInventory(M{"schemaVersion": float64(1), "projects": M{"alpha": project("alpha", "alpha")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := validateInventory(M{"schemaVersion": float64(1), "projects": M{"alpha": project("alpha", "shared"), "beta": project("beta", "shared")}}); err == nil {
		t.Fatal("overlapping Incus ownership accepted")
	}
}

func TestSopsRecipientPolicy(t *testing.T) {
	host := "age1" + strings.Repeat("q", 58)
	other := "age1" + strings.Repeat("p", 58)
	got, err := checkRecipients([]any{other, host}, host)
	if err != nil || got[0] != other {
		t.Fatalf("recipients: %v %v", got, err)
	}
	if _, err := checkRecipients([]any{other}, host); err == nil {
		t.Fatal("policy without host recipient accepted")
	}
	if _, err := checkRecipients([]any{host, host}, host); err == nil {
		t.Fatal("duplicate recipient accepted")
	}
	if !strings.HasSuffix(string(sopsPolicy([]string{host, other})), other+","+host+"\n") {
		t.Fatal("policy not sorted")
	}
}

func TestRecoveryKitEnvelopeRoundTrip(t *testing.T) {
	recipient := "age1" + strings.Repeat("q", 58)
	identity := "AGE-SECRET-KEY-1" + strings.Repeat("Q", 58)
	creds := map[string][]byte{"restic-password": []byte("hunter2")}
	encoded := M{"restic-password": b64(creds["restic-password"])}
	payload := canonical(M{"version": 1, "recipient": recipient, "identity": identity, "credentials": encoded, "manifest": kitManifest(recipient, creds)})
	salt, nonce := bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 12)
	passphrase := "correct horse battery staple"
	aead, err := kitAEAD(passphrase, salt)
	if err != nil {
		t.Fatal(err)
	}
	sealed := aead.Seal(nil, nonce, []byte(payload), kitMagic)
	serial := []byte(canonical(M{"format": "nixus-recovery-kit", "version": 1, "salt": b64(salt), "nonce": b64(nonce), "ciphertext": b64(sealed)}))
	record, got, err := kitDecode(serial, passphrase)
	if err != nil || str(record["recipient"]) != recipient || string(got["restic-password"]) != "hunter2" {
		t.Fatalf("decode: %v %v", record, err)
	}
	if _, _, err := kitDecode(serial, "wrong passphrase here!"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	if _, err := kitAEAD("short", salt); err == nil {
		t.Fatal("short passphrase accepted")
	}
}

func TestRecoveryArchiveRoundTripAndTamper(t *testing.T) {
	useState(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a"), "alpha")
	var buf bytes.Buffer
	if err := writeRecoveryArchive(&buf, map[string]string{"config/a": filepath.Join(dir, "a")}, "configuration"); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "kit.tar.gz")
	os.WriteFile(archive, buf.Bytes(), 0o600)
	manifest, entries, err := recoveryInspect(archive)
	if err != nil || str(manifest["kind"]) != "configuration" || string(entries["config/a"]) != "alpha" {
		t.Fatalf("inspect: %v %v", manifest, err)
	}
	staged := filepath.Join(dir, "staged")
	if _, err := recoveryStage(archive, staged); err != nil {
		t.Fatal(err)
	}
	if _, err := recoveryStage(archive, staged); err == nil {
		t.Fatal("existing staging destination overwritten")
	}
}

func TestCommissioningReportValidation(t *testing.T) {
	ctx := M{"revision": "unknown", "version": "0.1.0", "sourceDigest": strings.Repeat("a", 64), "inputsDigest": strings.Repeat("b", 64),
		"settingsDigest": strings.Repeat("c", 64), "system": "unknown", "kernel": "6.1", "incus": "unknown",
		"hardwareDigest": strings.Repeat("d", 64), "scope": "virtual-machine", "architecture": "x86_64", "hardwareDevices": false,
		"mode": "fresh", "environment": "automated-fixture"}
	report := M{"format": 1, "context": ctx, "evidence": []any{}}
	if err := recordEvidence(report, ctx, "install-resume", "passed", "manual-attestation"); err != nil {
		t.Fatal(err)
	}
	if err := recordEvidence(report, ctx, "kvm", "passed", "manual-attestation"); err == nil {
		t.Fatal("automated probe attested manually")
	}
	report["evidence"] = list(report["evidence"])[:1]
	summary, err := summarizeEvidence(report, nil, "")
	if err != nil || summary["qualification"] != "unqualified" {
		t.Fatalf("summary: %v %v", summary, err)
	}
	report["extra"] = true
	if validateReport(report) == nil {
		t.Fatal("extra report field accepted")
	}
}

func TestInstallerIntentAndGuestNetwork(t *testing.T) {
	answers, err := normalizeIntent(M{"version": float64(1), "network": "lan", "adguard": true, "guestSubnet": "10.20.30.0/24"})
	if err != nil || answers["network"] != "lan" || answers["guestSubnet"] != "10.20.30.0/24" {
		t.Fatalf("normalize: %v %v", answers, err)
	}
	for _, bad := range []M{{"version": float64(2)}, {"unknown": 1}, {"guestSubnet": "8.8.8.0/24"}, {"guestSubnet": "10.0.0.0/16"}, {"laptop": "yes"}} {
		if _, err := normalizeIntent(bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	network, err := guestNetwork([]any{M{"dst": "10.90.90.0/24"}}, "")
	if err != nil || network["cidr"] != "10.77.0.0/24" || network["gatewayCIDR"] != "10.77.0.1/24" {
		t.Fatalf("guest network: %v %v", network, err)
	}
}

func TestNetworkRepairSelectsSavedBridge(t *testing.T) {
	settings := M{"management": M{"interface": "eth0", "configure": false}, "guests": M{"bridge": "incusbr0"}, "connectivity": M{"guestInterfaces": []any{}}}
	links := []any{M{"ifname": "eth0", "master": "br0"}, M{"ifname": "br0"}}
	profiles := []M{
		{"uuid": "11111111-1111-1111-1111-111111111111", "id": "lan", "type": "bridge", "interface": "br0", "controller": "", "auto": "no"},
		{"uuid": "22222222-2222-2222-2222-222222222222", "id": "lan-port", "type": "802-3-ethernet", "interface": "eth0", "controller": "br0", "auto": "no"},
	}
	name, selected, err := selectManagement(settings, links, profiles, "")
	if err != nil || name != "br0" || len(selected) != 2 {
		t.Fatalf("select: %s %v %v", name, selected, err)
	}
	settings["guests"] = M{"bridge": "br0"}
	if _, _, err := selectManagement(settings, links, profiles, ""); err == nil {
		t.Fatal("guest bridge selected for management")
	}
}

func TestBrokerFramingRejectsAmbiguousBodies(t *testing.T) {
	get, _ := http.NewRequest("GET", "/status", strings.NewReader("x"))
	get.Header.Set("Content-Length", "1")
	if _, err := checkFraming(get); err == nil {
		t.Fatal("GET body accepted")
	}
	post, _ := http.NewRequest("POST", "/apply", strings.NewReader("{}"))
	post.Header["Content-Length"] = []string{"2", "2"}
	if _, err := checkFraming(post); err == nil {
		t.Fatal("duplicate Content-Length accepted")
	}
	post.Header["Content-Length"] = []string{"2"}
	if n, err := checkFraming(post); err != nil || n != 2 {
		t.Fatalf("valid body rejected: %v", err)
	}
}

func TestPortalSessionsExpireOnPasswordIdentityChange(t *testing.T) {
	auth := NewAuth()
	auth.sessions["tok"] = &session{csrf: "c", username: "nobody-here", identity: "x"}
	if auth.get("nixus_session=tok") != nil {
		t.Fatal("session for unknown account accepted")
	}
	if len(cookieValue("a=1; nixus_session=t; b=2", "nixus_session")) != 1 {
		t.Fatal("cookie parse")
	}
}

func TestConsoleLinesUseOnlyConfiguredAddress(t *testing.T) {
	settings := M{"management": M{"interface": "eth0", "address": "192.0.2.10"}, "setup": M{"enable": true, "port": float64(9440)}, "ready": true}
	links := []any{M{"ifname": "eth0", "addr_info": []any{M{"family": "inet", "scope": "global", "local": "192.0.2.10"}}}}
	lines := strings.Join(consoleLines(settings, links, map[string]map[string]string{}, "a", "a", "", ""), "\n")
	for _, want := range []string{"Management: eth0  192.0.2.10", "Nixus: https://192.0.2.10:9440", "Incus: https://192.0.2.10:8443", "Boot: current configuration is the boot default"} {
		if !strings.Contains(lines, want) {
			t.Errorf("missing %q in\n%s", want, lines)
		}
	}
}

func TestReleaseRequiresExactCIEvidence(t *testing.T) {
	run := M{"head_sha": strings.Repeat("a", 40), "conclusion": "success", "status": "completed", "path": ".github/workflows/pages.yml",
		"event": "push", "repository": M{"full_name": "OmarDardery/Nixus"}, "html_url": "https://example.invalid/run"}
	jobs := []any{M{"status": "completed", "conclusion": "success", "steps": []any{M{"name": "Deploy to GitHub Pages", "status": "completed", "conclusion": "success"}}}}
	if _, err := ciRun("website", run, jobs, strings.Repeat("a", 40), "OmarDardery/Nixus"); err != nil {
		t.Fatal(err)
	}
	if _, err := ciRun("website", run, jobs, strings.Repeat("b", 40), "OmarDardery/Nixus"); err == nil {
		t.Fatal("run for another revision accepted")
	}
}

func TestBase64StrictDecoding(t *testing.T) {
	if _, err := unb64("Zm9v\n"); err == nil {
		t.Fatal("non-canonical base64 accepted")
	}
	if v, err := unb64(base64.StdEncoding.EncodeToString([]byte("ok"))); err != nil || string(v) != "ok" {
		t.Fatal("valid base64 rejected")
	}
}
