# End-to-end OCI path through the real broker socket: a local registry holds a
# base image; a Dockerfile pinned to its digest is staged, reviewed and
# published; the broker fetches the pinned base, the unprivileged offline
# sandbox builds it, and the verified image is imported into Incus.
{ pkgs }:
let
  defaults = import ../site-defaults.nix;
  settings = defaults // {
    hostName = "nixus-test"; cpuVendor = "intel";
    setup = defaults.setup // { enable = true; };
    management = defaults.management // { interface = "eth0"; address = "127.0.0.1"; trustedCIDRs = [ "127.0.0.0/8" ]; };
  };
  siteSource = import ./site-source.nix { inherit pkgs; };
  # A tiny base image with one marker file, served by the local registry.
  baseImage = pkgs.dockerTools.buildImage {
    name = "nixus/base";
    tag = "1";
    # busybox gives the deployed service a real command to run.
    copyToRoot = [
      pkgs.busybox
      (pkgs.runCommand "base-root" { } ''
        mkdir -p $out/etc
        echo nixus-base-layer > $out/etc/base-marker
      '')
    ];
  };
  # Three versions of one tag for the image update scenario (#61).
  webImage = version: withBusybox: pkgs.dockerTools.buildImage {
    name = "nixus/webbase";
    tag = "1";
    copyToRoot = (if withBusybox then [ pkgs.busybox ] else [ ]) ++ [
      (pkgs.runCommand "web-root-${version}" { } ''
        mkdir -p $out/etc
        echo ${version} > $out/etc/web-version
      '')
    ];
  };
  webV1 = webImage "v1" true;
  webV2 = webImage "v2" true;
  webBroken = webImage "broken" false;
  hostNode = withRegistry: { lib, pkgs, ... }: {
      imports = [ ../configuration-bootstrap.nix ];
      virtualisation = { memorySize = if withRegistry then 4096 else 3072; diskSize = 8192; cores = 2; };
      boot.kernelModules = lib.mkForce [ ];
      environment.systemPackages = [ pkgs.curl pkgs.jq pkgs.skopeo pkgs.restic ];
      services.dockerRegistry = lib.mkIf withRegistry { enable = true; listenAddress = "127.0.0.1"; port = 5000; };
      # The local fixture registry has no TLS; mark only it as insecure.
      environment.etc."containers/registries.conf".text = ''
        [[registry]]
        location = "localhost:5000"
        insecure = true
      '';
      virtualisation.incus = {
        enable = true;
        preseed = {
          # As on real hosts (modules/incus.nix); incus-compose requires a listener.
          config."core.https_address" = "127.0.0.1:8443";
          storage_pools = [ { name = "default"; driver = "dir"; } ];
          networks = [ { name = "incusbr0"; type = "bridge";
            config = { "ipv4.address" = "10.0.100.1/24"; "ipv4.nat" = "true"; "ipv6.address" = "none"; }; } ];
          profiles = [ { name = "default"; devices = {
            eth0 = { name = "eth0"; network = "incusbr0"; type = "nic"; };
            root = { path = "/"; pool = "default"; type = "disk"; };
          }; } ];
        };
      };
      networking.nftables.enable = true;
      # Surface isolated builder diagnostics in the journal.
      systemd.services.nixus-admin-backend.environment.NIXUS_OCI_VM_TEST = "1";
      systemd.services.nixus-test-fixture = {
        wantedBy = [ "multi-user.target" ];
        after = [ "systemd-tmpfiles-setup.service" ];
        before = [ "nixus-management-identity.service" "nixus-admin-backend.service" "nixus-ui.service" ];
        requiredBy = [ "nixus-management-identity.service" "nixus-admin-backend.service" "nixus-ui.service" ];
        serviceConfig = { Type = "oneshot"; RemainAfterExit = true; UMask = "0077"; };
        script = ''
          root=/var/lib/nixus/config
          mkdir -p "$root/lib" "$root/machine" /srv/nixus
          chmod 0700 /srv/nixus
          for f in site.nix site-defaults.nix lib/machine.nix lib/settings-migrations.nix; do
            install -m 0600 ${siteSource}/$f "$root/$f"
          done
          echo '{"version": 1}' > "$root/machine/format.json"
          cat > "$root/machine/settings.json" <<'JSON'
          ${builtins.toJSON settings}
          JSON
          echo '{"interface": "eth0", "trustedCIDRs": ["127.0.0.0/8"]}' > "$root/machine/installation.json"
          echo '["site.nix","site-defaults.nix","lib/machine.nix","lib/settings-migrations.nix","machine/format.json","machine/settings.json","machine/installation.json"]' > "$root/.nixus-files.json"
        '';
      };
    };
in pkgs.testers.runNixOSTest {
  name = "nixus-oci";
  globalTimeout = 2700;
  node.specialArgs = {
    inventory = settings;
    installedBase = { ... }: { system.stateVersion = "26.05"; };
  };
  nodes.machine = hostNode true;
  # An empty Nixus host for the cold-host restore (#44).
  nodes.fresh = hostNode false;
  testScript = ''
    import base64, hashlib, json, time

    def broker(path, body=None):
        if body is None:
            out = machine.succeed("curl -sf --unix-socket /run/nixus-admin/backend.sock http://localhost" + path)
        else:
            body = dict(body, _actor="admin")
            out = machine.succeed("curl -sS --fail-with-body --unix-socket /run/nixus-admin/backend.sock -H 'Content-Type: application/json' "
                                  "--data @- http://localhost" + path + " <<'EOF'\n" + json.dumps(body) + "\nEOF")
        return json.loads(out)

    machine.start()
    machine.wait_for_unit("nixus-admin-backend.service")
    machine.wait_for_unit("docker-registry.service")
    machine.wait_for_unit("incus.service")
    machine.wait_for_open_port(5000)

    with subtest("publish a digest-pinned base image to the local registry"):
        machine.succeed("skopeo --insecure-policy copy --dest-tls-verify=false docker-archive:${baseImage} docker://localhost:5000/nixus/base:1")
        digest = machine.succeed("skopeo --insecure-policy inspect --tls-verify=false docker://localhost:5000/nixus/base:1 | jq -r .Digest").strip()
        assert digest.startswith("sha256:"), digest

    with subtest("stage, review and publish the original source bytes"):
        files = {
            "Dockerfile": ("FROM localhost:5000/nixus/base:1@" + digest + "\nCOPY payload.txt /payload.txt\nCMD [\"/bin/sleep\", \"86400\"]\n").encode(),
            "payload.txt": b"guarded-oci-build\n",
        }
        entries = [{"path": p, "size": len(d), "sha256": hashlib.sha256(d).hexdigest()} for p, d in files.items()]
        prepared = broker("/project-import/prepare", {"project": "testapp", "files": entries})
        for p, d in files.items():
            broker("/project-import/chunk", {"id": prepared["id"], "path": p, "offset": 0, "data": base64.b64encode(d).decode()})
        sealed = broker("/project-import/finish", {"id": prepared["id"], "manifestHash": prepared["manifestHash"]})
        review = broker("/project-import/review", {"id": prepared["id"], "manifestHash": sealed["manifestHash"]})
        published = broker("/project-import/publish", {"id": prepared["id"], "reviewId": review["reviewId"], "acknowledge": True})
        revision = published["revision"]
        plan = broker("/project-import/plan", {"project": "testapp", "revision": revision})
        lock = plan["imageLock"]
        assert lock[0]["pinned"] and lock[0]["digest"] == digest, lock
        assert "dockerfile-base-image-must-be-pinned-by-digest" not in plan["blocking"], plan["blocking"]

    with subtest("an unpinned base is refused at review time"):
        bad = {"Dockerfile": b"FROM localhost:5000/nixus/base:1\n"}
        bentries = [{"path": p, "size": len(d), "sha256": hashlib.sha256(d).hexdigest()} for p, d in bad.items()]
        bp = broker("/project-import/prepare", {"project": "unpinned", "files": bentries})
        broker("/project-import/chunk", {"id": bp["id"], "path": "Dockerfile", "offset": 0, "data": base64.b64encode(bad["Dockerfile"]).decode()})
        bs = broker("/project-import/finish", {"id": bp["id"], "manifestHash": bp["manifestHash"]})
        br = broker("/project-import/review", {"id": bp["id"], "manifestHash": bs["manifestHash"]})
        bpub = broker("/project-import/publish", {"id": bp["id"], "reviewId": br["reviewId"], "acknowledge": True})
        bplan = broker("/project-import/plan", {"project": "unpinned", "revision": bpub["revision"]})
        assert "dockerfile-base-image-must-be-pinned-by-digest" in bplan["blocking"], bplan["blocking"]

    with subtest("offline sandbox build from the fetched pinned base, then Incus import"):
        oci = broker("/oci/review", {"project": "testapp", "revision": revision})
        assert oci["status"] == "ready", oci
        broker("/oci/build", {"id": oci["id"], "planHash": oci["planHash"]})
        deadline = time.time() + 900
        while True:
            status = broker("/oci/status")
            if status["status"] in ("imported", "failed", "interrupted", "cancelled"):
                break
            assert time.time() < deadline, status
            time.sleep(5)
        if status["status"] != "imported":
            machine.succeed("journalctl -b -u nixus-admin-backend -u 'nixus-oci-*' --no-pager | tail -n 120 >&2")
        assert status["status"] == "imported", status
        artifact = status["artifacts"][0]
        assert artifact["incusFingerprint"], artifact
        images = json.loads(machine.succeed("incus image list --project testapp --format=json"))
        assert any(i["fingerprint"] == artifact["incusFingerprint"] for i in images), images

    with subtest("the built image contains the base layer and the payload"):
        rootfs = "/var/lib/incus/images/" + artifact["incusFingerprint"] + ".rootfs"
        machine.succeed("test -s " + rootfs)
        listing = machine.succeed("tar -tf " + rootfs)
        assert "base-marker" in listing and "payload.txt" in listing, listing

    with subtest("a reviewed project revision deploys the imported image with incus-compose"):
        broker("/project/initialize", {"flake": "{ outputs = { self }: {}; }\n",
                                       "lock": json.dumps({"nodes": {"root": {}}, "root": "root", "version": 7})})
        decl = '{ ... }: { nixus.project = { backend = "incus-compose"; incusProject = "testapp"; }; }\n'
        reviewed = broker("/project/review", {"changes": {"testapp/default.nix": decl}, "sourceRevisions": {"testapp": revision}})
        actions = [a for a in reviewed["runtimeActions"] if a["project"] == "testapp"]
        assert [a["action"] for a in actions] == ["compose-up"], reviewed["runtimeActions"]
        broker("/project/publish", {"id": reviewed["id"], "planHash": reviewed["planHash"]})
        broker("/project/deploy", {"id": reviewed["id"], "planHash": reviewed["planHash"]})
        deadline = time.time() + 900
        while True:
            project = broker("/project/status")
            if project["deployment"] in ("verified", "partial", "interrupted"):
                break
            assert time.time() < deadline, project
            time.sleep(5)
        if project["deployment"] != "verified":
            machine.succeed("journalctl -b -u nixus-admin-backend -u 'nixus-project-*' --no-pager | tail -n 120 >&2")
        assert project["deployment"] == "verified", project
        running = json.loads(machine.succeed("incus list --project testapp --format=json"))
        assert len(running) == 1 and running[0]["status"] == "Running", running
        assert running[0]["config"]["volatile.base_image"] == artifact["incusFingerprint"], running[0]["config"]
        served = machine.succeed("incus exec " + running[0]["name"] + " --project testapp -- /bin/cat /payload.txt")
        assert served == "guarded-oci-build\n", served

    with subtest("project backup: config, Incus data, encrypted off-host copy and full verification"):
        machine.succeed("install -d -m 0700 /var/lib/nixus-secrets && head -c 32 /dev/urandom | base64 > /var/lib/nixus-secrets/project-restic-password && chmod 0600 /var/lib/nixus-secrets/project-restic-password")
        policy = ('{ ... }: { nixus.backups = { enable = true; schedule = "daily"; verification = "full";\n'
                  '  restic = { repository = "/var/lib/nixus-restic-drill"; initialize = true; }; }; }\n')
        breview = broker("/project/review", {"changes": {"backups.nix": policy}})
        broker("/project/publish", {"id": breview["id"], "planHash": breview["planHash"]})
        status = json.loads(machine.succeed("nixus-admin project-backup run"))
        phases = {k: v["state"] for k, v in status["phases"].items()}
        assert phases == {"config": "complete", "data": "complete", "offHost": "complete",
                          "verification": "complete", "github": "skipped"}, status["phases"]
        assert status["coverage"]["testapp"]["sourceRevision"] == revision, status["coverage"]

    with subtest("restore drill: restic restore, exact bytes, instance import and start"):
        machine.succeed("RESTIC_PASSWORD_FILE=/var/lib/nixus-secrets/project-restic-password "
                        "restic -r /var/lib/nixus-restic-drill restore latest --target /tmp/restore >&2")
        restored_decl = machine.succeed("cat $(find /tmp/restore -path '*/workspace/testapp/default.nix' | head -n1)")
        assert restored_decl == decl, restored_decl
        restored_df = machine.succeed("cat $(find /tmp/restore -path '*/sources/testapp/Dockerfile' | head -n1)")
        assert restored_df.encode() == files["Dockerfile"], restored_df
        archive = machine.succeed("find /tmp/restore -name 'instance-*.tar.gz' | head -n1").strip()
        assert archive, "no instance export in the restored snapshot"
        machine.succeed("incus project create drill -c features.images=false -c features.profiles=false -c features.storage.volumes=false")
        machine.succeed("incus import " + archive + " restored --project drill")
        machine.succeed("incus start restored --project drill")
        served = machine.succeed("incus exec restored --project drill -- /bin/cat /payload.txt")
        assert served == "guarded-oci-build\n", served
        running = json.loads(machine.succeed("incus list --project testapp --format=json"))
        assert len(running) == 1 and running[0]["status"] == "Running", running

    with subtest("cold-host restore: an empty host rebuilds projects from the encrypted backup alone"):
        machine.succeed("tar -C /var/lib -czf /tmp/restic-repo.tgz nixus-restic-drill")
        machine.copy_from_vm("/tmp/restic-repo.tgz")
        password = machine.succeed("cat /var/lib/nixus-secrets/project-restic-password")
        fresh.start()
        fresh.wait_for_unit("nixus-admin-backend.service")
        fresh.wait_for_unit("incus.service")
        fresh.copy_from_host(str(machine.out_dir / "restic-repo.tgz"), "/tmp/restic-repo.tgz")
        fresh.succeed("tar -C /var/lib -xzf /tmp/restic-repo.tgz && mv /var/lib/nixus-restic-drill /var/lib/nixus-restic-in")
        fresh.succeed("install -d -m 0700 /var/lib/nixus-secrets && install -m 0600 /dev/stdin /var/lib/nixus-secrets/restore-password <<'EOF'\n" + password + "EOF")
        fresh.fail("test -e /srv/nixus/projects")
        report = json.loads(fresh.succeed("nixus-admin project-backup restore --repository /var/lib/nixus-restic-in "
                                          "--password-file /var/lib/nixus-secrets/restore-password"))
        assert report["status"] == "restored", report
        assert report["sources"] == {"testapp": revision}, report["sources"]
        assert "testapp/" + json.loads(machine.succeed("incus list --project testapp --format=json"))[0]["name"] in report["incus"]["started"], report["incus"]
        assert fresh.succeed("cat /srv/nixus/projects/testapp/default.nix") == decl
        assert fresh.succeed("cat /srv/nixus/projects/backups.nix") == policy
        restored_src = "/srv/nixus/project-sources/testapp/revisions/" + revision + "/source/Dockerfile"
        assert fresh.succeed("cat " + restored_src).encode() == files["Dockerfile"]
        restored = json.loads(fresh.succeed("incus list --project testapp --format=json"))
        assert len(restored) == 1 and restored[0]["status"] == "Running", restored
        served = fresh.succeed("incus exec " + restored[0]["name"] + " --project testapp -- /bin/cat /payload.txt")
        assert served == "guarded-oci-build\n", served
        # A second restore onto the now-populated host is refused before any change.
        fresh.fail("nixus-admin project-backup restore --repository /var/lib/nixus-restic-in --password-file /var/lib/nixus-secrets/restore-password")
        fresh.shutdown()

    def push_web(image):
        machine.succeed("skopeo --insecure-policy copy --dest-tls-verify=false docker-archive:" + image + " docker://localhost:5000/nixus/webbase:1")
        return machine.succeed("skopeo --insecure-policy inspect --tls-verify=false docker://localhost:5000/nixus/webbase:1 | jq -r .Digest").strip()

    def run_auto(expect_ok):
        code, out = machine.execute("nixus-admin image-updates auto 2>&1")
        if (code == 0) != expect_ok:
            machine.succeed("nixus-admin image-updates status >&2; journalctl -b --no-pager | grep -E 'nixus: |COMPOSE-VM|OCI-VM' | tail -n 60 >&2")
        assert (code == 0) == expect_ok, out

    def web_instance():
        found = json.loads(machine.succeed("incus list --project web --format=json"))
        assert len(found) == 1, found
        return found[0]

    def web_exec(command):
        return machine.succeed("incus exec " + web_instance()["name"] + " --project web -- /bin/sh -c '" + command + "'")

    with subtest("image updates: deploy a Compose project with a named volume and an auto policy"):
        d1 = push_web("${webV1}")
        web_files = {
            "Dockerfile": ("FROM localhost:5000/nixus/webbase:1@" + d1 + "\nCMD [\"/bin/sleep\", \"86400\"]\n").encode(),
            "compose.yaml": b"services:\n  app:\n    build: .\n    volumes:\n      - data:/data\nvolumes:\n  data: {}\n",
        }
        wentries = [{"path": p, "size": len(d), "sha256": hashlib.sha256(d).hexdigest()} for p, d in web_files.items()]
        wp = broker("/project-import/prepare", {"project": "web", "files": wentries})
        for p, d in web_files.items():
            broker("/project-import/chunk", {"id": wp["id"], "path": p, "offset": 0, "data": base64.b64encode(d).decode()})
        ws = broker("/project-import/finish", {"id": wp["id"], "manifestHash": wp["manifestHash"]})
        wr = broker("/project-import/review", {"id": wp["id"], "manifestHash": ws["manifestHash"]})
        web_rev = broker("/project-import/publish", {"id": wp["id"], "reviewId": wr["reviewId"], "acknowledge": True})["revision"]
        wo = broker("/oci/review", {"project": "web", "revision": web_rev})
        broker("/oci/build", {"id": wo["id"], "planHash": wo["planHash"]})
        deadline = time.time() + 900
        while broker("/oci/status")["status"] not in ("imported", "failed", "interrupted"):
            assert time.time() < deadline
            time.sleep(3)
        assert broker("/oci/status")["status"] == "imported", broker("/oci/status")
        web_decl = '{ ... }: { nixus.project = { backend = "incus-compose"; updates = { policy = "auto"; healthSeconds = 10; }; }; }\n'
        wrev = broker("/project/review", {"changes": {"web/default.nix": web_decl}, "sourceRevisions": {"web": web_rev}})
        broker("/project/publish", {"id": wrev["id"], "planHash": wrev["planHash"]})
        broker("/project/deploy", {"id": wrev["id"], "planHash": wrev["planHash"]})
        deadline = time.time() + 900
        while broker("/project/status")["deployment"] not in ("verified", "partial", "interrupted"):
            assert time.time() < deadline
            time.sleep(3)
        assert broker("/project/status")["deployment"] == "verified", broker("/project/status")
        assert web_exec("cat /etc/web-version").strip() == "v1"
        web_exec("echo keep-me > /data/marker")

    with subtest("image updates: a new digest is applied automatically and volume data survives"):
        d2 = push_web("${webV2}")
        checked = json.loads(machine.succeed("nixus-admin image-updates check"))
        img = [i for i in checked["projects"]["web"]["images"] if i["file"] == "Dockerfile"][0]
        assert img["status"] == "update-available" and img["latest"] == d2, img
        run_auto(True)
        view = json.loads(machine.succeed("nixus-admin image-updates status"))
        assert view["projects"]["web"]["lastUpdate"]["status"] == "updated", view["projects"]["web"]
        assert web_instance()["status"] == "Running"
        assert web_exec("cat /etc/web-version").strip() == "v2"
        assert web_exec("cat /data/marker").strip() == "keep-me"

    with subtest("image updates: a broken image is rolled back, data restored, digest held"):
        web_exec("echo still-here > /data/marker")
        d3 = push_web("${webBroken}")
        machine.succeed("nixus-admin image-updates check >&2")
        run_auto(False)
        view = json.loads(machine.succeed("nixus-admin image-updates status"))
        assert view["projects"]["web"]["lastUpdate"]["status"] == "rolled-back", view["projects"]["web"]
        assert d3 in view["projects"]["web"]["holds"], view["projects"]["web"]
        assert web_instance()["status"] == "Running"
        assert web_exec("cat /etc/web-version").strip() == "v2"
        assert web_exec("cat /data/marker").strip() == "still-here"
        rechecked = json.loads(machine.succeed("nixus-admin image-updates check"))
        assert rechecked["projects"]["web"]["updates"] == 0, rechecked["projects"]["web"]
        run_auto(True)

    with subtest("one-step app deploy, as the Apps page does it"):
        notes = {"Dockerfile": ("FROM localhost:5000/nixus/base:1@" + digest + "\nCMD [\"/bin/sleep\", \"86400\"]\n").encode()}
        nentries = [{"path": p, "size": len(d), "sha256": hashlib.sha256(d).hexdigest()} for p, d in notes.items()]
        np_ = broker("/project-import/prepare", {"project": "notes", "files": nentries})
        broker("/project-import/chunk", {"id": np_["id"], "path": "Dockerfile", "offset": 0, "data": base64.b64encode(notes["Dockerfile"]).decode()})
        ns = broker("/project-import/finish", {"id": np_["id"], "manifestHash": np_["manifestHash"]})
        broker("/apps/deploy", {"project": "notes", "kind": "source", "stagingId": ns["id"], "manifestHash": ns["manifestHash"]})
        deadline = time.time() + 900
        while broker("/apps")["notes"]["status"] not in ("deployed", "failed"):
            assert time.time() < deadline, broker("/apps")
            time.sleep(3)
        job = broker("/apps")["notes"]
        if job["status"] != "deployed":
            machine.succeed("journalctl -b --no-pager | grep -E 'nixus: |COMPOSE-VM|OCI-VM' | tail -n 60 >&2")
        assert job["status"] == "deployed", job
        running = json.loads(machine.succeed("incus list --project notes --format=json"))
        assert len(running) == 1 and running[0]["status"] == "Running", running
        assert machine.succeed("cat /srv/nixus/projects/notes/default.nix").strip().endswith("}")
        saved = broker("/apps/backup-policy", {"policy": policy.replace("\"daily\"", "\"weekly\"")})
        assert saved["saved"], saved

    with subtest("published source bytes are unchanged"):
        src = "/srv/nixus/project-sources/testapp/revisions/" + revision + "/source/Dockerfile"
        assert machine.succeed("cat " + src).encode() == files["Dockerfile"]
  '';
}
