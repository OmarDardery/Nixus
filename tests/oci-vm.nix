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
in pkgs.testers.runNixOSTest {
  name = "nixus-oci";
  globalTimeout = 1500;
  node.specialArgs = {
    inventory = settings;
    installedBase = { ... }: { system.stateVersion = "26.05"; };
  };
  nodes.machine = { lib, pkgs, ... }: {
    imports = [ ../configuration-bootstrap.nix ];
    virtualisation = { memorySize = 4096; diskSize = 8192; cores = 2; };
    boot.kernelModules = lib.mkForce [ ];
    environment.systemPackages = [ pkgs.curl pkgs.jq pkgs.skopeo ];
    services.dockerRegistry = { enable = true; listenAddress = "127.0.0.1"; port = 5000; };
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

    with subtest("published source bytes are unchanged"):
        src = "/srv/nixus/project-sources/testapp/revisions/" + revision + "/source/Dockerfile"
        assert machine.succeed("cat " + src).encode() == files["Dockerfile"]
  '';
}
