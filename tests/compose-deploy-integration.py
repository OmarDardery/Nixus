"""Disposable NixOS VM: deploy a two-service Compose app built from source with
the real pinned incus-compose, redeploy a changed revision, keep volume data,
and refuse instances that Compose does not own (#45)."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
from unittest.mock import patch

os.environ["NIXUS_STATE"] = "/var/lib/nixus-oci-vm-state"
os.environ["NIXUS_PROJECT_SOURCES"] = "/srv/nixus/project-sources"
os.environ["NIXUS_OCI_ROOT"] = "/var/lib/nixus-oci"
os.environ["NIXUS_OCI_VM_TEST"] = "1"
Path(os.environ["NIXUS_STATE"]).mkdir(mode=0o700, exist_ok=True)

import compose_deploy
import native_imports
import oci_builds
import runtime as rt

BUSYBOX = Path(os.environ["NIXUS_OCI_TEST_BUSYBOX"]).read_bytes()
DOCKERFILE = (b"FROM scratch\nCOPY --chmod=0755 busybox /bin/busybox\nCOPY page.txt /page.txt\n"
              b'CMD ["/bin/busybox", "sleep", "3600"]\n')
COMPOSE = b"""services:
  web:
    build: ./web
  worker:
    build: ./worker
    volumes:
      - data:/data
volumes:
  data: {}
"""


def incus(*args):
    result = subprocess.run(["incus", "--force-local", *args], capture_output=True, text=True, timeout=300)
    if result.returncode:
        raise SystemExit("incus " + " ".join(args) + " failed: " + result.stderr[-2000:])
    return result.stdout


def publish(page):
    files = {"compose.yaml": COMPOSE}
    for service in ("web", "worker"):
        files[service + "/Dockerfile"] = DOCKERFILE
        files[service + "/busybox"] = BUSYBOX
        files[service + "/page.txt"] = page if service == "web" else b"worker\n"
    stage, published = native_imports.ImportStaging(), native_imports.PublishedSources()
    entries = [{"path": n, "size": len(v), "sha256": hashlib.sha256(v).hexdigest()} for n, v in files.items()]
    prepared = stage.prepare("root-test", "shop", entries)
    for name, data in files.items():
        for offset in range(0, len(data), native_imports.MAX_CHUNK):
            stage.chunk(prepared["id"], "root-test", name, offset,
                        base64.b64encode(data[offset:offset + native_imports.MAX_CHUNK]).decode())
    sealed = stage.finish(prepared["id"], "root-test", prepared["manifestHash"])
    approval = published.review(stage, prepared["id"], "root-test", sealed["manifestHash"])
    return published.publish(stage, prepared["id"], "root-test", approval["reviewId"], acknowledge=True)["revision"]


def build(revision):
    engine = oci_builds.OCIBuilds()
    review = engine.review("shop", revision, principal="vm-test")
    assert review["status"] == "ready", review
    with patch.object(rt, "pin_worker_runtime"), patch.object(
            oci_builds.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"", b"")):
        engine.queue(review["id"], review["planHash"])
    done = engine.run(review["id"])
    assert done["status"] == "imported", done
    return done


def instances():
    rows = json.loads(incus("query", "/1.0/instances?recursion=1&project=shop"))
    return {r["config"][compose_deploy.SERVICE_LABEL]: r for r in rows}


def deploy(revision):
    planned = compose_deploy.observe("shop", "shop", revision)
    assert planned["action"] == "compose-up", planned
    result = compose_deploy.recheck_and_apply(planned)
    assert result["status"] == "verified", result
    again = compose_deploy.observe("shop", "shop", revision)
    assert again["action"] == "noop", again
    return planned


first = publish(b"version-1\n")
build(first)
deploy(first)
running = instances()
assert set(running) == {"web", "worker"}, running
assert all(r["status"] == "Running" for r in running.values()), running
worker = running["worker"]["name"]
incus("exec", worker, "--project", "shop", "--", "/bin/busybox", "sh", "-c", "echo kept > /data/mark")
web = running["web"]["name"]
assert incus("exec", web, "--project", "shop", "--", "/bin/busybox", "cat", "/page.txt") == "version-1\n"

# A changed revision is a new build, a new image and a reviewed recreate.
second = publish(b"version-2\n")
build(second)
planned = deploy(second)
assert "web" in planned["recreates"], planned
running = instances()
web = running["web"]["name"]
assert incus("exec", web, "--project", "shop", "--", "/bin/busybox", "cat", "/page.txt") == "version-2\n"
worker = running["worker"]["name"]
assert incus("exec", worker, "--project", "shop", "--", "/bin/busybox", "cat", "/data/mark") == "kept\n", \
    "Named volume data must survive a redeploy"

# Exclusive ownership: an instance Compose does not manage blocks the adapter.
incus("create", "local:" + planned["images"][0]["alias"], "stray", "--project", "shop", "--storage", "default")
try:
    compose_deploy.observe("shop", "shop", second)
    raise SystemExit("Unmanaged instance in a Compose project was not refused")
except compose_deploy.ComposeRefused:
    pass
incus("delete", "--force", "stray", "--project", "shop")
assert compose_deploy.observe("shop", "shop", second)["action"] == "noop"
print("COMPOSE-DEPLOY-VM-PASSED")
