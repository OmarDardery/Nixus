"""Disposable NixOS VM: real unprivileged systemd+bwrap+Buildah build, then a
fingerprint-verified import into real Incus and an OCI container start."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

os.environ["NIXUS_STATE"] = "/var/lib/nixus-oci-vm-state"
os.environ["NIXUS_PROJECT_SOURCES"] = "/srv/nixus/project-sources"
os.environ["NIXUS_OCI_ROOT"] = "/var/lib/nixus-oci"

import native_imports
import runtime as rt
import oci_builds

os.environ["NIXUS_OCI_VM_TEST"] = "1"
Path(os.environ["NIXUS_STATE"]).mkdir(mode=0o700, exist_ok=True)
stage = native_imports.ImportStaging()
published = native_imports.PublishedSources()
engine = oci_builds.OCIBuilds()
files = {
    "Dockerfile": (b"FROM scratch\nCOPY --chmod=0755 busybox /bin/busybox\nCOPY payload.txt /payload.txt\n"
                   b'CMD ["/bin/busybox", "sleep", "600"]\n'),
    "payload.txt": b"guarded-oci-build\n",
    "busybox": Path(os.environ["NIXUS_OCI_TEST_BUSYBOX"]).read_bytes(),
}
entries = [{"path": name, "size": len(value), "sha256": hashlib.sha256(value).hexdigest()}
           for name, value in files.items()]
prepared = stage.prepare("root-test", "testapp", entries)
for name, data in files.items():
    for offset in range(0, len(data), native_imports.MAX_CHUNK):
        stage.chunk(prepared["id"], "root-test", name, offset,
                    base64.b64encode(data[offset:offset + native_imports.MAX_CHUNK]).decode())
sealed = stage.finish(prepared["id"], "root-test", prepared["manifestHash"])
approval = published.review(stage, prepared["id"], "root-test", sealed["manifestHash"])
current = published.publish(stage, prepared["id"], "root-test", approval["reviewId"], acknowledge=True)
source = published.root / "testapp" / "revisions" / current["revision"] / "source"
assert (source / "Dockerfile").read_bytes() == files["Dockerfile"]

# The real pinned incus-compose parser runs under systemd-run as nixus-oci,
# with bubblewrap --unshare-all, no host network and no Incus socket.
review = engine.review("testapp", current["revision"], principal="vm-test")
assert review["status"] == "ready", review
assert review["services"][0]["built"] is True, review
assert not list((oci_builds.ROOT / "jobs").iterdir()), "Isolated snapshot cleaned after review"

# Mock only root dispatcher, not the unprivileged builder: it runs for real.
with patch.object(rt, "pin_worker_runtime"), patch.object(
        oci_builds.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"", b"")):
    queued = engine.queue(review["id"], review["planHash"])
assert queued["status"] == "queued"
completed = engine.run(review["id"])
assert completed["status"] == "imported", completed
artifact = completed["artifacts"][0]
assert artifact["sha256"] and artifact["bytes"] > 0
assert (source / "Dockerfile").read_bytes() == files["Dockerfile"]
assert (source / "payload.txt").read_bytes() == files["payload.txt"]
assert not list((oci_builds.ROOT / "jobs").iterdir()), "Builder work removed"


def incus(*args):
    return subprocess.run(["incus", "--force-local", *args], check=True, capture_output=True,
                          text=True, timeout=300).stdout


# The alias incus-compose resolves for the generated image reference points at
# exactly the fingerprint root computed before import.
project = artifact["incusProject"]
assert project == "testapp", artifact
assert artifact["incusAlias"] == "local/" + artifact["image"].removeprefix("localhost/"), artifact
alias = json.loads(incus("query", "/1.0/images/aliases/" + artifact["incusAlias"] + "?project=" + project))
assert alias["target"] == artifact["incusFingerprint"], (alias, artifact)
image = json.loads(incus("query", "/1.0/images/" + artifact["incusFingerprint"] + "?project=" + project))
assert image["properties"]["type"] == "oci", image
assert json.loads(incus("query", "/1.0/projects/" + project))["config"]["user.nixus.owner"] == "true"
# A retry is idempotent: same fingerprint, alias unmoved, no duplicate image.
import oci_images
folder = engine._job(review["id"]) / "artifacts"
oci_images.import_image(project, artifact["incusAlias"], artifact["incusFingerprint"],
                        folder / "app.meta.tar", folder / "app.rootfs.tar", oci_builds._incus)
assert len(json.loads(incus("query", "/1.0/images?project=" + project))) == 1

# Incus reads config.json from the image: the OCI container runs the image CMD.
incus("create", artifact["incusAlias"], "proof", "--project", project, "--storage", "default")
assert incus("config", "get", "proof", "oci.entrypoint", "--project", project).strip() == "/bin/busybox sleep 600"
incus("start", "proof", "--project", project)
assert incus("exec", "proof", "--project", project, "--", "/bin/busybox", "cat", "/payload.txt") == "guarded-oci-build\n"
incus("delete", "--force", "proof", "--project", project)
print("OCI-ISOLATED-BUILDAH-VM-PASSED")
