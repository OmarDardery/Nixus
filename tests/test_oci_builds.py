"""Verify independent, no-Incus OCI build review and artifact journaling."""
import base64
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "admin"))
sys.path.insert(0, str(ROOT / "tests"))
import oci_builds
import oci_compose
import native_imports as sources
import runtime as rt
import test_oci_artifacts
import test_oci_images


class OCIBuildReviewTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.patches = [
            patch.object(rt, "audit"),
            patch.object(rt, "locked", return_value=nullcontext()),
            patch.object(oci_builds, "ROOT", self.root / "oci"),
            patch.object(oci_builds, "_account", return_value=(os.geteuid(), os.getegid())),
            patch.object(oci_builds, "_chown_tree"),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        self.publisher = sources.PublishedSources(self.root / "private-source")
        self.staging = sources.ImportStaging(self.root / "state")
        self.manager = oci_builds.OCIBuilds(self.root / "state", publisher=self.publisher)
        self.published = self._source(b"FROM scratch\nCOPY content.dat /content.dat\n", b"binary")

    def _source(self, dockerfile, content):
        values = {"Dockerfile": dockerfile, "content.dat": content}
        files = [{"path": name, "size": len(value), "sha256": hashlib.sha256(value).hexdigest()}
                 for name, value in values.items()]
        ready = self.staging.prepare("owner", "sample", files)
        for name, data in values.items():
            self.staging.chunk(ready["id"], "owner", name, 0, base64.b64encode(data).decode())
        done = self.staging.finish(ready["id"], "owner", ready["manifestHash"])
        reviewed = self.publisher.review(self.staging, done["id"], "owner", done["manifestHash"])
        return self.publisher.publish(self.staging, done["id"], "owner",
                                      reviewed["reviewId"], acknowledge=True)

    def fake_sandbox(self, workspace, mode, identity):
        spec = json.loads((workspace / "work" / "intent.json").read_text())
        checked = oci_compose.validate_model(
            {"services": {"app": {"build": {"context": "."}}}},
            project="sample", revision=spec["revision"], compose_path="Dockerfile",
            files=spec["sourceFiles"])
        if mode == "inspect":
            (workspace / "out" / "intent.json").write_text(json.dumps(checked))
            return
        self.assertEqual(mode, "build")
        self.assertEqual(checked["intentHash"], spec["intentHash"])
        content = test_oci_artifacts.archive()
        (workspace / "out" / "app.oci.tar").write_bytes(content)
        flat = test_oci_images.rootfs()
        (workspace / "out" / "app.rootfs.tar").write_bytes(flat)
        (workspace / "out" / "build-result.json").write_text(json.dumps({
            "format": 1, "project": "sample", "revision": spec["revision"],
            "intentHash": checked["intentHash"],
            "artifacts": [{"service": "app", "image": checked["services"][0]["image"],
                           "artifact": "app.oci.tar",
                           "sha256": hashlib.sha256(content).hexdigest(),
                           "bytes": len(content), "rootfs": "app.rootfs.tar",
                           "rootfsSha256": hashlib.sha256(flat).hexdigest(),
                           "rootfsBytes": len(flat)}]
        }))

    def test_review_is_source_only_and_build_approval_is_exact(self):
        with patch.object(oci_builds, "_run_sandbox", side_effect=self.fake_sandbox):
            reviewed = self.manager.review("sample", self.published["revision"], principal="portal-admin")
        self.assertEqual(reviewed["status"], "ready")
        self.assertEqual(reviewed["services"][0]["built"], True)
        self.assertFalse((self.root / "oci" / "jobs").joinpath(reviewed["id"]).exists(),
                         "Builder workspace cleaned after preview")
        with self.assertRaisesRegex(ValueError, "exact"):
            self.manager.queue(reviewed["id"], "0" * 64)
        self.assertEqual(self.manager.status(reviewed["id"])["status"], "ready")

    def test_failed_builder_keeps_existing_private_source_unchanged(self):
        with patch.object(oci_builds, "_run_sandbox", side_effect=self.fake_sandbox):
            reviewed = self.manager.review("sample", self.published["revision"])
        with patch.object(oci_builds.rt, "pin_worker_runtime"), patch.object(
                oci_builds.subprocess, "run"):
            queued = self.manager.queue(reviewed["id"], reviewed["planHash"])
        self.assertEqual(queued["status"], "queued")
        def reject(*args):
            raise ValueError("buildah failed without output")
        with patch.object(oci_builds, "_run_sandbox", side_effect=reject):
            result = self.manager.run(reviewed["id"])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["errorCode"], "build-or-artifact-verification-failed")
        self.assertEqual(self.publisher.attest("sample", self.published["revision"])["fileCount"], 2)
        self.assertFalse((self.manager._job(reviewed["id"]) / "artifacts" / "app.oci.tar").exists())
        self.assertFalse((self.root / "state" / "oci-build-active.json").exists())

    def built(self, incus):
        with patch.object(oci_builds, "_run_sandbox", side_effect=self.fake_sandbox):
            reviewed = self.manager.review("sample", self.published["revision"])
        with patch.object(oci_builds.rt, "pin_worker_runtime"), patch.object(
                oci_builds.subprocess, "run"):
            self.manager.queue(reviewed["id"], reviewed["planHash"])
        with patch.object(oci_builds, "_run_sandbox", side_effect=self.fake_sandbox), \
                patch.object(oci_builds, "_incus", incus):
            return reviewed, self.manager.run(reviewed["id"])

    def test_build_artifact_is_verified_then_imported_with_its_fingerprint(self):
        incus = test_oci_images.FakeIncus()
        reviewed, done = self.built(incus)
        self.assertEqual(done["status"], "imported")
        self.assertEqual(len(done["artifacts"]), 1)
        folder = self.manager._job(reviewed["id"]) / "artifacts"
        artifact = folder / "app.oci.tar"
        for path in (artifact, folder / "app.rootfs.tar", folder / "app.meta.tar"):
            self.assertEqual(path.stat().st_mode & 0o222, 0, path)
        item = done["artifacts"][0]
        self.assertEqual(item["sha256"], hashlib.sha256(artifact.read_bytes()).hexdigest())
        self.assertEqual(item["incusFingerprint"], hashlib.sha256(
            (folder / "app.meta.tar").read_bytes() + (folder / "app.rootfs.tar").read_bytes()).hexdigest())
        self.assertEqual(incus.aliases[("sample", item["incusAlias"])], item["incusFingerprint"])
        self.assertEqual(item["incusAlias"], "local/" + item["image"].removeprefix("localhost/"))
        with tarfile.open(folder / "app.meta.tar") as meta:
            spec = json.loads(meta.extractfile("config.json").read())
        self.assertEqual(spec["process"]["args"], ["/bin/app"])
        self.assertFalse((self.root / "state" / "oci-build-active.json").exists())
        self.assertEqual(self.manager.status(reviewed["id"])["status"], "imported")

    def test_import_failure_keeps_verified_artifacts_and_reports_it(self):
        reviewed, done = self.built(test_oci_images.FakeIncus(wrong_fingerprint=True))
        self.assertEqual(done["status"], "failed")
        self.assertEqual(done["errorCode"], "incus-import-failed")
        self.assertTrue((self.manager._job(reviewed["id"]) / "artifacts" / "app.oci.tar").exists())

    def test_published_source_rotation_blocks_expired_review(self):
        with patch.object(oci_builds, "_run_sandbox", side_effect=self.fake_sandbox):
            reviewed = self.manager.review("sample", self.published["revision"])
        self._source(b"FROM scratch\n", b"next")
        with self.assertRaisesRegex(ValueError, "revision"):
            self.manager.queue(reviewed["id"], reviewed["planHash"])


class SandboxCommandTests(unittest.TestCase):
    def test_sandbox_has_no_network_and_child_uses_offline_policy(self):
        import oci_builder_child as child
        env = {"NIXUS_OCI_BWRAP_BIN": "/nix/store/x-bwrap/bin/bwrap",
               "NIXUS_OCI_COMPOSE_BIN": "/nix/store/x-compose/bin/incus-compose",
               "NIXUS_OCI_BUILDAH_BIN": "/nix/store/x-buildah/bin/buildah"}
        with patch.dict(os.environ, env), patch.object(oci_builds.os.path, "realpath",
                                                       side_effect=lambda p: "/nix/store/x" + str(p)):
            command = oci_builds._sandbox_command(Path("/var/empty/job"), "build")
        self.assertIn("--unshare-all", command)
        self.assertNotIn("--share-net", command)
        self.assertEqual(command[command.index("--cap-add") + 1], "ALL")
        self.assertEqual(child.POLICY["default"], [{"type": "reject"}])
        self.assertEqual(set(child.POLICY["transports"]), {"containers-storage", "oci-archive"})


if __name__ == "__main__":
    unittest.main()
