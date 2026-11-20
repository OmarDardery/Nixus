"""Verified rootfs, runtime config and fingerprint-checked Incus import (#47)."""
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "admin"))
import oci_artifacts
import oci_images

IMAGE = "localhost/nixus-sample-app:" + "a" * 32


def rootfs(entries=None):
    """entries: list of (name, type, data_or_linkname)."""
    entries = entries if entries is not None else [
        ("./etc", tarfile.DIRTYPE, None),
        ("./etc/passwd", tarfile.REGTYPE, b"root:x:0:0:root:/root:/bin/sh\napp:x:1000:1000::/home/app:/bin/sh\n"),
        ("./etc/group", tarfile.REGTYPE, b"root:x:0:\nstaff:x:50:\n"),
        ("./bin", tarfile.DIRTYPE, None),
        ("./bin/app", tarfile.REGTYPE, b"#!/bin/sh\n"),
        ("./bin/alias", tarfile.LNKTYPE, "./bin/app"),
        ("./bin/sh", tarfile.SYMTYPE, "app"),
    ]
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        root = tarfile.TarInfo(".")
        root.type = tarfile.DIRTYPE
        tar.addfile(root)
        for name, kind, value in entries:
            item = tarfile.TarInfo(name)
            item.type = kind
            if kind == tarfile.REGTYPE:
                item.size = len(value)
                tar.addfile(item, io.BytesIO(value))
                continue
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                item.linkname = value
            tar.addfile(item)
    return buffer.getvalue()


class FakeIncus:
    """In-memory Incus: split-image fingerprint = sha256(metadata || rootfs)."""
    def __init__(self, projects=None, wrong_fingerprint=False):
        self.projects = projects if projects is not None else {}
        self.images, self.aliases, self.calls = {}, {}, []
        self.wrong = wrong_fingerprint

    def __call__(self, *args, timeout=600):
        self.calls.append(args)
        if args[0] == "query":
            path, _, query = args[1].partition("?project=")
            parts = path.split("/")
            if parts[2] == "projects":
                if parts[3] not in self.projects:
                    raise ValueError("not found")
                return json.dumps({"config": self.projects[parts[3]]})
            if parts[3] == "aliases":
                key = (query, "/".join(parts[4:]))
                if key not in self.aliases:
                    raise ValueError("not found")
                return json.dumps({"target": self.aliases[key]})
            if (query, parts[3]) not in self.images:
                raise ValueError("not found")
            return json.dumps(self.images[(query, parts[3])])
        if args[:2] == ("project", "create"):
            self.projects[args[2]] = dict(a.split("=", 1) for a in args[4::2])
            return ""
        if args[:2] == ("image", "import"):
            project = args[args.index("--project") + 1]
            digest = hashlib.sha256(Path(args[2]).read_bytes() + Path(args[3]).read_bytes()).hexdigest()
            if self.wrong:
                digest = "f" * 64
            with tarfile.open(args[2]) as meta:
                properties = json.loads(meta.extractfile("metadata.yaml").read())["properties"]
            self.images[(project, digest)] = {"fingerprint": digest, "properties": properties}
            return "Image imported with fingerprint: " + digest + "\n"
        if args[:2] == ("image", "delete"):
            del self.images[(args[args.index("--project") + 1], args[2])]
            return ""
        if args[:3] == ("image", "alias", "create"):
            self.aliases[(args[args.index("--project") + 1], args[3])] = args[4]
            return ""
        raise AssertionError("unexpected incus call " + repr(args))


class RuntimeSpecTests(unittest.TestCase):
    def spec(self, config, passwd="", group=""):
        return json.loads(oci_images.runtime_spec(config, passwd, group))

    def test_matches_incus_compose_shape(self):
        value = self.spec({"Entrypoint": ["/bin/app"], "Cmd": ["--serve"], "Env": ["PATH=/opt/bin", "A=1"],
                           "WorkingDir": "/srv", "User": "1000"},
                          "app:x:1000:1000::/home/app:/bin/sh\n")
        self.assertEqual(value["process"]["args"], ["/bin/app", "--serve"])
        self.assertEqual(value["process"]["cwd"], "/srv")
        self.assertEqual(value["process"]["user"], {"uid": 1000, "gid": 1000})
        self.assertEqual(value["process"]["env"], ["TERM=xterm", "PATH=/opt/bin", "A=1", "HOME=/home/app"])

    def test_defaults_and_named_users_resolve_from_the_image(self):
        value = self.spec({"Cmd": ["/x"], "User": "app:staff"},
                          "app:x:1000:1000::/home/app:/bin/sh\n", "staff:x:50:\n")
        self.assertEqual(value["process"]["user"], {"uid": 1000, "gid": 50})
        self.assertEqual(value["process"]["cwd"], "/")
        self.assertIn("PATH=" + oci_images.DEFAULT_PATH, value["process"]["env"])

    def test_unresolved_user_or_missing_command_fails_instead_of_running_as_root(self):
        for config in ({"Cmd": ["/x"], "User": "ghost"}, {}, {"Cmd": "/x"},
                       {"Cmd": ["/x"], "Env": ["BROKEN"]}, {"Cmd": ["/x"], "WorkingDir": "relative"}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                oci_images.runtime_spec(config)


class MetadataAndNamesTests(unittest.TestCase):
    def test_metadata_is_deterministic_and_marks_oci(self):
        first = oci_images.metadata_tar(IMAGE, "amd64", 1700000000, b"{}")
        self.assertEqual(first, oci_images.metadata_tar(IMAGE, "amd64", 1700000000, b"{}"))
        with tarfile.open(fileobj=io.BytesIO(first)) as tar:
            self.assertEqual(tar.getnames(), ["metadata.yaml", "config.json"])
            meta = json.loads(tar.extractfile("metadata.yaml").read())
        self.assertEqual(meta["architecture"], "x86_64")
        self.assertEqual(meta["properties"]["type"], "oci")
        with self.assertRaises(ValueError):
            oci_images.metadata_tar(IMAGE, "s390x", 1, b"{}")

    def test_names_match_incus_compose(self):
        self.assertEqual(oci_images.alias_for(IMAGE), "local/nixus-sample-app:" + "a" * 32)
        self.assertEqual(oci_images.incus_project("my--app-"), "my-app")
        for bad in ("docker.io/library/nginx:1", "localhost/other:1", None):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                oci_images.alias_for(bad)


class RootfsVerificationTests(unittest.TestCase):
    def check(self, content, digest=None, size=None):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "app.rootfs.tar"
            path.write_bytes(content)
            return oci_artifacts.verify_rootfs(path, digest or hashlib.sha256(content).hexdigest(),
                                               len(content) if size is None else size)

    def test_valid_rootfs_returns_account_files(self):
        result = self.check(rootfs())
        self.assertIn("app:x:1000", result["passwd"])
        self.assertIn("staff", result["group"])

    def test_escapes_special_files_and_tampering_are_refused(self):
        for entries in ([("./dev/null", tarfile.CHRTYPE, None)], [("./fifo", tarfile.FIFOTYPE, None)],
                        [("../escape", tarfile.REGTYPE, b"x")], [("/abs", tarfile.REGTYPE, b"x")],
                        [("./a/../b", tarfile.REGTYPE, b"x")],
                        [("./link", tarfile.LNKTYPE, "./missing")]):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                self.check(rootfs(entries))
        with self.assertRaises(ValueError):
            self.check(rootfs(), digest="0" * 64)
        with self.assertRaises(ValueError):
            self.check(rootfs(), size=1)


class ImportTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        folder = Path(temp.name)
        self.meta, self.rootfs = folder / "app.meta.tar", folder / "app.rootfs.tar"
        self.meta.write_bytes(oci_images.metadata_tar(IMAGE, "amd64", 1, oci_images.runtime_spec({"Cmd": ["/x"]})))
        self.rootfs.write_bytes(rootfs())
        self.expected = oci_images.fingerprint(self.meta, self.rootfs)
        self.alias = oci_images.alias_for(IMAGE)

    def run_import(self, incus):
        oci_images.ensure_project("sample", incus)
        return oci_images.import_image("sample", self.alias, self.expected, self.meta, self.rootfs, incus)

    def test_import_creates_owned_project_and_binds_alias_to_exact_fingerprint(self):
        incus = FakeIncus()
        result = self.run_import(incus)
        self.assertEqual(result["fingerprint"], self.expected)
        self.assertEqual(incus.projects["sample"]["features.images"], "true")
        self.assertEqual(incus.projects["sample"][oci_images.OWNER_KEY], "true")
        self.assertEqual(incus.aliases[("sample", self.alias)], self.expected)
        self.assertNotIn("copy", {c[0] + " " + c[1] for c in incus.calls if len(c) > 1})
        # Idempotent: a retry neither re-imports nor moves the alias.
        before = len([c for c in incus.calls if c[:2] == ("image", "import")])
        self.run_import(incus)
        self.assertEqual(len([c for c in incus.calls if c[:2] == ("image", "import")]), before)

    def test_fingerprint_mismatch_removes_the_import_and_binds_nothing(self):
        incus = FakeIncus(wrong_fingerprint=True)
        with self.assertRaisesRegex(ValueError, "different image fingerprint"):
            self.run_import(incus)
        self.assertEqual(incus.images, {})
        self.assertEqual(incus.aliases, {})

    def test_alias_on_other_content_and_shared_image_store_are_refused(self):
        incus = FakeIncus()
        incus.aliases[("sample", self.alias)] = "e" * 64
        incus.projects["sample"] = {"features.images": "true"}
        with self.assertRaisesRegex(ValueError, "different content"):
            self.run_import(incus)
        self.assertEqual(incus.aliases[("sample", self.alias)], "e" * 64)
        with self.assertRaisesRegex(ValueError, "default image store"):
            oci_images.ensure_project("shared", FakeIncus({"shared": {"features.images": "false"}}))


if __name__ == "__main__":
    unittest.main()
