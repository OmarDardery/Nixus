"""Compose deploy adapter: preconditions, exclusive ownership, idempotent up (#45)."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "admin"))
import compose_deploy as cd
import oci_images

REVISION = "a" * 64
FP = "b" * 64
ALIAS = "local/nixus-shop-web:" + "a" * 32
OWNED = {oci_images.OWNER_KEY: "true", oci_images.BACKEND_KEY: oci_images.COMPOSE_BACKEND,
         "features.images": "true"}


class Builds:
    def __init__(self, record="default"):
        self.record = {"id": "c" * 32, "intentHash": "d" * 64,
                       "artifacts": [{"service": "web", "incusAlias": ALIAS, "incusFingerprint": FP}],
                       "services": [{"service": "web"}, {"service": "db"}],
                       "intent": {"separateOverride": "services: {}\n"}} if record == "default" else record

    def imported(self, project, revision):
        return self.record if (project, revision) == ("shop", REVISION) else None


class Incus:
    def __init__(self, project=None, aliases=None, instances=None):
        self.project = dict(OWNED) if project is None else project
        self.aliases = {ALIAS: FP} if aliases is None else aliases
        self.instances = instances if instances is not None else []
        self.calls = []

    def __call__(self, *args, timeout=600):
        self.calls.append(args)
        if args[0] == "query":
            path = args[1]
            if path == "/1.0/projects/shop":
                if self.project is False:
                    raise ValueError("missing")
                return json.dumps({"config": self.project})
            if path.startswith("/1.0/images/aliases/"):
                name = path[len("/1.0/images/aliases/"):].split("?")[0]
                if name not in self.aliases:
                    raise ValueError("missing")
                return json.dumps({"target": self.aliases[name]})
            if path.startswith("/1.0/instances"):
                return json.dumps(self.instances)
        if args[:2] == ("project", "set"):
            key, value = args[3].split("=", 1)
            self.project[key] = value
            return ""
        raise AssertionError(args)


def instance(name, service, status="Running", image=FP, extra=None):
    return {"name": name, "status": status,
            "config": {cd.SERVICE_LABEL: service, "volatile.base_image": image, **(extra or {})}}


class ObserveTests(unittest.TestCase):
    def observe(self, incus, builds=None):
        return cd.observe("shop", "shop", REVISION, builds=builds or Builds(), incus=incus)

    def test_fresh_project_plans_compose_up(self):
        resource = self.observe(Incus())
        self.assertEqual(resource["action"], "compose-up")
        self.assertEqual(resource["services"], ["db", "web"])
        self.assertEqual(resource["images"], [{"service": "web", "alias": ALIAS, "fingerprint": FP}])

    def test_running_reviewed_images_with_recorded_intent_is_noop(self):
        incus = Incus(instances=[instance("web-1", "web"), instance("db-1", "db", image="other")])
        incus.project[cd.INTENT_KEY] = "d" * 64
        self.assertEqual(self.observe(incus)["action"], "noop")
        incus.instances[0]["status"] = "Stopped"
        self.assertEqual(self.observe(incus)["action"], "compose-up")

    def test_image_change_is_reported_as_a_recreate(self):
        incus = Incus(instances=[instance("web-1", "web", image="e" * 64)])
        resource = self.observe(incus)
        self.assertEqual(resource["recreates"], ["web"])

    def test_preconditions_and_exclusive_ownership_fail_closed(self):
        cases = [
            (Incus(), Builds(None), "Build and import"),
            (Incus(project=False), None, "not owned"),
            (Incus(project={oci_images.OWNER_KEY: "true"}), None, "not owned"),
            (Incus(aliases={}), None, "alias"),
            (Incus(aliases={ALIAS: "f" * 64}), None, "alias"),
            (Incus(instances=[instance("vm", "web", extra={cd.NATIVE_OWNER: "true"})]), None, "native"),
            (Incus(instances=[{"name": "stray", "status": "Running", "config": {}}]), None, "not managed"),
        ]
        for incus, builds, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(cd.ComposeRefused, message):
                self.observe(incus, builds)
        with self.assertRaisesRegex(cd.ComposeRefused, "name incus-compose derives"):
            cd.observe("shop", "other", REVISION, builds=Builds(), incus=Incus())


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.incus = Incus()
        self.builds = Builds()
        self.approved = cd.observe("shop", "shop", REVISION, builds=self.builds, incus=self.incus)

    def fake_up(self, *args, **kwargs):
        self.incus.instances[:] = [instance("web-1", "web"), instance("db-1", "db")]
        self.incus.project[cd.INTENT_KEY] = "d" * 64

    def test_apply_runs_up_once_then_verifies(self):
        with patch.object(cd, "up", side_effect=self.fake_up) as up:
            result = cd.recheck_and_apply(self.approved, builds=self.builds, incus=self.incus)
        up.assert_called_once()
        self.assertEqual(result["health"], "Running")
        with patch.object(cd, "up") as again:
            cd.recheck_and_apply(self.approved, builds=self.builds, incus=self.incus)
        again.assert_not_called()

    def test_changed_build_or_instances_since_review_refuse(self):
        changed = Builds({**self.builds.record, "id": "9" * 32})
        with patch.object(cd, "up") as up, self.assertRaisesRegex(cd.ComposeRefused, "changed since review"):
            cd.recheck_and_apply(self.approved, builds=changed, incus=self.incus)
        self.incus.instances.append(instance("web-1", "web", status="Stopped"))
        with self.assertRaisesRegex(cd.ComposeRefused, "instances changed"):
            cd.recheck_and_apply(self.approved, builds=self.builds, incus=self.incus)
        up.assert_not_called()

    def test_resume_reruns_up_and_unhealthy_result_is_not_verified(self):
        self.incus.instances.append(instance("web-1", "web", status="Stopped"))
        with patch.object(cd, "up", side_effect=lambda *a, **k: None):
            with self.assertRaisesRegex(cd.ComposeRefused, "not all running"):
                cd.recheck_and_apply(self.approved, verify_only=True, builds=self.builds, incus=self.incus)
        with patch.object(cd, "up", side_effect=self.fake_up):
            self.assertEqual(cd.recheck_and_apply(self.approved, verify_only=True, builds=self.builds,
                                                  incus=self.incus)["status"], "verified")

    def test_up_command_never_builds_removes_or_downs(self):
        captured = []
        def compose(args, **kwargs):
            captured.append(args)
            return b""
        with patch.object(cd, "_materialize", return_value=(Path("/var/empty"), [Path("/var/empty/c.yaml")])), \
                patch.object(cd, "_compose", side_effect=compose), patch.object(cd.rt, "STATE", Path("/tmp")):
            cd.up("shop", "shop", REVISION, builds=self.builds, incus=self.incus)
        args = captured[0]
        self.assertIn("up", args)
        for flag in ("--no-build", "--detach", "--no-healthd", "--no-dns"):
            self.assertIn(flag, args)
        for forbidden in ("down", "--volumes", "--build", "--recreate", "rm"):
            self.assertNotIn(forbidden, args)
        self.assertEqual(self.incus.project[cd.INTENT_KEY], "d" * 64)


if __name__ == "__main__":
    unittest.main()
