"""Deploy a reviewed Compose project with the pinned incus-compose (#45).

Preconditions, all checked again immediately before every apply:
- the project's bound source revision has an `imported` OCI build (#47) and
  every built image alias still points at its verified fingerprint;
- the Incus project is owned by Nixus *for Compose* (user.nixus.owner and
  user.nixus.backend=incus-compose). It never holds native or host-owned
  instances, and every instance in it carries incus-compose's service label.

Apply runs `incus-compose up --detach --no-build` on a root-only copy of the
exact reviewed source plus the reviewed image override. It never runs `down`,
never removes volumes, and never builds or pulls the locally built images.
`up` is idempotent, so an interrupted apply is resumed by running it again.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import oci_images
import runtime as rt

SERVICE_LABEL = "user.label.incus-compose.service"
INTENT_KEY = "user.nixus.compose-intent"
NATIVE_OWNER = "user.nixus.owner"
STABLE = ("kind", "project", "name", "sourceProject", "revision", "buildId", "intentHash", "images", "services")


class ComposeRefused(ValueError):
    pass


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _incus(*args, timeout=600):
    import operations
    return operations.incus(*args, timeout=timeout)


def _query(path, incus):
    try:
        return json.loads(incus("query", path))
    except ValueError:
        return None


def _builds():
    import oci_builds
    return oci_builds.OCIBuilds()


def observe(source_project, incus_project, revision, *, builds=None, incus=None):
    """Read-only. Returns a reviewable resource, or raises ComposeRefused."""
    incus = incus or _incus
    if incus_project != oci_images.incus_project(source_project):
        raise ComposeRefused("A Compose project's Incus project must be the name incus-compose derives")
    build = (builds or _builds()).imported(source_project, revision)
    if build is None:
        raise ComposeRefused("Build and import the bound source revision before deploying it")
    project = _query("/1.0/projects/" + incus_project, incus)
    config = (project or {}).get("config") or {}
    if (project is None or config.get(oci_images.OWNER_KEY) != "true"
            or config.get(oci_images.BACKEND_KEY) != oci_images.COMPOSE_BACKEND):
        raise ComposeRefused("The Incus project is not owned by Nixus for Compose")
    images = []
    for item in sorted(build["artifacts"], key=lambda a: a["service"]):
        alias = _query("/1.0/images/aliases/" + item["incusAlias"] + "?project=" + incus_project, incus)
        if (alias or {}).get("target") != item["incusFingerprint"]:
            raise ComposeRefused("A built image alias no longer points at its verified fingerprint")
        images.append({"service": item["service"], "alias": item["incusAlias"],
                       "fingerprint": item["incusFingerprint"]})
    services = sorted(s["service"] for s in build["services"])
    instances = _query("/1.0/instances?recursion=1&project=" + incus_project, incus) or []
    observed = {}
    for instance in instances:
        settings = instance.get("config") or {}
        if settings.get(NATIVE_OWNER) == "true":
            raise ComposeRefused("A native Nixus-owned instance is inside the Compose project")
        service = settings.get(SERVICE_LABEL)
        if not service:
            raise ComposeRefused("An instance not managed by incus-compose is inside the Compose project")
        observed[instance["name"]] = {"service": service, "status": str(instance.get("status"))[:32],
                                      "image": settings.get("volatile.base_image", "")}
    expected = {i["service"]: i["fingerprint"] for i in images}
    running = {s: [o for o in observed.values() if o["service"] == s] for s in services}
    current = (config.get(INTENT_KEY) == build["intentHash"] and all(
        running[s] and all(o["status"] == "Running" and o["image"] == expected.get(s, o["image"])
                           for o in running[s]) for s in services))
    recreated = sorted(s for s in services if any(o["image"] != expected.get(s, o["image"]) for o in running[s]))
    resource = {
        "kind": "compose", "project": incus_project, "name": "compose", "sourceProject": source_project,
        "revision": revision, "buildId": build["id"], "intentHash": build["intentHash"],
        "images": images, "services": services, "instances": observed,
        "action": "noop" if current else "compose-up",
        "observedStatus": "Running" if current else "Pending",
        "before": {"services": sorted({o["service"] for o in observed.values()})},
        "after": {"services": services, "revision": revision},
        "recreates": recreated,
    }
    resource["etag"] = digest({k: resource[k] for k in STABLE + ("instances",)})
    return resource


def _materialize(source_project, revision, build, directory):
    from native_imports import PublishedSources, _verified_source, check_files
    from oci_source_plan import source_plan
    publisher = PublishedSources()
    plan = source_plan(source_project, revision, publisher)
    source = directory / "source"
    source.mkdir(mode=0o700)
    _verified_source(publisher.root / source_project / "revisions" / revision / "source",
                     check_files(plan["sourceFiles"]), destination=source)
    if plan.get("generatedCompose"):
        compose = source / ".nixus-generated-compose.yaml"
        rt.atomic(compose, plan["generatedCompose"], mode=0o600)
    elif plan.get("entrypoint"):
        compose = source / plan["entrypoint"]
    else:
        raise ComposeRefused("The reviewed source has no Compose entry point")
    files = [compose]
    override = build["intent"].get("separateOverride") or ""
    if override:
        files.append(directory / "nixus-override.yaml")
        rt.atomic(files[-1], override, mode=0o600)
    return source, files


def _compose(args, *, cwd, home, timeout=1800):
    binary = os.environ.get("NIXUS_OCI_COMPOSE_BIN") or "incus-compose"
    env = {"PATH": os.environ.get("PATH", "/run/current-system/sw/bin"), "HOME": str(home),
           "INCUS_COMPOSE_UP_NO_BUILD": "1"}
    result = subprocess.run([binary, "--ansi", "never", *args], cwd=cwd, env=env,
                            capture_output=True, timeout=timeout)
    if result.returncode:
        if os.environ.get("NIXUS_OCI_VM_TEST") == "1":
            print("COMPOSE-VM-STDERR:", result.stderr[-3000:].decode(errors="replace"))
        raise ComposeRefused("incus-compose could not bring the reviewed project up")
    return result.stdout


def up(source_project, incus_project, revision, *, builds=None, incus=None):
    """Bring the exact reviewed revision up. Never down, never volume removal."""
    build = (builds or _builds()).imported(source_project, revision)
    if build is None:
        raise ComposeRefused("Build and import the bound source revision before deploying it")
    scratch = Path(tempfile.mkdtemp(prefix="compose-", dir=rt.STATE))
    try:
        os.chmod(scratch, 0o700)
        source, files = _materialize(source_project, revision, build, scratch)
        flags = ["-p", source_project, "-P", str(source)]
        for item in files:
            flags += ["-f", str(item)]
        # Local images exist in the project; digest-pinned images may be fetched.
        _compose(flags + ["--image-cache", "", "up", "--detach", "--no-build", "--pull", "missing",
                          "--no-healthd", "--no-dns"], cwd=source, home=scratch)
        (incus or _incus)("project", "set", incus_project, INTENT_KEY + "=" + build["intentHash"])
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def stable(resource):
    return {k: resource.get(k) for k in STABLE}


def recheck_and_apply(approved, *, verify_only=False, builds=None, incus=None):
    actual = observe(approved["sourceProject"], approved["project"], approved["revision"],
                     builds=builds, incus=incus)
    if stable(actual) != stable(approved):
        raise ComposeRefused("The Compose project changed since review; re-review before deployment")
    if actual["action"] == "noop":
        return {"status": "verified", "newEtag": actual["etag"], "health": "Running"}
    if not verify_only and actual["etag"] != approved["etag"]:
        raise ComposeRefused("Compose instances changed since review; re-review before deployment")
    up(approved["sourceProject"], approved["project"], approved["revision"], builds=builds, incus=incus)
    verified = observe(approved["sourceProject"], approved["project"], approved["revision"],
                       builds=builds, incus=incus)
    if verified["action"] != "noop":
        raise ComposeRefused("Compose services are not all running the reviewed images")
    return {"status": "verified", "newEtag": verified["etag"], "health": "Running"}
