"""Turn verified OCI build output into fingerprint-checked Incus images (#47).

Incus 7 has no local OCI-archive import, so this follows the format Incus and
incus-compose use for OCI-type split images:

- metadata tarball: metadata.yaml (JSON, properties.type=oci) + config.json
  (an OCI *runtime* spec Incus reads for oci.entrypoint/cwd/uid/gid and env)
- rootfs tarball: the flattened image filesystem from the sandbox

Incus fingerprints a split image as sha256(metadata || rootfs). The fingerprint
is computed here *before* import and the import is refused on any mismatch, so
an alias only ever points at the exact reviewed bytes. Nothing is pulled from a
registry. The alias matches what incus-compose resolves for the generated
`image: localhost/nixus-...` reference, so `incus-compose up` (#45) reuses it.
"""
import hashlib
import io
import json
import re
import tarfile

DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ARCHITECTURES = {"amd64": "x86_64", "arm64": "aarch64"}
LOCAL_IMAGE = re.compile(r"localhost/(nixus-[a-z0-9-]{1,50}):([0-9a-f]{1,64})\Z")
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")
OWNER_KEY = "user.nixus.owner"
BACKEND_KEY = "user.nixus.backend"
COMPOSE_BACKEND = "incus-compose"
MAX_ARGS = 256


def incus_project(name):
    """incus-compose's SanitizeProjectName (slug) for Nixus' already-safe names."""
    value = re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", name.lower())).strip("-")
    if not value:
        raise ValueError("Project name has no Incus equivalent")
    return value


def alias_for(image):
    """incus-compose maps localhost/X:T to the project alias local/X:T."""
    match = LOCAL_IMAGE.fullmatch(image or "")
    if not match:
        raise ValueError("Only reviewed local Nixus image references can be imported")
    return "local/" + match.group(1) + ":" + match.group(2)


def _accounts(text):
    rows = []
    for line in text.splitlines():
        fields = line.split(":")
        if len(fields) >= 3 and fields[2].isdigit():
            rows.append(fields)
    return rows


def _identity(value, rows, kind):
    if value.isdigit():
        number = int(value)
    else:
        found = [int(r[2]) for r in rows if r[0] == value]
        if len(found) != 1:
            raise ValueError("Image " + kind + " is not a number and is not defined in the image")
        number = found[0]
    if number > 0xFFFFFFFE:
        raise ValueError("Image " + kind + " is out of range")
    return number


def _strings(value, label):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_ARGS or not all(isinstance(v, str) for v in value):
        raise ValueError("Image " + label + " must be a list of strings")
    return list(value)


def runtime_spec(config, passwd="", group=""):
    """The config.json incus-compose writes for built images, with user names
    resolved from the image instead of silently becoming root."""
    if not isinstance(config, dict):
        raise ValueError("Image config is malformed")
    args = _strings(config.get("Entrypoint"), "entrypoint") + _strings(config.get("Cmd"), "command")
    if not args:
        raise ValueError("Image defines no ENTRYPOINT or CMD to run")
    users, groups = _accounts(passwd), _accounts(group)
    user = config.get("User") or ""
    if not isinstance(user, str):
        raise ValueError("Image user is malformed")
    name, _, group_name = user.partition(":")
    uid = _identity(name, users, "user") if name else 0
    if group_name:
        gid = _identity(group_name, groups, "group")
    else:
        gid = next((int(r[3]) for r in users if int(r[2]) == uid and len(r) > 3 and r[3].isdigit()), 0)
    env = ["PATH=" + DEFAULT_PATH, "TERM=xterm"]
    for entry in _strings(config.get("Env"), "environment"):
        key, separator, _ = entry.partition("=")
        if not separator or not ENV_NAME.fullmatch(key):
            raise ValueError("Image environment entry is malformed")
        env = [e for e in env if not e.startswith(key + "=")] + [entry]
    if not any(e.startswith("HOME=") for e in env):
        home = next((r[5] for r in users if int(r[2]) == uid and len(r) > 5 and r[5]), None)
        if home:
            env.append("HOME=" + home)
    cwd = config.get("WorkingDir") or "/"
    if not isinstance(cwd, str) or not cwd.startswith("/"):
        raise ValueError("Image working directory must be absolute")
    spec = {"ociVersion": "1.2.0",
            "process": {"args": args, "env": env, "cwd": cwd, "user": {"uid": uid, "gid": gid}}}
    return json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()


def metadata_tar(image, architecture, created, config_json):
    """Deterministic metadata tarball: the same inputs give the same bytes."""
    arch = ARCHITECTURES.get(architecture)
    if arch is None:
        raise ValueError("Unsupported image architecture")
    if type(created) is not int or created < 0:
        raise ValueError("Image creation time is malformed")
    metadata = json.dumps({"architecture": arch, "creation_date": created,
                           "properties": {"description": image + " (built by Nixus)", "type": "oci"}},
                          sort_keys=True, separators=(",", ":")).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in (("metadata.yaml", metadata), ("config.json", config_json)):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.mtime = len(data), 0o644, created
            archive.addfile(entry, io.BytesIO(data))
    return buffer.getvalue()


def fingerprint(metadata_path, rootfs_path):
    digest = hashlib.sha256()
    for path in (metadata_path, rootfs_path):
        with open(path, "rb") as stream:
            for block in iter(lambda: stream.read(65536), b""):
                digest.update(block)
    return digest.hexdigest()


def _query(incus, path):
    try:
        return json.loads(incus("query", path))
    except ValueError:
        return None


def ensure_project(project, incus):
    """Use the Incus project incus-compose will use. Nixus owns it exclusively
    for Compose: it must hold its own images and carry both ownership markers."""
    if project in ("default", "lab"):
        raise ValueError("Compose apps never use the default or host-owned lab Incus project")
    current = _query(incus, "/1.0/projects/" + project)
    if current is None:
        incus("project", "create", project, "-c", "features.images=true",
              "-c", "features.profiles=true", "-c", OWNER_KEY + "=true",
              "-c", BACKEND_KEY + "=" + COMPOSE_BACKEND)
        return
    config = current.get("config") or {}
    if config.get(OWNER_KEY) != "true" or config.get(BACKEND_KEY) != COMPOSE_BACKEND:
        raise ValueError("The Incus project is not owned by Nixus for Compose; refusing to adopt it")
    if config.get("features.images") != "true":
        raise ValueError("The Incus project shares the default image store; refusing to import into it")


def import_image(project, alias, expected, metadata_path, rootfs_path, incus):
    """Import once, verify the fingerprint Incus computed, then bind the alias."""
    if not FINGERPRINT.fullmatch(expected or ""):
        raise ValueError("Expected image fingerprint is malformed")
    suffix = "?project=" + project
    if _query(incus, "/1.0/images/" + expected + suffix) is None:
        output = incus("image", "import", str(metadata_path), str(rootfs_path), "--project", project, timeout=1800)
        found = re.search(r"fingerprint: ([0-9a-f]{64})", output or "")
        if found and found.group(1) != expected:
            incus("image", "delete", found.group(1), "--project", project)
            raise ValueError("Incus computed a different image fingerprint; the import was removed")
        image = _query(incus, "/1.0/images/" + expected + suffix)
        if image is None:
            raise ValueError("Incus did not store the image under the expected fingerprint")
    image = _query(incus, "/1.0/images/" + expected + suffix) or {}
    if (image.get("properties") or {}).get("type") != "oci":
        raise ValueError("Imported image is not marked as an OCI image")
    current = _query(incus, "/1.0/images/aliases/" + alias + suffix)
    if current is None:
        incus("image", "alias", "create", alias, expected, "--project", project)
    elif current.get("target") != expected:
        raise ValueError("The image alias already points at different content; refusing to move it")
    return {"alias": alias, "fingerprint": expected, "incusProject": project}
