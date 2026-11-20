"""Inspect untrusted Buildah OCI archives before any trusted Incus import.

An output archive is *not* an executable capability. The trusted broker checks
all archive member kinds, OCI content-addressed manifests and exact bytes.
The flattened rootfs the sandbox exports beside it is checked the same way
before oci_images.py turns the pair into a fingerprint-verified Incus image.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tarfile

HEX = re.compile(r"^[0-9a-f]{64}$")
MAX_IMAGE_BYTES = 1024 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_JSON = 1024 * 1024


def _bounded_json(data):
    if not isinstance(data, bytes) or len(data) > MAX_JSON:
        raise ValueError("Untrusted OCI manifest is oversized")
    result = json.loads(data)
    if not isinstance(result, dict):
        raise ValueError("Untrusted OCI manifest is not an object")
    return result


def _ref(obj):
    if (not isinstance(obj, dict) or obj.get("mediaType") not in (
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.oci.image.config.v1+json",
            "application/vnd.oci.image.layer.v1.tar+gzip",
            "application/vnd.oci.image.layer.v1.tar",
            "application/vnd.oci.image.layer.v1.tar+zstd")
            or not isinstance(obj.get("digest"), str)
            or not obj["digest"].startswith("sha256:")
            or not HEX.fullmatch(obj["digest"][7:])
            or type(obj.get("size")) is not int or obj["size"] < 0):
        raise ValueError("OCI image reference is malformed or unsupported")
    return obj["digest"][7:]


def verify_archive(path, expected_sha256, expected_bytes):
    """Check a single OCI tar and its reachable digest graph; no extraction."""
    path = Path(path)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_size != expected_bytes
            or not 0 < info.st_size <= MAX_IMAGE_BYTES
            or not isinstance(expected_sha256, str) or not HEX.fullmatch(expected_sha256)):
        raise ValueError("Untrusted OCI artifact metadata")
    checksum, counted = hashlib.sha256(), 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            counted += len(block)
            if counted > MAX_IMAGE_BYTES:
                raise ValueError("OCI artifact exceeds budget")
            checksum.update(block)
    if counted != expected_bytes or checksum.hexdigest() != expected_sha256:
        raise ValueError("OCI artifact hash differs from reviewed builder output")

    blobs, small, visited = {}, {}, set()
    with tarfile.open(path, mode="r:") as archive:
        for entry in archive:
            if len(visited) >= MAX_ENTRIES:
                raise ValueError("OCI archive contains excessive members")
            name = entry.name.removeprefix("./")
            if name in visited:
                raise ValueError("Duplicate OCI archive entry")
            visited.add(name)
            if entry.isdir():
                if name.rstrip("/") not in {"blobs", "blobs/sha256"}:
                    raise ValueError("Unexpected OCI directory metadata")
                continue
            if not entry.isfile():
                raise ValueError("OCI archive contains symbolic/hard links or special files")
            if name not in ("oci-layout", "index.json") and not (
                    name.startswith("blobs/sha256/") and
                    HEX.fullmatch(name[len("blobs/sha256/"):])):
                raise ValueError("Unexpected OCI archive path or member type")
            if entry.size < 0 or entry.size > MAX_IMAGE_BYTES:
                raise ValueError("OCI archive member exceeds budget")
            stream = archive.extractfile(entry)
            if stream is None:
                raise ValueError("OCI archive cannot be read")
            hash_value = hashlib.sha256()
            data = bytearray() if entry.size <= MAX_JSON else None
            actual = 0
            while True:
                block = stream.read(65536)
                if not block:
                    break
                actual += len(block)
                if actual > entry.size:
                    raise ValueError("OCI member size differs from header")
                hash_value.update(block)
                if data is not None:
                    data.extend(block)
            if actual != entry.size:
                raise ValueError("OCI archive member is truncated")
            if name.startswith("blobs/sha256/"):
                ident = name[len("blobs/sha256/"):]
                if ident != hash_value.hexdigest():
                    raise ValueError("OCI blob content digest does not match path")
                blobs[ident] = entry.size
            elif data is not None:
                small[name] = bytes(data)
            else:
                raise ValueError("OCI metadata exceeds size limit")
    if set(small) != {"oci-layout", "index.json"}:
        raise ValueError("OCI archive lacks required descriptors")
    if _bounded_json(small["oci-layout"]) != {"imageLayoutVersion": "1.0.0"}:
        raise ValueError("Unsupported OCI image archive layout")
    index = _bounded_json(small["index.json"])
    if (index.get("schemaVersion") != 2 or
            not isinstance(index.get("manifests"), list) or len(index["manifests"]) != 1):
        raise ValueError("Only a single-image OCI manifest is supported")
    manifest_id = _ref(index["manifests"][0])
    if manifest_id not in blobs or blobs[manifest_id] != index["manifests"][0]["size"]:
        raise ValueError("OCI top-level manifest blob is missing")
    # Reopen only the bounded manifest and config blobs for graph validation.
    wanted = {manifest_id}
    content = {}
    with tarfile.open(path, mode="r:") as archive:
        for entry in archive:
            name = entry.name.removeprefix("./")
            if name in {"blobs/sha256/" + x for x in wanted}:
                if entry.size > MAX_JSON:
                    raise ValueError("OCI manifest is oversized")
                stream = archive.extractfile(entry)
                content[name.split("/")[-1]] = stream.read(MAX_JSON + 1)
    manifest = _bounded_json(content[manifest_id])
    if (manifest.get("schemaVersion") != 2 or
            not isinstance(manifest.get("layers"), list)
            or len(manifest["layers"]) > 128):
        raise ValueError("Unsupported OCI image manifest")
    refs = [manifest.get("config"), *manifest["layers"]]
    for item in refs:
        ident = _ref(item)
        if blobs.get(ident) != item["size"]:
            raise ValueError("OCI image config or layer missing from archive")
    config_id = _ref(manifest["config"])
    with tarfile.open(path, mode="r:") as archive:
        member = next(e for e in archive if e.name.removeprefix("./") == "blobs/sha256/" + config_id)
        if member.size > MAX_JSON:
            raise ValueError("OCI image config is oversized")
        image = _bounded_json(archive.extractfile(member).read(MAX_JSON + 1))
    if not isinstance(image.get("config", {}), dict) or not isinstance(image.get("architecture"), str):
        raise ValueError("OCI image config is malformed")
    return {"sha256": checksum.hexdigest(), "bytes": counted,
            "ociManifestDigest": manifest_id, "blobs": len(blobs),
            "architecture": image["architecture"], "config": image.get("config") or {}}


MAX_ROOTFS_ENTRIES = 262144
MAX_ACCOUNT_FILE = 65536


def _member_name(name):
    if name in (".", "./"):
        return "."
    if not name.startswith("./"):
        raise ValueError("Rootfs member is not relative to the image root")
    parts = name[2:].rstrip("/").split("/")
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise ValueError("Rootfs member path escapes or is not normalized")
    return "/".join(parts)


def verify_rootfs(path, expected_sha256, expected_bytes):
    """Check the sandbox's flattened rootfs tar; nothing is extracted here.

    Allowed: directories, regular files, symlinks and hard links to earlier
    members. Device nodes, FIFOs, sockets and path escapes are refused.
    Returns the hash plus /etc/passwd and /etc/group for user resolution.
    """
    path = Path(path)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_size != expected_bytes
            or not 0 < info.st_size <= MAX_IMAGE_BYTES
            or not isinstance(expected_sha256, str) or not HEX.fullmatch(expected_sha256)):
        raise ValueError("Untrusted rootfs artifact metadata")
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            checksum.update(block)
    if checksum.hexdigest() != expected_sha256:
        raise ValueError("Rootfs hash differs from builder output")
    seen, accounts = set(), {}
    with tarfile.open(path, mode="r:") as archive:
        for count, entry in enumerate(archive):
            if count >= MAX_ROOTFS_ENTRIES:
                raise ValueError("Rootfs contains excessive members")
            name = _member_name(entry.name)
            if name in seen and not entry.isdir():
                raise ValueError("Duplicate rootfs member")
            if entry.islnk():
                if _member_name("./" + entry.linkname.removeprefix("./")) not in seen:
                    raise ValueError("Rootfs hard link target is outside the archive")
            elif not (entry.isdir() or entry.isreg() or entry.issym()):
                raise ValueError("Rootfs contains device nodes, FIFOs or other special files")
            if entry.mode & 0o6000 and entry.uid != 0:
                raise ValueError("Rootfs contains set-ID files owned by an unprivileged user")
            seen.add(name)
            if name in ("etc/passwd", "etc/group") and entry.isreg():
                if entry.size > MAX_ACCOUNT_FILE:
                    raise ValueError("Rootfs account database is oversized")
                accounts[name] = archive.extractfile(entry).read().decode("utf-8", "replace")
    return {"sha256": expected_sha256, "bytes": expected_bytes,
            "passwd": accounts.get("etc/passwd", ""), "group": accounts.get("etc/group", "")}
