"""Host credentials as SOPS/age ciphertext inside the reviewed machine source.

The installer creates the host age identity once. Web UI changes are encrypted
into ``machine/secrets/host.yaml`` of the job's staged source, so review, rollback
and recovery treat ciphertext like any other reviewed file. sops-nix decrypts it
at activation. Plaintext moves only through pipes, never through files, return
values or logs.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

import runtime as rt

KEY_FILE = Path('/var/lib/sops-nix/key.txt')
RELATIVE = 'machine/secrets/host.yaml'
# Web UI field -> sops-nix secret name (see modules/secrets.nix).
NAMES = {'cockpitPassword': 'cockpit-operator-password', 'wifiPassword': 'wifi-env',
         'resticPassword': 'restic-password', 'resticEnvironment': 'restic-environment',
         'tunnelCredentials': 'cloudflared'}
RECIPIENT = re.compile(r'age1[02-9ac-hj-np-z]{58}')
TOP_KEY = re.compile(r'^([A-Za-z0-9][A-Za-z0-9_-]{0,63}):')
PLACEHOLDER = 'nixus-host-secrets'
UNSET = 'cockpit-operator-password-unset'


def _run(args, data=None, key_file=None):
    env = dict(os.environ)
    if key_file is not None:
        env['SOPS_AGE_KEY_FILE'] = str(key_file)
    try:
        return subprocess.run(args, input=data, capture_output=True, check=True, timeout=60, env=env).stdout
    except (OSError, subprocess.SubprocessError):
        # Never echo tool output: it can contain plaintext or key material.
        raise ValueError('SOPS or age operation failed') from None


def path(root):
    return Path(root) / RELATIVE


def ensure_identity(key_file=KEY_FILE):
    """Create the host age identity once (0600 root). Never overwrites."""
    key_file = Path(key_file)
    if key_file.is_symlink():
        raise ValueError('Host age identity must be a regular file')
    if not key_file.exists():
        key_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(key_file.parent, 0o700)
        with tempfile.TemporaryDirectory(dir=key_file.parent) as temporary:
            candidate = Path(temporary) / 'key.txt'
            _run(['age-keygen', '-o', str(candidate)])
            os.chmod(candidate, 0o600)
            try:
                os.link(candidate, key_file)  # Fails if another installer won the race.
            except FileExistsError:
                pass
    return recipient(key_file)


def recipient(key_file=KEY_FILE):
    value = _run(['age-keygen', '-y', str(key_file)]).decode('ascii', 'replace').strip()
    if not RECIPIENT.fullmatch(value):
        raise ValueError('Invalid host age identity')
    return value


def names(file):
    """Top-level secret names, readable without decryption."""
    file = Path(file)
    if not file.is_file():
        return set()
    return {m.group(1) for line in file.read_text().splitlines()
            if (m := TOP_KEY.match(line)) and m.group(1) != 'sops'}


def present(root, field):
    return NAMES[field] in names(path(root))


def _decrypt(file, key_file):
    return json.loads(_run(['sops', 'decrypt', '--output-type', 'json', str(file)], key_file=key_file))


def _encrypt(values, target, key_file):
    data = json.dumps(values, sort_keys=True).encode()
    out = _run(['sops', 'encrypt', '--input-type', 'json', '--output-type', 'yaml',
                '--age', recipient(key_file), '--filename-override', 'host.yaml', '/dev/stdin'], data)
    target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    rt.atomic(target, out, mode=0o644)  # Ciphertext; readable like other source.


def locked_password_hash():
    """SHA-512 crypt of a random password that is discarded immediately."""
    import secrets
    value = _run(['openssl', 'passwd', '-6', '-stdin'], (secrets.token_urlsafe(32) + '\n').encode())
    value = value.decode('ascii').strip()
    if not value.startswith('$6$'):
        raise ValueError('Could not create a locked operator password')
    return value + '\n'


def initialize(root, key_file=KEY_FILE):
    """Create the encrypted file sops-nix reads on first activation.

    The managed operator account starts with an unusable password until the
    administrator chooses one in the Web UI, which also clears ``UNSET``.
    """
    target = path(root)
    if not target.is_file():
        _encrypt({PLACEHOLDER: 'initialized', NAMES['cockpitPassword']: locked_password_hash(),
                  UNSET: 'true'}, target, key_file)
    return target


def operator_password_set(root):
    found = names(path(root))
    return NAMES['cockpitPassword'] in found and UNSET not in found


def write(root, values, key_file=KEY_FILE):
    """Merge encoded Web UI values into the staged source's ciphertext."""
    if not isinstance(values, dict) or set(values) - set(NAMES):
        raise ValueError('Unknown host secret field')
    if any(not isinstance(value, str) for value in values.values()):
        raise ValueError('Invalid host secret value')
    target = path(root)
    current = _decrypt(target, key_file) if target.is_file() else {PLACEHOLDER: 'initialized'}
    current.pop('sops', None)
    current.update({NAMES[field]: value for field, value in values.items()})
    if 'cockpitPassword' in values:
        current.pop(UNSET, None)
    _encrypt(current, target, key_file)
    return sorted(values)
