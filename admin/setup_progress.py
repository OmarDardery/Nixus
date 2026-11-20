"""First-run setup checklist derived from live host state.

Nothing here is stored by the browser: every item is recomputed from root-owned
state, so the walkthrough resumes after a refresh, disconnect or reboot.
Results contain booleans and page names only, never paths, keys or secrets.
"""
import hashlib
from pathlib import Path
import time

import runtime as rt

MARKER = 'recovery-kit.json'

# id, title, detail, page
ITEMS = (
    ('administrator', 'Create your administrator account',
     'Approved from the host console and claimed in this browser.', 'accounts'),
    ('activation', 'Activate the hypervisor',
     'Review and confirm the first configuration: Incus, Cockpit and this console.', 'review'),
    ('incusBrowser', 'Enroll this browser for the Incus web UI',
     'Issue a browser certificate, import it, then open Incus.', 'security'),
    ('cockpitPassword', 'Set the Cockpit operator password',
     'Choose the Linux operator password used for Cockpit and SSH.', 'integrations'),
    ('secretsKey', 'Create the secrets encryption key',
     'Generate the host age identity used for SOPS-encrypted secrets.', 'projects'),
    ('recoveryKit', 'Save the encrypted recovery kit',
     'Download the passphrase-protected kit and store it off this host.', 'projects'),
    ('sshKey', 'Enroll an SSH key (optional)',
     'Add your laptop public key for key-based remote administration.', 'security'),
    ('backup', 'Configure off-host backups (optional)',
     'Choose a restic repository and schedule, then test a restore.', 'operations'),
)
OPTIONAL = {'sshKey', 'backup'}


def identity_digest(path):
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def record_recovery_kit(identity_path, now=None):
    """Called after a successful kit export; stores no key material."""
    digest = identity_digest(identity_path)
    if digest is None:
        return False
    try:
        rt.write_json(rt.STATE / MARKER, {'version': 1, 'identity': digest,
                                           'exportedAt': int(time.time() if now is None else now)})
    except OSError:
        # Advisory walkthrough state only: never fail the kit export over it.
        return False
    return True


def browser_enrolled(state):
    import browser_certificates
    try:
        records = browser_certificates.registry(state)['certificates'].values()
    except ValueError:
        return False
    return any(record['status'] == 'active' for record in records)


def cockpit_password_set(settings):
    if settings.get('secrets', {}).get('enable'):
        import host_secrets
        return host_secrets.operator_password_set(rt.ROOT)
    return rt.SECRET_PATHS['cockpitPassword'].exists()


def progress(status, *, state=None, identity=None, account_valid=None):
    state = Path(state or rt.STATE)
    if identity is None:
        import native_secrets
        identity = native_secrets.IDENTITY_FILE
    if account_valid is None:
        import enrollment
        account_valid = enrollment.account_valid
    settings = status.get('effectiveSettings') or status.get('settings') or {}
    cockpit = settings.get('cockpit', {})
    key = identity_digest(identity)
    marker = rt.read_json(state / MARKER, {}) if (state / MARKER).is_file() else {}
    done = {
        'administrator': bool(account_valid()),
        'activation': bool(status.get('setupComplete') and status.get('lastConfirmed')),
        'incusBrowser': browser_enrolled(state),
        'cockpitPassword': cockpit_password_set(settings),
        'secretsKey': key is not None,
        'recoveryKit': key is not None and marker.get('identity') == key,
        'sshKey': bool(settings.get('adminKeys')),
        'backup': bool(settings.get('backup', {}).get('enable')),
    }
    applicable = {name for name, *_ in ITEMS}
    if not (cockpit.get('enable') and cockpit.get('managePassword')):
        applicable.discard('cockpitPassword')
    items = [{'id': name, 'title': title, 'detail': detail, 'page': page,
              'required': name not in OPTIONAL, 'done': done[name]}
             for name, title, detail, page in ITEMS if name in applicable]
    required = [item for item in items if item['required']]
    return {'version': 1, 'items': items,
            'completed': sum(item['done'] for item in required), 'total': len(required),
            'complete': all(item['done'] for item in required)}
