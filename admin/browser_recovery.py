"""Browser-bound portal account recovery, approved by local root (Cockpit/SSH/console).

1. The sign-in page starts a request. The browser holds a private cookie token;
   only a short, non-secret request ID is shown.
2. An administrator runs `sudo nixus-admin recovery approve <ID> [--user NAME]`
   from Cockpit's terminal, SSH or the physical console.
3. That same browser, within the TTL, chooses a new password once. The request
   is consumed before the new verifier is written, so a crash can never allow
   a second reset. Changing the verifier invalidates the account's sessions.

Nothing here returns or stores a password, and Incus/Linux credentials are untouched.
"""
import math
import re
import secrets
import time

import runtime as rt
from browser_bootstrap import TOKEN, digest, material, scope

FILE = 'recovery-requests.json'
TTL = 300
REQUEST_ID = re.compile(r'[0-9A-F]{4}-[0-9A-F]{4}')


def boot_id():
    import enrollment
    return enrollment.boot_id()


def request_id(token):
    value = material(token, 'recovery-id')[:8].upper()
    return value[:4] + '-' + value[4:]


def empty():
    return {'version': 1, 'boot': boot_id(), 'requests': {}, 'created': {}}


def load():
    now = time.monotonic()
    path = rt.STATE / FILE
    try:
        if path.is_symlink() or (path.exists() and path.stat().st_size > 65536):
            raise ValueError()
        value = rt.read_json(path, None) or empty()
        if (not isinstance(value, dict) or value.get('version') != 1 or not isinstance(value.get('boot'), str)
                or not isinstance(value.get('requests'), dict) or not isinstance(value.get('created'), dict)):
            raise ValueError()
        if value['boot'] != boot_id():
            return empty()  # Monotonic deadlines and approvals never survive a reboot.
        for key, item in list(value['requests'].items()):
            if (not re.fullmatch(r'[0-9a-f]{64}', key) or not isinstance(item, dict)
                    or not REQUEST_ID.fullmatch(item.get('id', ''))
                    or type(item.get('expires')) not in (int, float) or not math.isfinite(item['expires'])
                    or not re.fullmatch(r'[0-9a-f]{64}', item.get('csrfHash', ''))
                    or not isinstance(item.get('address'), str) or not isinstance(item.get('origin'), str)
                    or item.get('approved') not in (None,) and not isinstance(item.get('approved'), str)):
                raise ValueError()
            if now >= item['expires'] or item.get('consumed'):
                del value['requests'][key]
        for address, times in list(value['created'].items()):
            if not isinstance(times, list) or any(type(t) not in (int, float) for t in times):
                raise ValueError()
            value['created'][address] = [t for t in times if 0 <= now - t < 300]
            if not value['created'][address]:
                del value['created'][address]
        return value
    except (ValueError, OSError, TypeError):
        raise rt.PublicError('Recovery request state is unavailable; use sudo nixus-admin reset-password from a private terminal') from None


def save(value):
    rt.write_json(rt.STATE / FILE, value)


def require_accounts():
    import accounts
    users = accounts.list_users()
    if not users:
        raise rt.PublicError('No portal account exists yet; use first-administrator enrollment')
    return users


def checked(value, token, csrf, address, origin):
    scope(address, origin)
    if not isinstance(token, str) or not TOKEN.fullmatch(token) or not isinstance(csrf, str):
        raise rt.PublicError('Recovery request expired or invalid; start again from the sign-in page')
    record = value['requests'].get(digest(token))
    if (not record or record['address'] != address or record['origin'] != origin
            or not secrets.compare_digest(record['csrfHash'], digest(csrf))):
        raise rt.PublicError('Recovery request expired or invalid; start again from the sign-in page')
    return record


def start(token, address, origin):
    scope(address, origin)
    with rt.locked(blocking=False):
        require_accounts()
        value = load()
        key = digest(token) if isinstance(token, str) and TOKEN.fullmatch(token) else None
        record = value['requests'].get(key)
        if record and (record['address'] != address or record['origin'] != origin):
            raise rt.PublicError('Recovery browser scope changed; start again on the management address')
        if not record:
            times = value['created'].setdefault(address, [])
            if len(times) >= 5 or len(value['requests']) >= 32:
                raise rt.PublicError('Too many recovery requests; wait five minutes before retrying')
            times.append(time.monotonic())
            token = secrets.token_urlsafe(32)
            key = digest(token)
            record = {'id': request_id(token), 'address': address, 'origin': origin,
                      'expires': time.monotonic() + TTL,
                      'csrfHash': digest(material(token, 'recovery-csrf')), 'approved': None}
            value['requests'][key] = record
        save(value)
        # token is a PRIVATE broker-to-frontend cookie field, stripped before JSON.
        return {'token': token, 'csrf': material(token, 'recovery-csrf'), 'requestId': record['id'],
                'approved': record['approved'] is not None, 'username': record['approved'],
                'expiresIn': max(0, int(record['expires'] - time.monotonic()))}


def approve(identifier, username=None):
    """Local root only (CLI). Binds the request to one existing account."""
    import accounts
    if not accounts.local_root():
        raise accounts.AuthorizationError('Local root approval is required')
    if not isinstance(identifier, str) or not REQUEST_ID.fullmatch(identifier.strip().upper()):
        raise rt.PublicError('Use the request ID shown in the browser, for example ABCD-1234')
    identifier = identifier.strip().upper()
    with rt.locked(blocking=False):
        users = [u['username'] for u in require_accounts()]
        if username is None:
            if len(users) != 1:
                raise rt.PublicError('Several portal accounts exist; choose one with --user NAME')
            username = users[0]
        if username not in users:
            raise rt.PublicError('Unknown portal account')
        value = load()
        matches = [r for r in value['requests'].values() if secrets.compare_digest(r['id'], identifier)]
        if len(matches) != 1:
            raise rt.PublicError('No pending recovery request has that ID; it may have expired')
        record = matches[0]
        if record['approved'] is not None:
            raise rt.PublicError('That recovery request is already approved')
        record['approved'] = username
        save(value)
    rt.audit('portal-recovery-approved', username=username)
    return {'approved': True}


def complete(token, csrf, address, origin, password):
    import accounts
    with rt.locked(blocking=False):
        value = load()
        record = checked(value, token, csrf, address, origin)
        username = record['approved']
        if username is None:
            raise rt.PublicError('Approve this request from the host first with the command shown on this page')
        if accounts.record(username) is None:
            raise rt.PublicError('The approved account no longer exists; start again')
        if not isinstance(password, str) or not 16 <= len(password) <= 256:
            raise rt.PublicError('Administrator passwords must contain 16–256 characters')
        # Consume first: a crash after this point can never permit a second reset.
        record['consumed'] = True
        save(value)
    accounts.change_password(username, password)
    with rt.locked(blocking=False):
        value = load()
        value['requests'] = {k: r for k, r in value['requests'].items() if r.get('approved') != username}
        save(value)
    rt.audit('portal-recovery-completed', username=username)
    return {'ok': True, 'username': username}
