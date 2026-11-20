"""Inspect local login readiness without exposing shadow hashes in output."""
import grp
import pwd
import subprocess

import runtime as rt


def operator_unset_marker():
    return rt.STATE / 'operator-password-unset'


def shadow(username):
    result = subprocess.run(['getent', 'shadow', username], capture_output=True, text=True, timeout=10)
    if result.returncode:
        return None
    fields = result.stdout.strip().split(':')
    return fields[1] if len(fields) == 9 and fields[0] == username else None


def cockpit_accounts():
    try:
        wheel = grp.getgrnam('wheel')
    except KeyError:
        return []
    accounts = []
    for account in pwd.getpwall():
        if account.pw_uid == 0 or account.pw_shell.endswith(('/nologin', '/false')):
            continue
        if account.pw_name not in wheel.gr_mem and account.pw_gid != wheel.gr_gid:
            continue
        encoded = shadow(account.pw_name)
        if encoded and not encoded.startswith(('!', '*')):
            accounts.append(account.pw_name)
    return accounts


def ensure_operator_password():
    """Lock the managed operator account until the administrator sets a password.

    Writes the hash of a random password that is discarded immediately; no
    plaintext is stored. The Web UI replaces it and clears the unset marker.
    """
    encoded = rt.SECRET_PATHS['cockpitPassword']
    rt.durable_unlink(rt.STATE / 'operator-password')  # Retire any legacy plaintext.
    if not encoded.exists():
        import host_secrets
        rt.atomic(encoded, host_secrets.locked_password_hash())
        rt.atomic(operator_unset_marker(), '1\n')