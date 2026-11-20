"""First run on real NixOS: console-approved browser claim, setup progress, host SOPS.

Usage: first-run-client.py claim|after-reboot. Credentials are disposable.
"""
import json
import os
from pathlib import Path
import pty
import select
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ORIGIN = 'https://127.0.0.1:9440'
CONTEXT = ssl.create_default_context(cafile='/var/lib/nixus-admin/ca.crt')
USER, PASSWORD = 'firstadmin', 'first-run-vm-portal-password-1!'
STATE = Path('/var/lib/nixus-admin')


def request(path, body=None, cookie=None, csrf=None):
    headers = {'Origin': ORIGIN}
    if cookie: headers['Cookie'] = cookie
    if csrf: headers['X-Nixus-CSRF'] = csrf
    if body is not None: headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(ORIGIN + path, data=json.dumps(body).encode() if body is not None else None, headers=headers)
    try:
        response = urllib.request.urlopen(req, context=CONTEXT, timeout=60)
    except urllib.error.HTTPError as exc:
        response = exc
    return response.status, json.loads(response.read() or b'{}'), response.headers


def approve_from_console(code):
    """Drive `sudo nixus-admin approve-enrollment` through a real terminal."""
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp('nixus-admin', ['nixus-admin', 'approve-enrollment'])
    output, sent, deadline = b'', False, time.monotonic() + 60
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.2)
        if not ready: continue
        try: data = os.read(fd, 4096)
        except OSError: break
        if not data: break
        output += data
        if not sent and b'Code displayed in your browser' in output:
            os.write(fd, code.encode() + b'\n'); sent = True
    _, status = os.waitpid(pid, 0)
    assert os.WEXITSTATUS(status) == 0 and b'Browser approved' in output, output
    assert code.encode() not in output.split(b'browser:', 1)[-1], 'Approval code echoed'


def progress(cookie, csrf):
    status, result, _ = request('/api/setup-progress', cookie=cookie, csrf=csrf)
    assert status == 200, result
    text = json.dumps(result)
    for forbidden in (PASSWORD, '/var/lib', 'AGE-SECRET-KEY'):
        assert forbidden not in text, forbidden
    return {item['id']: item['done'] for item in result['items']}, result


def login():
    status, result, headers = request('/api/login', {'username': USER, 'password': PASSWORD})
    assert status == 200, result
    return headers['Set-Cookie'].split(';')[0], result['csrf']


def claim():
    # The installer opened enrollment and generated no portal password.
    assert not (STATE / 'setup-password').exists()
    assert not (STATE / 'auth.json').exists() and not (STATE / 'users.json').exists()
    status, start, headers = request('/api/bootstrap')
    assert status == 200 and len(start['approvalCode']) == 32, start
    bootstrap = headers['Set-Cookie'].split(';')[0]
    # Before console approval the claim is refused.
    status, refused, _ = request('/api/bootstrap/claim', {'username': USER, 'password': PASSWORD}, bootstrap, start['csrf'])
    assert status != 200, refused
    approve_from_console(start['approvalCode'])
    status, claimed, headers = request('/api/bootstrap/claim', {'username': USER, 'password': PASSWORD}, bootstrap, start['csrf'])
    assert status == 200 and claimed['role'] == 'admin', claimed
    assert not (STATE / 'web-enrollment').exists(), 'Enrollment capability must retire after the claim'
    cookie = [c.split(';')[0] for c in headers.get_all('Set-Cookie') if c.startswith('nixus_session=')][0]
    done, result = progress(cookie, claimed['csrf'])
    assert done['administrator'] and not done['activation'] and not done['secretsKey'], done
    assert not result['complete'] and result['completed'] == 1, result
    # A second browser cannot claim again.
    status, again, _ = request('/api/bootstrap')
    assert status != 200 or not again.get('approvalCode'), again


def host_secrets_roundtrip():
    """The SOPS/age path used by the installer and review, on the real NixOS tools."""
    sys.path[:0] = ['/etc/nixus-test-admin', '/etc/nixus-test-scripts']
    import host_secrets
    with tempfile.TemporaryDirectory() as folder:
        key, root = Path(folder) / 'sops-nix/key.txt', Path(folder) / 'source'
        host_secrets.ensure_identity(key)
        host_secrets.initialize(root, key)
        assert not host_secrets.operator_password_set(root)
        host_secrets.write(root, {'resticPassword': 'vm-restic-sentinel'}, key)
        assert 'vm-restic-sentinel' not in host_secrets.path(root).read_text()
        env = dict(os.environ, SOPS_AGE_KEY_FILE=str(key))
        plain = json.loads(subprocess.run(['sops', 'decrypt', '--output-type', 'json', str(host_secrets.path(root))],
                                          capture_output=True, check=True, env=env).stdout)
        assert plain['restic-password'] == 'vm-restic-sentinel'


def after_reboot():
    cookie, csrf = login()
    done, _ = progress(cookie, csrf)
    assert done['administrator'] and not done['activation'], done
    assert not (STATE / 'web-enrollment').exists()


def recover():
    """Forgotten password: browser-bound request, real root CLI approval (#28)."""
    new = 'first-run-vm-recovered-password-2!'
    status, start, headers = request('/api/recovery')
    assert status == 200 and not start['approved'], start
    cookie = headers['Set-Cookie'].split(';')[0]
    # Another browser cannot finish this request, approved or not.
    _, other, other_headers = request('/api/recovery')
    other_cookie = other_headers['Set-Cookie'].split(';')[0]
    approval = subprocess.run(['nixus-admin', 'recovery', 'approve', start['requestId'], '--user', USER],
                              capture_output=True, text=True, timeout=60)
    assert approval.returncode == 0 and 'Approved' in approval.stdout, approval
    assert new not in approval.stdout + approval.stderr
    status, _, _ = request('/api/recovery/complete', {'password': new}, other_cookie, other['csrf'])
    assert status != 200
    status, done, _ = request('/api/recovery/complete', {'password': new}, cookie, start['csrf'])
    assert status == 200 and done['username'] == USER, done
    status, again, _ = request('/api/recovery/complete', {'password': new + 'x'}, cookie, start['csrf'])
    assert status != 200, 'A consumed recovery request was reused'
    assert request('/api/login', {'username': USER, 'password': PASSWORD})[0] != 200
    assert request('/api/login', {'username': USER, 'password': new})[0] == 200
    for path in STATE.rglob('*'):
        if path.is_file():
            assert new.encode() not in path.read_bytes(), path


if __name__ == '__main__':
    {'claim': lambda: (claim(), host_secrets_roundtrip()), 'after-reboot': after_reboot,
     'recover': recover}[sys.argv[1]]()
    print('first-run ' + sys.argv[1] + ' passed', flush=True)
