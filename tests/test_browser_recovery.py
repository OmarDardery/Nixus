"""Browser-bound, root-approved portal account recovery (#28)."""
import json
import os
import types
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(BASE / 'admin'), str(BASE / 'scripts')]
import accounts
import browser_recovery as recovery
import runtime as rt

from credential_fixtures import SECRETS

ADDRESS, ORIGIN = '192.0.2.40', 'https://192.0.2.10:9440'
OLD, NEW = 'old-portal-password-fixture-1', 'new-portal-password-fixture-2'


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.clock = [1000.0]
        for item in (patch.object(rt, 'STATE', self.state), patch.object(rt, 'audit'),
                     patch('enrollment.boot_id', return_value='boot-a'),
                     patch.object(recovery.time, 'monotonic', side_effect=lambda: self.clock[0]),
                     patch.object(accounts, 'local_root', return_value=True),
                     patch.object(rt.grp, 'getgrnam', return_value=types.SimpleNamespace(gr_gid=os.getgid()))):
            item.start(); self.addCleanup(item.stop)
        rt.write_json(self.state / 'auth.json', rt.password_record(OLD))

    def begin(self, token=None, address=ADDRESS, origin=ORIGIN):
        return recovery.start(token, address, origin)

    def complete(self, request, password=NEW, address=ADDRESS, origin=ORIGIN):
        return recovery.complete(request['token'], request['csrf'], address, origin, password)

    def test_request_root_approval_exact_browser_resets_once(self):
        request = self.begin()
        self.assertRegex(request['requestId'], r'^[0-9A-F]{4}-[0-9A-F]{4}$')
        self.assertFalse(request['approved'])
        with self.assertRaisesRegex(ValueError, 'Approve this request'):
            self.complete(request)
        self.assertEqual(recovery.approve(request['requestId'].lower()), {'approved': True})
        self.assertTrue(self.begin(request['token'])['approved'])
        self.assertEqual(self.complete(request), {'ok': True, 'username': 'admin'})
        self.assertTrue(accounts.matches('admin', NEW))
        self.assertFalse(accounts.matches('admin', OLD))  # Old sessions fail their fingerprint check.
        with self.assertRaises(ValueError):
            self.complete(request, 'another-new-password-fixture-3')

    def test_wrong_browser_scope_or_csrf_cannot_use_an_approval(self):
        request = self.begin()
        recovery.approve(request['requestId'])
        other = self.begin()
        for call in (lambda: recovery.complete(other['token'], other['csrf'], ADDRESS, ORIGIN, NEW),
                     lambda: recovery.complete(request['token'], other['csrf'], ADDRESS, ORIGIN, NEW),
                     lambda: self.complete(request, address='192.0.2.99'),
                     lambda: self.complete(request, origin='https://evil.invalid'),
                     lambda: recovery.complete('x' * 43, request['csrf'], ADDRESS, ORIGIN, NEW)):
            with self.subTest(call=call), self.assertRaises(ValueError):
                call()
        self.assertTrue(accounts.matches('admin', OLD))

    def test_non_root_unknown_expired_repeated_and_wrong_account_approvals_fail(self):
        request = self.begin()
        with patch.object(accounts, 'local_root', return_value=False), self.assertRaises(PermissionError):
            recovery.approve(request['requestId'])
        for bad in ('0000-0000', 'not-an-id', ''):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                recovery.approve(bad)
        with self.assertRaisesRegex(ValueError, 'Unknown portal account'):
            recovery.approve(request['requestId'], 'nobody')
        recovery.approve(request['requestId'])
        with self.assertRaisesRegex(ValueError, 'already approved'):
            recovery.approve(request['requestId'])
        late = self.begin()
        self.clock[0] += recovery.TTL + 1
        with self.assertRaises(ValueError):
            recovery.approve(late['requestId'])
        with self.assertRaises(ValueError):
            self.complete(request)

    def test_several_accounts_require_an_explicit_target(self):
        accounts.update('owner', 'admin', 'owner-portal-password-fixture')
        request = self.begin()
        with self.assertRaisesRegex(ValueError, '--user'):
            recovery.approve(request['requestId'])
        recovery.approve(request['requestId'], 'owner')
        self.assertEqual(self.complete(request)['username'], 'owner')
        self.assertTrue(accounts.matches('owner', NEW))
        self.assertTrue(accounts.matches('admin', OLD))

    def test_crash_after_consumption_never_allows_a_second_reset(self):
        request = self.begin()
        recovery.approve(request['requestId'])
        with patch.object(accounts, 'change_password', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.complete(request)
        with self.assertRaises(ValueError):
            self.complete(request)
        self.assertTrue(accounts.matches('admin', OLD))

    def test_reboot_discards_pending_approvals(self):
        request = self.begin()
        recovery.approve(request['requestId'])
        with patch('enrollment.boot_id', return_value='boot-b'), self.assertRaises(ValueError):
            self.complete(request)

    def test_weak_password_does_not_consume_the_approval(self):
        request = self.begin()
        recovery.approve(request['requestId'])
        with self.assertRaisesRegex(ValueError, '16'):
            self.complete(request, 'short')
        self.assertEqual(self.complete(request)['username'], 'admin')

    def test_rate_limit_and_no_account_refusal(self):
        for _ in range(5):
            self.begin()
        with self.assertRaisesRegex(ValueError, 'Too many'):
            self.begin()
        (self.state / 'auth.json').unlink()
        with self.assertRaisesRegex(ValueError, 'enrollment'):
            self.begin(address='192.0.2.41')

    def test_state_and_results_contain_no_passwords_or_tokens(self):
        request = self.begin()
        recovery.approve(request['requestId'])
        result = self.complete(request)
        stored = (self.state / recovery.FILE).read_text() if (self.state / recovery.FILE).exists() else ''
        public = json.dumps({k: v for k, v in request.items() if k != 'token'}) + json.dumps(result) + stored
        for secret in (NEW, OLD, request['token'], *SECRETS.values()):
            self.assertNotIn(secret, public)


if __name__ == '__main__':
    unittest.main()
