"""The managed operator account starts locked; no plaintext password is ever stored."""
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(BASE / 'admin'), str(BASE / 'scripts')]
import local_access
import runtime as rt
import setup_progress


@unittest.skipUnless(shutil.which('openssl'), 'requires openssl')
class OperatorLockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / 'state'; self.state.mkdir()
        self.encoded = Path(self.temp.name) / 'cockpit-operator-password'
        for item in (patch.object(rt, 'STATE', self.state),
                     patch.dict(rt.SECRET_PATHS, cockpitPassword=self.encoded)):
            item.start(); self.addCleanup(item.stop)

    def test_locked_hash_without_plaintext_and_legacy_plaintext_retired(self):
        (self.state / 'operator-password').write_text('legacy-plaintext-sentinel\n')
        local_access.ensure_operator_password()
        self.assertTrue(self.encoded.read_text().startswith('$6$'))
        self.assertFalse((self.state / 'operator-password').exists())
        self.assertTrue(local_access.operator_unset_marker().exists())
        stored = b''.join(p.read_bytes() for p in Path(self.temp.name).rglob('*') if p.is_file())
        self.assertNotIn(b'legacy-plaintext-sentinel', stored)
        # Idempotent: an existing hash (locked or chosen) is never replaced.
        before = self.encoded.read_bytes()
        local_access.ensure_operator_password()
        self.assertEqual(self.encoded.read_bytes(), before)

    def test_setup_step_is_done_only_after_a_chosen_password(self):
        settings = {'secrets': {'enable': False}}
        local_access.ensure_operator_password()
        self.assertFalse(setup_progress.cockpit_password_set(settings))
        local_access.operator_unset_marker().unlink()  # What applying a portal password does.
        self.assertTrue(setup_progress.cockpit_password_set(settings))


class RecoveryKitNamesTests(unittest.TestCase):
    def test_retired_plaintext_names_are_not_archived(self):
        source = (BASE / 'admin/recovery.py').read_text()
        for name in ("'setup-password'", "'operator-password'"):
            self.assertNotIn(name, source)


if __name__ == '__main__':
    unittest.main()
