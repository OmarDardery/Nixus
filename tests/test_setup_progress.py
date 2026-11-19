"""The first-run walkthrough is derived from host state and never leaks secrets."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(BASE / 'admin'), str(BASE / 'scripts')]
import runtime as rt
import setup_progress

from credential_fixtures import SECRETS


def status(**settings):
    effective = {'cockpit': {'enable': True, 'managePassword': True}, 'adminKeys': [], 'backup': {'enable': False}}
    effective.update(settings)
    return {'setupComplete': False, 'lastConfirmed': None, 'effectiveSettings': effective}


class SetupProgressTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / 'state'; self.state.mkdir()
        self.identity = Path(self.temp.name) / 'projects.agekey'
        self.secret = Path(self.temp.name) / 'cockpit-operator-password'
        for item in (patch.object(rt, 'STATE', self.state),
                     patch.dict(rt.SECRET_PATHS, cockpitPassword=self.secret)):
            item.start(); self.addCleanup(item.stop)

    def progress(self, value, account=True):
        return setup_progress.progress(value, state=self.state, identity=self.identity,
                                       account_valid=lambda: account)

    def states(self, result):
        return {item['id']: item['done'] for item in result['items']}

    def test_fresh_host_lists_required_steps_in_order(self):
        result = self.progress(status())
        self.assertEqual([item['id'] for item in result['items']],
                         ['administrator', 'activation', 'incusBrowser', 'cockpitPassword',
                          'secretsKey', 'recoveryKit', 'sshKey', 'backup'])
        self.assertEqual((result['completed'], result['total'], result['complete']), (1, 6, False))
        self.assertEqual({i['id'] for i in result['items'] if not i['required']}, {'sshKey', 'backup'})

    def test_cockpit_step_applies_only_to_managed_password(self):
        for cockpit in ({'enable': False, 'managePassword': True}, {'enable': True, 'managePassword': False}):
            with self.subTest(cockpit=cockpit):
                ids = [i['id'] for i in self.progress(status(cockpit=cockpit))['items']]
                self.assertNotIn('cockpitPassword', ids)

    def test_every_step_is_recomputed_from_host_state(self):
        value = status(adminKeys=['ssh-ed25519 AAAA fixture'], backup={'enable': True})
        value.update(setupComplete=True, lastConfirmed={'id': 'a' * 32})
        self.secret.write_text('$6$hashed\n')
        self.identity.write_text(SECRETS['private-key'])
        rt.write_json(self.state / 'browser-certificates.json', {'version': 1, 'certificates': {}})
        with patch('browser_certificates.registry', return_value={'certificates': {'a' * 64: {'status': 'active'}}}):
            self.assertFalse(self.states(self.progress(value))['recoveryKit'])
            setup_progress.record_recovery_kit(self.identity, now=1)
            result = self.progress(value)
        self.assertTrue(result['complete'])
        self.assertTrue(all(self.states(result).values()))

    def test_recovery_kit_must_match_the_current_identity(self):
        self.identity.write_text('first identity')
        setup_progress.record_recovery_kit(self.identity, now=1)
        self.assertTrue(self.states(self.progress(status()))['recoveryKit'])
        self.identity.write_text('rotated identity')
        self.assertFalse(self.states(self.progress(status()))['recoveryKit'])

    def test_revoked_or_invalid_browser_certificates_do_not_count(self):
        with patch('browser_certificates.registry', return_value={'certificates': {'a' * 64: {'status': 'revoked'}}}):
            self.assertFalse(self.states(self.progress(status()))['incusBrowser'])
        with patch('browser_certificates.registry', side_effect=ValueError('invalid')):
            self.assertFalse(self.states(self.progress(status()))['incusBrowser'])

    def test_output_and_marker_contain_no_secret_material(self):
        self.identity.write_text(SECRETS['private-key'])
        setup_progress.record_recovery_kit(self.identity, now=1)
        marker = (self.state / setup_progress.MARKER).read_text()
        exported = json.dumps(self.progress(status())) + marker
        for value in SECRETS.values():
            self.assertNotIn(value, exported)
        self.assertNotIn(str(self.identity), exported)


if __name__ == '__main__':
    unittest.main()
