"""Host credentials become SOPS/age ciphertext in the reviewed source (real tools)."""
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(BASE / 'admin'), str(BASE / 'scripts'), str(BASE / 'tests')]
import host_secrets
import runtime as rt

TOOLS = all(shutil.which(tool) for tool in ('sops', 'age-keygen', 'openssl'))


@unittest.skipUnless(TOOLS, 'requires sops, age and openssl (nix develop .#secrets-test)')
class HostSecretsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'source'
        self.key = Path(self.temp.name) / 'sops-nix' / 'key.txt'
        self.recipient = host_secrets.ensure_identity(self.key)

    def decrypt(self):
        env = dict(os.environ, SOPS_AGE_KEY_FILE=str(self.key))
        return json.loads(subprocess.run(['sops', 'decrypt', '--output-type', 'json', str(host_secrets.path(self.root))],
                                         capture_output=True, check=True, env=env).stdout)

    def test_identity_is_private_and_never_overwritten(self):
        mode = stat.S_IMODE(self.key.stat().st_mode)
        self.assertEqual(mode, 0o600)
        self.assertEqual(stat.S_IMODE(self.key.parent.stat().st_mode), 0o700)
        original = self.key.read_bytes()
        self.assertEqual(host_secrets.ensure_identity(self.key), self.recipient)
        self.assertEqual(self.key.read_bytes(), original)
        self.assertRegex(self.recipient, host_secrets.RECIPIENT)

    def test_initial_file_locks_the_operator_until_the_ui_sets_it(self):
        host_secrets.initialize(self.root, self.key)
        names = host_secrets.names(host_secrets.path(self.root))
        self.assertEqual(names, {host_secrets.PLACEHOLDER, 'cockpit-operator-password', host_secrets.UNSET})
        self.assertFalse(host_secrets.operator_password_set(self.root))
        self.assertTrue(self.decrypt()['cockpit-operator-password'].startswith('$6$'))
        original = host_secrets.path(self.root).read_bytes()
        host_secrets.initialize(self.root, self.key)  # Idempotent.
        self.assertEqual(host_secrets.path(self.root).read_bytes(), original)

    def test_write_merges_encrypts_and_clears_the_lock(self):
        host_secrets.initialize(self.root, self.key)
        changed = host_secrets.write(self.root, {'cockpitPassword': '$6$chosen$hash\n',
                                                 'resticPassword': 'restic-plaintext-sentinel'}, self.key)
        self.assertEqual(changed, ['cockpitPassword', 'resticPassword'])
        text = host_secrets.path(self.root).read_text()
        self.assertNotIn('restic-plaintext-sentinel', text)
        self.assertNotIn('$6$chosen$hash', text)
        self.assertTrue(host_secrets.operator_password_set(self.root))
        values = self.decrypt()
        self.assertEqual(values['restic-password'], 'restic-plaintext-sentinel')
        self.assertEqual(values['cockpit-operator-password'], '$6$chosen$hash\n')
        host_secrets.write(self.root, {'wifiPassword': 'NIXUS_WIFI_PSK=x\n'}, self.key)
        self.assertEqual(self.decrypt()['restic-password'], 'restic-plaintext-sentinel')
        self.assertTrue(host_secrets.present(self.root, 'wifiPassword'))

    def test_rejects_unknown_fields_and_hides_tool_output(self):
        with self.assertRaises(ValueError):
            host_secrets.write(self.root, {'invented': 'x'}, self.key)
        with self.assertRaises(ValueError):
            host_secrets.write(self.root, {'resticPassword': 7}, self.key)
        failure = subprocess.CalledProcessError(1, ['sops'], output=b'leaked-plaintext', stderr=b'leaked-key')
        with patch.object(host_secrets.subprocess, 'run', side_effect=failure):
            with self.assertRaises(ValueError) as error:
                host_secrets.write(self.root, {'resticPassword': 'x'}, self.key)
        self.assertNotIn('leaked', str(error.exception))
        self.assertTrue(error.exception.__suppress_context__)
        self.assertIsNone(error.exception.__cause__)


@unittest.skipUnless(TOOLS, 'requires sops, age and openssl (nix develop .#secrets-test)')
class SopsReviewTests(unittest.TestCase):
    def test_review_encrypts_into_the_job_source_and_stages_no_plaintext(self):
        from controller import Manager
        from test_setup import HOST, settings
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'repo'; state = Path(folder) / 'state'; state.mkdir()
            key = Path(folder) / 'key.txt'
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            (root / 'flake.nix').write_text('{}')
            subprocess.run(['git', '-C', str(root), 'add', 'flake.nix'], check=True)
            current = settings()
            current['secrets'].update(enable=True, hostFile=host_secrets.RELATIVE, ageKeyFile=str(key))
            rt.write_json(root / 'local/settings.json', current)
            host_secrets.ensure_identity(key)
            host_secrets.initialize(root, key)
            live = host_secrets.path(root).read_bytes()
            manager = Manager(root, state)
            with patch.object(rt, 'STATE', state), patch('controller.inventory', return_value=HOST), \
                    patch('controller.read_settings', side_effect=lambda r: rt.read_json(rt.machine_path(r, 'settings'), {})), \
                    patch.object(manager, 'spawn') as spawn:
                output = manager.review({'hostName': 'changed'}, {'resticPassword': 'Review-plaintext-sentinel-1!'})
            directory = manager.job_path(output['id'])
            job = rt.read_json(directory / 'job.json')
            self.assertEqual(job['secretChanges'], [])
            self.assertEqual(job['encryptedSecretChanges'], ['resticPassword'])
            self.assertFalse((directory / 'secrets.json').exists())
            self.assertEqual(host_secrets.path(root).read_bytes(), live, 'Live ciphertext changes only on apply')
            for path in directory.rglob('*'):
                if path.is_file():
                    self.assertNotIn(b'Review-plaintext-sentinel-1!', path.read_bytes(), path)
            self.assertTrue(host_secrets.present(directory / 'source', 'resticPassword'))
            spawn.assert_called_once_with('build', output['id'])


class HostSecretNamesTests(unittest.TestCase):
    def test_names_are_read_without_decryption(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / 'host.yaml'
            file.write_text('restic-password: ENC[AES256_GCM,data:x]\nsops:\n    age: []\n  nested: ENC[x]\n')
            self.assertEqual(host_secrets.names(file), {'restic-password'})
            self.assertEqual(host_secrets.names(Path(folder) / 'missing.yaml'), set())


if __name__ == '__main__':
    unittest.main()
