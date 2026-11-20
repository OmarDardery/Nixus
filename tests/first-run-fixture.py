"""Fresh-install state for the first-run VM test: source, TLS, open enrollment.

Mirrors what the installer leaves behind; unlike portal-fixture.py, no portal
account is created.
"""
import grp
import json
import os
from pathlib import Path

import enrollment
import runtime as rt

root = rt.ROOT
root.mkdir(parents=True, mode=0o700, exist_ok=True)
files = ['site.nix', 'site-defaults.nix', 'lib/machine.nix', 'lib/settings-migrations.nix']
for name in files:
    rt.atomic(root / name, (Path(os.environ['NIXUS_TEST_SITE_SOURCE']) / name).read_text())
rt.write_json(root / 'machine/format.json', {'version': 1})
rt.write_json(root / 'machine/settings.json', json.loads(Path('/etc/nixus-test-settings.json').read_text()))
rt.write_json(root / 'machine/installation.json', {'interface': 'eth0', 'trustedCIDRs': ['127.0.0.0/8']})
rt.write_json(root / '.nixus-files.json', files + ['machine/format.json', 'machine/settings.json', 'machine/installation.json'])
rt.STATE.mkdir(parents=True, mode=0o710, exist_ok=True)
os.chown(rt.STATE, 0, grp.getgrnam('nixus-ui').gr_gid)
rt.STATE.chmod(0o710)
rt.issue_tls('127.0.0.1', 'nixus-first-run')
# Same call as the installer; idempotent across reboots and before/after claim.
enrollment.ensure_web_enrollment()
