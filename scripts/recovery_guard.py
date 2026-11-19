"""Keep ordinary automation from creating empty guests during host recovery."""
import json
import os
from pathlib import Path

MODE = Path('/etc/nixus/recovery-mode')


def require_normal():
    if MODE.exists():
        raise ValueError('Replacement-host recovery is active; use the recovery workflow before enabling ordinary automation')
    journal = Path(os.environ.get('NIXUS_STATE', '/var/lib/nixus-admin')) / 'replacement-recovery.json'
    if journal.exists():
        try:
            record = json.loads(journal.read_text())
            if record.get('format') == 1 and record.get('phase') == 'complete': return
        except (OSError, ValueError, AttributeError):
            pass
        raise ValueError('Unfinished recovery journal blocks automation; inspect nixus-admin recovery status')
