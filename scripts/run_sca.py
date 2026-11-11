"""Run Snyk Open Source; findings are evaluated separately by the gate."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def manifests(root=ROOT):
    return [p for p in (root / 'requirements.txt', root / 'demo/requirements.txt') if p.is_file()]


def main():
    reports = ROOT / 'reports'
    reports.mkdir(exist_ok=True)
    # Never reuse results from an earlier local run.
    for pattern in ('snyk-*.json', 'sca-summary.*'):
        for path in reports.glob(pattern):
            path.unlink()
    if not os.environ.get('SNYK_TOKEN'):
        print('SCA error: SNYK_TOKEN is missing.', file=sys.stderr)
        return 2
    python = ROOT / '.sca-venv' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    snyk = shutil.which('snyk')
    if not snyk or not python.is_file() or not (ROOT / 'requirements.txt').is_file():
        print('SCA error: install Snyk, requirements.txt and .sca-venv first.', file=sys.stderr)
        return 2
    failed = False
    for manifest in manifests():
        name = 'demo' if manifest.parent.name == 'demo' else 'requirements'
        output = reports / f'snyk-{name}.json'
        try:
            result = subprocess.run([
                snyk, 'test', f'--file={manifest.relative_to(ROOT).as_posix()}',
                '--package-manager=pip', f'--json-file-output={output}',
                f'--command={python}', f'--policy-path={ROOT / ".snyk"}',
            ], cwd=ROOT, shell=False, capture_output=True, timeout=600)
            # Do not relay tool output, which may contain credentials.
            print(f'{manifest.relative_to(ROOT)}: Snyk exit code {result.returncode}')
            if result.returncode not in (0, 1) or not output.is_file():
                failed = True
        except (OSError, subprocess.TimeoutExpired):
            print(f'SCA error: scanner failed for {manifest.relative_to(ROOT)}.', file=sys.stderr)
            failed = True
    return 2 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
