"""Normalize Snyk Open Source JSON and fail closed on invalid reports."""
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
LEVELS = ('critical', 'high', 'medium', 'low')


def normalize(data, manifest):
    results = data if isinstance(data, list) else [data]
    if not results:
        raise ValueError('Empty Snyk result')
    findings = {}
    for result in results:
        if not isinstance(result, dict) or result.get('error') or not isinstance(result.get('vulnerabilities'), list):
            raise ValueError('Invalid or failed Snyk report')
        if result.get('ok') is not True and not result['vulnerabilities']:
            raise ValueError('Unsuccessful empty Snyk result')
        for item in result['vulnerabilities']:
            if not isinstance(item, dict) or not all(item.get(k) for k in ('id', 'name', 'version', 'severity')):
                raise ValueError('Incomplete vulnerability')
            severity = item['severity'].lower()
            if severity not in LEVELS:
                raise ValueError('Unknown severity')
            key = (manifest, item['id'], item['name'], item['version'])
            fix = item.get('fixedIn') or []
            upgrade = [v for v in item.get('upgradePath', []) if isinstance(v, str)]
            entry = findings.setdefault(key, {
                'snyk_id': item['id'], 'cve': item.get('identifiers', {}).get('CVE', []),
                'component': item['name'], 'version': item['version'], 'severity': severity,
                'cvss': item.get('cvssScore'), 'fixed_in': [], 'upgrade_path': [],
                'manifest': manifest,
            })
            entry['fixed_in'] = sorted(set(entry['fixed_in'] + fix))
            entry['upgrade_path'] = sorted(set(entry['upgrade_path'] + upgrade))
    return list(findings.values())


def markdown(summary):
    lines = ['# SCA summary', '', f'Quality Gate: {"FAILED" if summary["gate_failed"] else "PASSED"}', '']
    lines.extend(f'- {level.upper()}: {summary["counts"][level]}' for level in LEVELS)
    lines += ['', 'MEDIUM: warning; LOW: information.', '']
    for v in summary['vulnerabilities']:
        fix = ', '.join(v['fixed_in'] or v['upgrade_path']) or 'Unknown'
        lines.append(f'- {v["severity"].upper()} {v["component"]}@{v["version"]}: '
                     f'{v["snyk_id"]}; CVE: {", ".join(v["cve"]) or "Unknown"}; '
                     f'CVSS: {v["cvss"] if v["cvss"] is not None else "Unknown"}; '
                     f'fix: {fix}; manifest: {v["manifest"]}')
    return '\n'.join(lines) + '\n'


def main(root=ROOT):
    reports = root / 'reports'
    reports.mkdir(exist_ok=True)
    for name in ('sca-summary.json', 'sca-summary.md'):
        (reports / name).unlink(missing_ok=True)
    try:
        expected = [('snyk-requirements.json', 'requirements.txt')]
        if (root / 'demo/requirements.txt').is_file():
            expected.append(('snyk-demo.json', 'demo/requirements.txt'))
        findings = []
        for name, manifest in expected:
            findings.extend(normalize(json.loads((reports / name).read_text(encoding='utf-8')), manifest))
        counts = {level: sum(v['severity'] == level for v in findings) for level in LEVELS}
        summary = {'report_generated': True, 'counts': counts, 'vulnerabilities': findings,
                   'gate_failed': bool(counts['critical'] or counts['high']),
                   'has_actionable': any(counts[level] for level in LEVELS[:3])}
        rendered = markdown(summary)
        (reports / 'sca-summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
        (reports / 'sca-summary.md').write_text(rendered, encoding='utf-8')
        print(rendered)
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as stream:
                stream.write(rendered)
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
                stream.write(f'report_generated=true\nhas_actionable={str(summary["has_actionable"]).lower()}\n')
        return int(summary['gate_failed'])
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        print('SCA error: missing, malformed or unsuccessful Snyk report.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
