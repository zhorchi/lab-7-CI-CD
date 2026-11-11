"""Synthetic scanner results and mocked HTTP only; no live Jira calls."""
import json
from pathlib import Path
import subprocess
from unittest.mock import Mock

import pytest
import requests

from scripts import check_sca_gate as gate, jira_sync as jira, run_sca


def vulnerability(level='high'):
    return {'id': 'SNYK-PYTHON-EXAMPLE-TEST', 'name': 'example', 'version': '1.0',
            'severity': level, 'identifiers': {'CVE': ['CVE-TEST-ONLY']},
            'cvssScore': 8.0, 'fixedIn': ['2.0'], 'upgradePath': [False, 'example@2.0']}


@pytest.mark.parametrize('severity,code', [('critical', 1), ('high', 1), ('medium', 0), ('low', 0)])
def test_gate_severity(tmp_path, monkeypatch, severity, code):
    reports = tmp_path / 'reports'
    reports.mkdir()
    item = vulnerability(severity)
    (reports / 'snyk-requirements.json').write_text(json.dumps({'ok': False, 'vulnerabilities': [item, item]}))
    output, step_summary = tmp_path / 'output', tmp_path / 'step-summary'
    monkeypatch.setenv('GITHUB_OUTPUT', str(output))
    monkeypatch.setenv('GITHUB_STEP_SUMMARY', str(step_summary))
    assert gate.main(tmp_path) == code
    result = json.loads((reports / 'sca-summary.json').read_text())
    assert result['counts'][severity] == 1
    assert result['has_actionable'] == (severity != 'low')
    assert result['vulnerabilities'][0]['manifest'] == 'requirements.txt'
    assert result['vulnerabilities'][0]['fixed_in'] == ['2.0']
    assert 'report_generated=true' in output.read_text()
    assert step_summary.read_text() == (reports / 'sca-summary.md').read_text()


def test_clean_and_demo_reports(tmp_path):
    reports = tmp_path / 'reports'
    reports.mkdir()
    clean = json.dumps({'ok': True, 'vulnerabilities': []})
    (reports / 'snyk-requirements.json').write_text(clean)
    assert gate.main(tmp_path) == 0
    (tmp_path / 'demo').mkdir()
    (tmp_path / 'demo/requirements.txt').touch()
    assert gate.main(tmp_path) == 2
    assert not (reports / 'sca-summary.json').exists()
    (reports / 'snyk-demo.json').write_text(clean)
    assert gate.main(tmp_path) == 0


@pytest.mark.parametrize('data', [{}, [], {'error': 'failure'}, {'ok': False, 'vulnerabilities': []},
                                 {'vulnerabilities': [vulnerability('unknown')]}])
def test_invalid_results_fail_closed(data):
    with pytest.raises(ValueError):
        gate.normalize(data, 'requirements.txt')


def test_optional_metadata_not_invented():
    item = vulnerability()
    for name in ('cvssScore', 'fixedIn', 'upgradePath', 'identifiers'):
        item.pop(name)
    result = gate.normalize([{'ok': False, 'vulnerabilities': [item]}], 'requirements.txt')[0]
    assert result['cve'] == [] and result['cvss'] is None
    assert result['fixed_in'] == result['upgrade_path'] == []


def test_manifest_discovery(tmp_path):
    (tmp_path / 'requirements.txt').touch()
    assert run_sca.manifests(tmp_path) == [tmp_path / 'requirements.txt']
    (tmp_path / 'demo').mkdir()
    (tmp_path / 'demo/requirements.txt').touch()
    assert run_sca.manifests(tmp_path) == [tmp_path / 'requirements.txt', tmp_path / 'demo/requirements.txt']


@pytest.mark.parametrize('level', ['high', 'critical'])
def test_gate_combines_project_and_demo(tmp_path, level):
    reports = tmp_path / 'reports'
    reports.mkdir()
    (tmp_path / 'demo').mkdir()
    (tmp_path / 'demo/requirements.txt').touch()
    for filename, severity in [('snyk-requirements.json', 'medium'), ('snyk-demo.json', level)]:
        (reports / filename).write_text(json.dumps({'ok': False, 'vulnerabilities': [vulnerability(severity)]}))
    assert gate.main(tmp_path) == 1
    result = json.loads((reports / 'sca-summary.json').read_text())
    assert result['counts']['medium'] == 1 and result['counts'][level] == 1
    assert result['has_actionable'] is True
    assert {v['manifest'] for v in result['vulnerabilities']} == {'requirements.txt', 'demo/requirements.txt'}
    assert 'demo/requirements.txt' in (reports / 'sca-summary.md').read_text()


def jira_env():
    return {'JIRA_BASE_URL': 'https://example.atlassian.net', 'JIRA_USER_EMAIL': 'test@example.test',
            'JIRA_API_TOKEN': 'secret-test-token', 'JIRA_PROJECT_KEY': 'LAB',
            'GITHUB_REPOSITORY': 'example/lab', 'SCA_SCOPE': 'pr-2', 'GITHUB_RUN_ID': '123'}


def summary(level='medium'):
    return {'report_generated': True, 'vulnerabilities': gate.normalize(
        {'ok': False, 'vulnerabilities': [vulnerability(level)]}, 'requirements.txt')}


def response(data, status=200):
    result = Mock(status_code=status)
    result.json.return_value = data
    return result


@pytest.mark.parametrize('level', ['medium', 'high', 'critical'])
def test_jira_create_adf_and_deduplicate(level):
    session = Mock()
    session.request.side_effect = [response({'issues': []}), response({'key': 'LAB-1'}, 201)]
    jira.sync(summary(level), jira_env(), session)
    search, create = session.request.call_args_list
    assert search.args[1].endswith('/search/jql')
    fields = create.kwargs['json']['fields']
    assert fields['issuetype'] == {'name': 'Task'}
    assert fields['description']['type'] == 'doc'
    assert fields['description']['version'] == 1
    assert fields['labels'][0] in search.kwargs['json']['jql']
    assert 'actions/runs/123' in json.dumps(fields)
    assert 'secret-test-token' not in json.dumps(fields)
    session.request.reset_mock()
    session.request.side_effect = [response({'issues': [{'key': 'LAB-1'}]}), response({}, 204)]
    jira.sync(summary(level), jira_env(), session)
    assert session.request.call_args.args == ('PUT', 'https://example.atlassian.net/rest/api/3/issue/LAB-1')
    assert session.request.call_args_list[0].kwargs['json']['jql'] == search.kwargs['json']['jql']


def test_jira_missing_secrets_and_low():
    session = Mock()
    with pytest.raises(jira.JiraError, match='missing:'):
        jira.sync(summary(), {}, session)
    jira.sync(summary('low'), {}, session)
    session.request.assert_not_called()


def test_jira_localized_issue_type():
    session = Mock()
    session.request.side_effect = [response({'issues': []}), response({'key': 'LAB-1'}, 201)]
    env = jira_env()
    env['JIRA_ISSUE_TYPE'] = 'Задача'
    jira.sync(summary(), env, session)
    assert session.request.call_args.kwargs['json']['fields']['issuetype'] == {'name': 'Задача'}


@pytest.mark.parametrize('status', [301, 400, 401, 403, 429, 500])
def test_jira_http_errors_hide_response(status):
    session = Mock()
    session.request.return_value = response({'error': 'secret-test-token'}, status)
    with pytest.raises(jira.JiraError, match=f'HTTP {status}') as error:
        jira.sync(summary(), jira_env(), session)
    assert 'secret-test-token' not in str(error.value)


def test_jira_network_error_hides_details():
    session = Mock()
    session.request.side_effect = requests.ConnectionError('secret-test-token')
    with pytest.raises(jira.JiraError) as error:
        jira.sync(summary(), jira_env(), session)
    assert 'secret-test-token' not in str(error.value)


def test_jira_error_details_are_useful_and_redacted():
    session = Mock()
    session.request.return_value = response({
        'errorMessages': ['Invalid project; secret-test-token'],
        'errors': {'issuetype': 'Specify a valid issue type'},
    }, 400)
    with pytest.raises(jira.JiraError) as error:
        jira.sync(summary(), jira_env(), session)
    message = str(error.value)
    assert 'search/jql' in message
    assert 'Invalid project' in message
    assert 'Specify a valid issue type' in message
    assert 'secret-test-token' not in message


@pytest.mark.parametrize('codes,expected', [([0, 0], 0), ([1, 1], 0), ([2, 0], 2), ([3, 1], 2)])
def test_scan_return_codes_and_all_manifests(tmp_path, monkeypatch, codes, expected):
    monkeypatch.setattr(run_sca, 'ROOT', tmp_path)
    monkeypatch.setenv('SNYK_TOKEN', 'secret-test-token')
    (tmp_path / 'requirements.txt').touch()
    (tmp_path / 'demo').mkdir()
    (tmp_path / 'demo/requirements.txt').touch()
    executable = tmp_path / '.sca-venv' / ('Scripts/python.exe' if run_sca.os.name == 'nt' else 'bin/python')
    executable.parent.mkdir(parents=True)
    executable.touch()
    monkeypatch.setattr(run_sca.shutil, 'which', lambda _: 'snyk')
    monkeypatch.setattr(run_sca, 'manifests', lambda: [tmp_path / 'requirements.txt', tmp_path / 'demo/requirements.txt'])
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        assert kwargs['shell'] is False
        assert f'--command={executable}' in args
        assert 'secret-test-token' not in ' '.join(args)
        output = next(v.split('=', 1)[1] for v in args if v.startswith('--json-file-output='))
        Path(output).write_text('{"ok": true, "vulnerabilities": []}')
        return subprocess.CompletedProcess(args, codes[len(calls) - 1])

    monkeypatch.setattr(run_sca.subprocess, 'run', fake_run)
    assert run_sca.main() == expected
    assert len(calls) == 2


def test_scan_missing_token_clears_stale_results(tmp_path, monkeypatch):
    monkeypatch.setattr(run_sca, 'ROOT', tmp_path)
    monkeypatch.delenv('SNYK_TOKEN', raising=False)
    (tmp_path / 'reports').mkdir()
    (tmp_path / 'reports/sca-summary.json').write_text('{}')
    assert run_sca.main() == 2
    assert not (tmp_path / 'reports/sca-summary.json').exists()
