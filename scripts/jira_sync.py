"""Synchronize an aggregate SCA Task with Jira Cloud REST API v3."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

import requests


class JiraError(ValueError):
    """A controlled error message safe to show without API response bodies."""


def request(session, method, url, **kwargs):
    try:
        response = session.request(method, url, timeout=30, allow_redirects=False, **kwargs)
    except requests.RequestException:
        raise JiraError('Jira network request failed (details hidden to protect credentials).') from None
    if not 200 <= response.status_code < 300:
        raise JiraError(f'Jira HTTP {response.status_code}: {method} request rejected.')
    if response.status_code == 204:
        return {}
    try:
        return response.json()
    except ValueError:
        raise JiraError('Jira returned invalid JSON.') from None


def sync(summary, env, session):
    if summary.get('report_generated') is not True or not isinstance(summary.get('vulnerabilities'), list):
        raise ValueError('A successful SCA summary is required.')
    findings = [v for v in summary['vulnerabilities'] if v['severity'] in ('medium', 'high', 'critical')]
    if not findings:
        print('No MEDIUM/HIGH/CRITICAL findings; Jira Task is not needed.')
        return
    required = ('JIRA_BASE_URL', 'JIRA_USER_EMAIL', 'JIRA_API_TOKEN', 'JIRA_PROJECT_KEY')
    missing = [key for key in required if not env.get(key)]
    if missing:
        raise JiraError('Jira integration not executed; missing: ' + ', '.join(missing))
    base = env['JIRA_BASE_URL'].rstrip('/')
    parsed = urlsplit(base)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('JIRA_BASE_URL must be an HTTPS URL without credentials/query/fragment.')
    project = env['JIRA_PROJECT_KEY']
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', project):
        raise ValueError('Invalid JIRA_PROJECT_KEY.')
    repository = env.get('GITHUB_REPOSITORY')
    scope = env.get('SCA_SCOPE') or env.get('GITHUB_HEAD_REF') or env.get('GITHUB_REF')
    if not repository or not scope:
        raise ValueError('Set GITHUB_REPOSITORY and SCA_SCOPE (or GITHUB_REF) for stable deduplication.')
    label = 'sca-' + hashlib.sha256(f'{repository}:{scope}'.encode()).hexdigest()[:32]
    session.auth = (env['JIRA_USER_EMAIL'], env['JIRA_API_TOKEN'])
    session.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
    api = base + '/rest/api/3'
    existing = request(session, 'POST', api + '/search/jql', json={
        'jql': f'project = "{project}" AND labels = "{label}" ORDER BY created DESC',
        'maxResults': 1, 'fields': ['key'],
    })
    if not isinstance(existing.get('issues'), list):
        raise ValueError('Jira search response has no issues list.')
    run_url = f'{env.get("GITHUB_SERVER_URL", "https://github.com")}/{repository}/actions/runs/{env.get("GITHUB_RUN_ID", "")}'
    paragraphs = [f'SCA findings for {repository} ({scope})', f'GitHub Actions: {run_url}']
    for v in findings:
        paragraphs.append(f'{v["component"]}@{v["version"]} | {v["severity"].upper()} | '
                          f'{v["snyk_id"]} | CVE: {", ".join(v["cve"]) or "Unknown"} | '
                          f'Fix: {", ".join(v["fixed_in"] or v["upgrade_path"]) or "Unknown"} | '
                          f'{v["manifest"]}')
    description = {'type': 'doc', 'version': 1, 'content': [
        {'type': 'paragraph', 'content': [{'type': 'text', 'text': line}]} for line in paragraphs
    ]}
    fields = {'summary': f'SCA: dependency vulnerabilities in {repository} ({scope})'[:255],
              'description': description}
    if existing['issues']:
        key = existing['issues'][0]['key']
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*-\d+', key):
            raise ValueError('Invalid Jira issue key in search response.')
        request(session, 'PUT', api + '/issue/' + key, json={'fields': fields})
        print('Existing Jira SCA Task updated.')
    else:
        fields.update({'project': {'key': project}, 'issuetype': {'name': 'Task'}, 'labels': [label]})
        created = request(session, 'POST', api + '/issue', json={'fields': fields})
        if not created.get('key'):
            raise ValueError('Jira did not return a created issue key.')
        print('Jira SCA Task created.')


def main():
    try:
        summary = json.loads(Path('reports/sca-summary.json').read_text(encoding='utf-8'))
        with requests.Session() as session:
            sync(summary, os.environ, session)
        return 0
    except JiraError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError):
        # Only our controlled ValueError messages may be printed.
        print('Jira sync failed. Verify summary, Jira settings and API access.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
