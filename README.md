# Лабораторная работа №7: SCA (Python, Snyk + Jira)

Приложение и исходные тесты сохранены. Workflow SCA Security Scan запускается
при push/PR в main, ежедневно в 03:00 UTC (06:00 МСК) и вручную.

## Настройка GitHub Actions

Settings → Secrets and variables → Actions:

| Тип | Имя | Значение |
| --- | --- | --- |
| Secret | SNYK_TOKEN | Токен Snyk Open Source |
| Secret | JIRA_USER_EMAIL | Email пользователя Jira Cloud |
| Secret | JIRA_API_TOKEN | API token Jira |
| Variable | JIRA_BASE_URL | https://your-site.atlassian.net |
| Variable | JIRA_PROJECT_KEY | Ключ проекта с типом задачи Task |

Пользователю Jira нужны права поиска, создания и изменения задач.
SNYK_TOKEN передаётся только шагу сканирования. Внешние fork PR выполняют тесты
и генерацию SBOM без Snyk/Jira: это не означает успешную проверку SCA.
Jira для внутренних PR использует скрипт и зависимости из main.
Перед первым PR конфигурация должна присутствовать в main.

## Локальный запуск (PowerShell)

Нужны Python 3.12 и Node.js LTS. Из корня проекта:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-sca.txt
npm install -g snyk
py -3.12 -m venv .sca-venv
.\.sca-venv\Scripts\python.exe -m pip install -r requirements.txt
if (Test-Path demo/requirements.txt) {
    .\.sca-venv\Scripts\python.exe -m pip install -r demo/requirements.txt
}
.\.venv\Scripts\python.exe -m pytest

.\.venv\Scripts\python.exe scripts/run_sca.py
.\.venv\Scripts\python.exe scripts/check_sca_gate.py
.\.venv\Scripts\python.exe -m cyclonedx_py environment .sca-venv/Scripts/python.exe --output-format JSON --output-file reports/sbom.cdx.json
```

В Linux используйте python3.12, .venv/bin/python и .sca-venv/bin/python.
SCA-инструменты отделены от анализируемого окружения. SBOM учитывает все
установленные зависимости приложения, включая транзитивные и инструменты
тестирования из исходного requirements.txt.
Учебный demo/requirements.txt пока не создаётся. При появлении его зависимости
устанавливаются в то же .sca-venv после основных. Конфликтующие версии могут
повлиять на дерево обоих манифестов; ошибки установки/сканирования нельзя
считать чистым результатом. Код библиотек из demo отдельно не запускается.

## Отчёты и Quality Gate

Артефакт sca-reports содержит snyk-requirements.json, опционально snyk-demo.json,
sca-summary.json, sca-summary.md и sbom.cdx.json. Сводка выводится также в Step Summary.
Одинаковые Snyk ID/пакет/версия внутри манифеста объединяются.
Неизвестные CVE, CVSS и исправления не выдумываются.

- CRITICAL/HIGH: 0 допустимых, Gate возвращает 1.
- MEDIUM: предупреждение; LOW: информация.
- Отсутствующий/ошибочный отчёт: код 2, проверка не считается успешной.
- Snyk 0/1 означает завершённое сканирование, 2/3 — техническую ошибку.

Gate использует continue-on-error для сохранения отчётов и создания SBOM,
затем финальный шаг завершает scan с ошибкой. Jira запускается даже после
провала Gate при наличии отчёта с MEDIUM/HIGH/CRITICAL.
Одна агрегированная Task создаётся/обновляется по стабильной хеш-метке
репозитория и ветки/номера PR. Существующая задача обновляется, включая закрытую,
но автоматически не переоткрывается. Чистое сканирование не закрывает задачи.
Запуски одной ветки/PR сериализованы. Параллельные локальные запуски и задержка
индексации поиска Jira всё ещё могут привести к дубликатам.
Без секретов или при отказе API Jira job завершается с явной ошибкой.

## Исключения и обновления

Политика .snyk изначально пуста. Только подтверждённое ложное срабатывание
можно исключить командой:

```text
snyk ignore --id=<SNYK-ID> --reason="<обоснование>" --expiry=<YYYY-MM-DD>
```

Реальные уязвимости ради зелёного CI не подавляются.
Dependabot еженедельно предлагает PR для pip (до 5 открытых) и GitHub Actions.

## Проверки

Добавленные tests/test_sca.py используют только синтетические Snyk JSON и mock HTTP:
уровни Gate, отсутствующие отчёты, коды Snyk, ADF, дедупликация и ошибки Jira.
Реальные Jira Issue из локальных тестов не создаются.
Для отдельной проверки YAML можно установить PyYAML; пайплайну он не нужен.

Документация:
- [Snyk test](https://docs.snyk.io/developer-tools/snyk-cli/commands/test)
- [CycloneDX CLI](https://cyclonedx-bom-tool.readthedocs.io/en/stable/usage.html)
- [Jira REST API v3](https://developer.atlassian.com/cloud/jira/platform/rest/v3/)
