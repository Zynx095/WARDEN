# Northstar Engineering: project briefing

Northstar Engineering is a fictional company for the Fetch-A-Thon 3.0 demo. Its employee
portal is modelled on a real open-source application:

- **Reference application:** Flask Microblog, https://github.com/miguelgrinberg/microblog
- **Commit inspected:** `a975ef64864354867c88e0ed3a17ba7d17dca752` (2025-04-06, "Update README file")
- **Local clone (read-only reference):** `D:\AI\northstar_reference\microblog`. Nothing was modified
  or pushed. WARDEN never touches this clone.

## What the application does

Microblog is the application of Miguel Grinberg's Flask Mega-Tutorial (2024 edition): users
register and log in, post short updates, follow each other, edit their profile ("about me", last
seen), send private messages, get notifications, search posts (Elasticsearch), translate posts
(Microsoft Translator), export their posts through a background task queue (Redis + RQ), and use a
token-authenticated REST API. Northstar uses it as its internal employee portal.

## The files an engineering agent would touch

| Kind | In Microblog | Typical agent work |
|---|---|---|
| Application code | `app/models.py`, `app/main/routes.py`, `app/auth/*.py`, `app/api/*.py`, `app/tasks.py` | read for context, small fixes |
| Templates | `app/templates/*.html` | wording and layout changes |
| Tests | `tests.py` | add or update tests |
| Schema migrations | `migrations/versions/*.py` | generated, reviewed by humans |
| Settings | `config.py` (reads environment variables), `.flaskenv` | non-secret defaults |
| Deployment | `Dockerfile`, `boot.sh`, `deployment/nginx`, `deployment/supervisor` | infrastructure changes |
| Translations | `app/translations/es/LC_MESSAGES/messages.po` | content updates |

## Sensitive configuration and important state

`config.py` loads a `.env` file and reads `SECRET_KEY`, `DATABASE_URL`, `MAIL_USERNAME`,
`MAIL_PASSWORD`, `MS_TRANSLATOR_KEY`, `ELASTICSEARCH_URL` and `REDIS_URL`. In a real deployment those
live in an environment file that no assistant should read, let alone change. The SQLite database
(`app.db` by default) and the migration history are application state whose loss is not
recoverable from the repository.

## Safe, destructive and prohibited operations

| Category | Real-world example | WARDEN decision |
|---|---|---|
| Safe | read a source file, write a release note, list the project | allowed (`WDN-000`), executed, independently verified |
| Destructive | delete a cache or build artifact, overwrite an existing file, rename a file | held for an authorized human (`WDN-004`, `WDN-005`) |
| Prohibited | read or change the production environment file, touch anything outside the workspace | blocked before execution (`WDN-003`, `WDN-002`) |

## What WARDEN actually operates on in the demo

WARDEN works only inside its sandboxed demo workspace, `northstar_workspace\` in the WARDEN
repository, created by `demo\northstar.py setup`. It holds small synthetic stand-ins for the
files above, not Microblog source:

| File | Stands for | Role in the demo |
|---|---|---|
| `README.md` | the project README | context |
| `src/profile_service.py` | profile rules in `app/models.py` / `app/main/forms.py` | readable source |
| `tests/test_profile_service.py` | `tests.py` | readable tests |
| `config/app_config.json` | non-secret settings from `config.py` | readable configuration |
| `production.env` | the production `.env` (placeholders only: `DEMO_ONLY_PLACEHOLDER`) | protected, scenarios B and D |
| `tmp/session_cache.tmp` | a disposable cache file | destructive approval, scenario C |
| `demo_manifest.json` | the setup baseline (file hashes) | used by `northstar.py check` |
| `README.txt`, `cache.tmp`, `debug.log`, `.warden-demo-workspace` | WARDEN's standard demo fixtures and marker | present in every WARDEN demo workspace |

The demo does not claim that WARDEN edits Microblog. It shows the control layer an assistant
working on such a repository would go through.
