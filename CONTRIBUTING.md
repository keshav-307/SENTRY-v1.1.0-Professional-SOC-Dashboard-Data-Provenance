# Contributing to SENTRY

## Development setup

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

## Before submitting changes

1. Create a feature branch instead of working directly on `main`.
2. Keep changes focused on one problem or feature.
3. Run the test suite locally before opening a pull request:

   ```bash
   python -m pytest tests -q
   ```

4. Run a syntax check:

   ```bash
   python -m compileall -q core sensors app_v3.py api.py tests
   ```

5. Add or update tests for behaviour you change.
6. Keep detection thresholds configurable through `config/detection_rules.json`
   rather than hardcoding new values.
7. Never fabricate detection output, reputation results or anomaly scores.
   Unknown must stay unknown.
8. Never commit databases, credentials, secrets, virtual environments, or
   generated runtime files.

## Pull request process

1. Push the feature branch to your fork or to this repository.
2. Open a pull request targeting `main`.
3. Describe the changes and the testing you performed.
4. Wait for GitHub Actions to complete before merging.

Direct pushes to `main` are blocked. All changes must arrive through a pull
request.

## Mandatory CI requirement

The required status check is exactly:

```text
Pytest (Windows, Python 3.14)
```

GitHub Actions runs automatically for pull requests targeting `main` using
[`.github/workflows/tests.yml`](.github/workflows/tests.yml).

- The full pytest suite must pass.
- A pending or failed required check blocks merging.
- A successful check satisfies the CI requirement.
- If a check fails, inspect the Actions logs, fix the cause, and push another
  commit to the branch. Do not bypass or weaken the tests.

## Database safety

- Development database: `sentry.db`
- Demonstration database: `sentry_demo.db`
- Automated tests use isolated temporary databases.

The demonstration database is selected with `SENTRY_DB_PATH`:

```powershell
$env:SENTRY_DB_PATH = "sentry_demo.db"
.\run_sentry.bat
```

Never upload personal or production database files to GitHub. Never modify or
delete another user's database during development or testing. Back up
`sentry.db` before deliberately deleting or resetting it.

## Current project status

At the time of writing, SENTRY has **171 passing automated tests**, verified by
the GitHub Actions run for the protected `main` branch. This is a snapshot, not
a permanent guarantee: use the latest successful CI run as the authoritative
test status.

## Adding a detection rule

1. Add a rule ID and metadata to `RULE_METADATA` in `core/detector.py`
   (name, severity, description, MITRE mapping, recommended actions).
2. Add defaults to `DEFAULT_RULES_CONFIG` and `config/detection_rules.json`.
3. Implement the rule so it returns `Alert` objects with structured evidence
   built through `_build_evidence`, including the exact triggering events.
4. Add tests covering positive, below-threshold and missing-data cases.

## Code style

Follow the existing style: small functions, explicit names, no silent
exceptions. Enrichment and notification failures must never break detection.
