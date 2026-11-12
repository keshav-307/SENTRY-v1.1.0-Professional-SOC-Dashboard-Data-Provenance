# Contributing to SENTRY

## Development setup

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

## Before opening a pull request

1. Run the test suite: `python -m pytest tests -q`.
2. Run a syntax check: `python -m compileall -q core sensors app_v3.py api.py tests`.
3. Keep detection thresholds configurable through `config/detection_rules.json`
   rather than hardcoding new values.
4. Never fabricate detection output, reputation results or anomaly scores.
   Unknown must stay unknown.
5. Add or update tests for behaviour you change.

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
