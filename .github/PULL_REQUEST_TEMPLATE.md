## Description

<!-- Briefly explain what this pull request changes and why. -->

### Related issue

<!-- Link the related issue, or write "N/A". -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Detection-rule improvement
- [ ] Dashboard or UI improvement
- [ ] Documentation
- [ ] Tests or CI
- [ ] Other (describe below)

## Changes made

<!-- List the important changes in this pull request. -->

-

## Testing performed

- [ ] Ran `python -m pytest tests -q`
- [ ] Ran `python -m compileall -q core sensors app_v3.py api.py tests`
- [ ] Added or updated tests for changed behaviour, where applicable
- [ ] Verified that existing functionality remains intact

**Local test result:**

<!-- Include the test result or explain why a check could not be run. -->

## Required GitHub Actions check

The required status check is:

`Pytest (Windows, Python 3.14)`

- [ ] The required check completed successfully.
- [ ] If it failed, I reviewed the Actions logs and addressed the failure.

Do not merge while the required check is pending or failing.

## Database and security safety

- [ ] No personal, development, demonstration, or production database files are included.
- [ ] No credentials, API keys, tokens, secrets, or private configuration files are included.
- [ ] No virtual environments, generated runtime files, or unintended local artifacts are included.
- [ ] Existing user databases and database history have not been unnecessarily modified or deleted.
- [ ] Any database schema or migration changes are documented and tested.

## Detection and data integrity

- [ ] Detection output, reputation results, and anomaly scores are not fabricated.
- [ ] Unknown values remain explicitly unknown.
- [ ] Detection thresholds remain configurable through the appropriate configuration files.
- [ ] Changes to detection behaviour include relevant tests.

## Final checklist

- [ ] This pull request targets `main`.
- [ ] The changes are focused and relevant.
- [ ] Documentation has been updated where necessary.
- [ ] I have reviewed my own changes before requesting review.
