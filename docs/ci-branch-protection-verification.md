# CI Branch Protection Verification

This temporary document exists only to verify that the `main` branch requires:

- a pull request before merging; and
- a successful `Pytest (Windows, Python 3.14)` status check.

It is added from `ci/branch-protection-verification` for an end-to-end test.
The pull request must be closed without merging, and this branch and file must
then be deleted.
