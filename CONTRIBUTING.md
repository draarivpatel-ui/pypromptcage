# Contributing to pypromptcage

Thank you for improving deterministic prompt-security engineering.

## Ground rules

- Keep runtime dependencies at zero.
- Keep the package standard-library only.
- Support Python 3.9 through 3.13.
- Preserve typed public APIs and the `py.typed` marker.
- Add adversarial and benign regression tests for every scanner change.
- Use only synthetic credentials, tokens, canaries, and personal data in fixtures.
- Do not commit real credentials, real personal data, local home paths, or private hostnames.
- Keep rule IDs stable within a major version.

## Local verification

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
python -m compileall -q src tests
python scripts/check_repo.py
python -m pip install build
python -m build
```

The test suite uses only `unittest`. Generated parameterized cases count as individual tests. A change that alters scanner behavior should add both positive and negative cases.

## Code review checklist

- Input, decoded payload, recursion, candidate, and finding limits remain bounded.
- New regular expressions are simple and cannot backtrack through nested quantifiers.
- Evidence is clipped and does not reproduce secret values.
- Redaction positions refer to the canonical string being redacted.
- Findings include stable IDs, severity, CWE, and OWASP metadata.
- Type annotations match runtime behavior.
- Python 3.9 compatibility is preserved.

## Commit style

Use concise commits that explain why the change is needed. Do not add co-author trailers. Keep generated files reproducible.

## Security reports

Do not use the public issue tracker for sensitive vulnerability details. Follow [SECURITY.md](SECURITY.md).
