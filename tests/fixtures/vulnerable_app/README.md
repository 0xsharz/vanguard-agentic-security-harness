# vulnerable_app — smoke target

Two-bug fixture for end-to-end pipeline testing:

| Endpoint | Bug | CWE |
|----------|-----|-----|
| `/lookup?name=...` | SQL injection (f-string into `cur.execute`) | CWE-89 |
| `/ping?host=...`   | OS command injection (`shell=True` with user input) | CWE-78 |

Smoke run:

```bash
audit run --repo tests/fixtures/vulnerable_app --run-id smoke
audit report --run-id smoke --format md
```

Expectation: at least 2 reachable findings.
