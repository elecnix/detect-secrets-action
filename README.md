# detect-secrets-action

A GitHub Action that runs [Yelp/detect-secrets](https://github.com/Yelp/detect-secrets)
as a **baseline-diffed gate**: it fails only on secret findings that are NOT
in the audited baseline, compared on `(path, type, hashed_secret)` —
deliberately **not** on line numbers.

## Why not `detect-secrets-hook --baseline`?

The hook rewrites the baseline whenever a finding's *line number* shifts and
exits non-zero asking for a re-commit. That is correct for a pre-commit hook,
but pure churn in CI, where the tree is an ephemeral checkout: moving code
around would fail the build with no new secret anywhere. This gate compares
on content hashes only, so only a genuinely NEW finding fails.

## Usage

```yaml
- uses: elecnix/detect-secrets-action@v1
  with:
    baseline: .secrets.baseline        # default
    detect_secrets_version: "1.5.0"    # default; pinned, no floats
    python_version: "3.12"             # default
```

The step fails (exit 1) if the scan produces a finding whose
`(path, type, hash)` is absent from the baseline. The number of new findings
is exposed as the `new_findings` output.

### Preparing the baseline

```sh
pip install detect-secrets==1.5.0
detect-secrets scan $(git ls-files -co --exclude-standard | grep -v '^\.secrets\.baseline$') > .secrets.baseline
# audit every finding: mark each is_secret true/false
detect-secrets audit .secrets.baseline
git add .secrets.baseline && git commit -m "chore: add audited secrets baseline"
```

The baseline file itself is excluded from scans automatically — it stores the
triaged hashes themselves, so scanning it would find them again as "new".

## Development

```sh
pytest test_gate.py -q                                  # unit tests
python3 .github/fixtures.py clean-passes                # integration scenarios
python3 .github/fixtures.py planted-secret-fails
python3 .github/fixtures.py drift-passes
```

CI runs both on every push/PR: unit tests, plus three integration fixtures
that drive the real `gate.py` against real throwaway git repos (clean tree
passes; planted GitHub token fails; line-number drift passes).

## License

MIT
