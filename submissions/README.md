# Submissions

This directory holds the public proof bundles submitted by DePIN
participants. Everything here is public by design: anyone can
re-verify every bundle and recompute every figure on the dashboard.

## Layout

```
submissions/
  <your-github-account>/
    submission.json        - submission metadata (see below)
    bundle-<n>.json        - one or more signed proof bundles
```

Create one directory named after your GitHub account. Do not place
files for anyone else, and never place a key file here: bundles
contain public keys only. **Never commit a device key or any secret.**

## submission.json

```json
{
  "account": "your-github-account",
  "account_age_days": 0,
  "submitted_at_unix": 0,
  "bundles": ["bundle-1.json"]
}
```

- `account` — display label only.
- `account_age_days`, `submitted_at_unix` — display/informational
  only. They never influence weight, eligibility, or disqualification
  (SPEC v0.3 sections 8 and 10).
- `bundles` — file names of your proof bundles in this directory.
- Optional: `spot_checks` — your spot-check *responses*, keyed by
  bundle hash. Responses are only evaluated against expectations an
  operator supplies through a separate trusted channel; expectations
  written here are ignored.

## How submissions are processed

On every change, GitHub Actions runs the reference verifier and
scorer (the same code in `tools/`, runnable locally via
`scripts/run_verification.py`):

- An invalid bundle is **rejected without attribution**. A rejection
  never creates, damages, or disqualifies a node — a tampered copy of
  someone else's bundle cannot hurt its owner.
- Resubmitting the same bundle is idempotent: duplicates are ignored.
- Disqualification happens only on signed evidence (a failed spot
  check against an operator-supplied expectation). It revokes the
  node's whole history: raw count and adjusted weight become 0.

## Example

`example-demo/` contains a worked example built from the reference
implementation's synthetic demo bundle (not a real node, no real
chain data). The second entry in its `bundles` list is a deliberately
tampered copy, included so the rejection path is visible in the
verification output.
