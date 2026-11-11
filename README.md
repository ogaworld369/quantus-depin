# Quantus DePIN — Participation Registry

Verifiable participation records for people who run a Quantus full
node on an Android phone.

A phone cannot mine Quantus (QPoW). What it *can* do is stay online,
stay in sync, and relay blocks and transactions for the network. This
project makes that work countable: the node periodically signs a
**proof bundle** — a tamper-evident record of what it observed — and
anyone can verify the bundle and recompute the published figures.
There is no server to trust: submissions, verification, scoring, and
the dashboard all live in this repository, and the verification runs
in GitHub Actions on the same open code you can run locally.

This layer is strictly separate from the chain itself. It does not
touch Quantus consensus, block production (QPoW), or miner rewards,
and it pays out nothing. If this registry disappeared tomorrow, every
bundle would still verify with the standalone tools in `tools/`.

## How it works

1. **Checkpoints.** While the node runs, the node app's built-in recording component records
   one checkpoint every 600 seconds: the best block number and hash it
   observed, the finalized block number, and the number of peers it
   saw. (The SPEC also defines optional witness peer hashes, but the
   shipped recorder does not produce them — the node's safe RPC
   withholds peer lists — so witness-based scoring is specified but
   not yet active.)

   Each checkpoint feeds a sequential hash chain (SHA-256 applied
   1,000,000 times per checkpoint) seeded with the observed block
   hash, so a checkpoint interval cannot be computed before that
   block exists.
2. **Bundles.** Checkpoints are collected into a JSON bundle signed
   with the device's Ed25519 key. The device ID is derived from the
   public key; bundles contain public keys only, never secrets.
3. **Submission.** The participant opens a pull request adding their
   bundle under `submissions/<github-account>/` (see
   [submissions/README.md](submissions/README.md)).
4. **Verification and scoring.** GitHub Actions verifies every bundle
   (strict schema checks first, then signature, then the sequential
   chain) and runs the scorer:
   - **What counts** is only what can be cross-checked against public
     chain facts: block progression and finalization lag. Self-reported
     values such as peer counts are displayed but never scored.
   - **Time cannot be compressed or bought.** Credited days come only
     from gate-passing checkpoints at the fixed 600-second slot;
     missing checkpoints decay quadratically; checkpoints from the
     last 7 days are not settled yet; weight grows with the square
     root of settled days, capped at one year.
   - **Mutual witnessing (specified, not yet active).** The SPEC
     defines relay credit corroborated when two participants' bundles
     reference each other, with a block-local cap on closed clusters
     that only ever witness themselves. Because the recorder does
     not yet emit witness data (see step 1), this part of the scoring
     currently has nothing to act on.
   - **The penalty is time.** The only disqualification is a failed
     spot check backed by signed evidence, and it revokes the node's
     whole history. Invalid submissions are simply rejected, without
     attribution — submitting a tampered copy of someone else's bundle
     cannot hurt its owner, and resubmitting a bundle is idempotent.
5. **Dashboard.** The results are published as a static page
   (GitHub Pages). The headline figure is the **adjusted weight**;
   the raw node count is shown alongside, never as the headline.

Participation is opt-in and pseudonymous, and is designed to cost
nothing: install the node app, start the node, turn participation on.
There is no entry condition — no invite, no deposit, no account-age
requirement. All anti-forgery complexity lives on the aggregation
side, not in extra steps for participants.

## Repository layout

| Path | Contents |
|---|---|
| `tools/` | Reference implementation: proof format core, verifier, scorer, CLI (Python 3, standard library only) |
| `spec/SPEC.md` | The canonical protocol specification (Japanese) |
| `companion/` | Android companion app sources (v0.3.4) that record checkpoints and export bundles, with its JVM test harness under `companion/tests/` (the standalone predecessor — recording has since moved into the node app; see Status) |
| `tests/` | Python test suite for the reference implementation |
| `submissions/` | Public proof bundles, one directory per participant |
| `scripts/run_verification.py` | The full pipeline: discover, verify, score, report |
| `scripts/build_dashboard.py` | Builds `docs/index.html` from the run results |
| `.github/workflows/verify.yml` | Runs the pipeline on every submission change; deploys the dashboard to Pages on `main` |
| `docs/` | Generated dashboard (GitHub Pages) |

## Reproduce the verification locally

Requires Python 3 (standard library only, nothing to install):

```sh
python3 scripts/run_verification.py            # writes results/scores.json + results/summary.md
python3 scripts/build_dashboard.py             # writes docs/index.html
```

To verify a single bundle, or to build one from observations:

```sh
python3 tools/depin_cli.py verify --bundle submissions/example-demo/bundle-1.json --allow-legacy   # the worked example is a legacy-format bundle; current bundles ("0.5") need no flag
python3 tools/depin_cli.py keygen --out my-device-key.json     # keep this file private, mode 0600
python3 tools/depin_cli.py sample --out observations.json
python3 tools/depin_cli.py generate --key my-device-key.json --observations observations.json --out bundle.json
```

The protocol is specified in [spec/SPEC.md](spec/SPEC.md) (the
canonical text, in Japanese); this README is its English summary.

## Known limitations — read this before trusting the numbers

These are stated plainly, on purpose:

- **A valid bundle proves internal consistency, not history.** What
  verification establishes is that a signed observation record is
  internally consistent and bound to block hashes. It does **not**
  cryptographically prove that the device was actually online and
  relaying in the past: timestamps are device-reported, block hashes
  are public information, and the sequential chain is not a verifiable
  delay function (fast hardware computes it quickly). The "time wall"
  therefore only has meaning together with the submission history —
  *when* each bundle was seen by the aggregation — not from a bundle
  alone.
- **Chain cross-checks are NOT IMPLEMENTED yet.** Checkpoint block
  hashes have not been compared against the real Quantus chain, and
  spot-check expected values are not computed from chain data
  (`tools/chain_checks.py` is an explicit stub). Until that lands,
  spot checks are recorded as *not evaluated*, and no figure here has
  been corroborated against the chain itself.
- **Cluster-cap evasions remain.** Witness lists are not yet produced
  at all (see step 1), and once they are, a participant who omits them
  entirely, or splits activity across multiple identities, can still
  gain more than the current rules intend. The closed-cluster cap
  removes the simplest abuses, not all of them.
- **Witness hashes are not anonymous.** Anyone who knows a
  participant's identifier can test whether it appears in a bundle,
  and checkpoint timings reveal activity patterns.
- **The reference signing code is a prototype.** The pure-Python
  Ed25519 implementation is not constant-time and must not be used
  for production secrets; Ed25519 itself is not post-quantum. Its role
  here is offline identity and tamper-evidence only — the Quantus
  chain's own keys and post-quantum security are a separate layer.
- **This does not make the chain safer in the consensus sense.** More
  phone nodes thicken propagation, add geographic and network
  diversity, and add independent verifiers. They do not raise
  resistance to majority (51%) attacks, and nothing here claims
  otherwise.

## Status

- **Reference implementation: SPEC rules v0.9; bundle format "0.5".**
  The verifier, scorer, and CLI in `tools/` implement the v0.9 rules
  and are covered by the test suite in `tests/`.
- **Android companion: v0.3.4 (retired).** The standalone companion
  in `companion/` recorded checkpoints on a real device and
  exported bundles in the current format. Its role is complete:
  since 2026-11-11, participation recording is integrated into
  the Quantus Node app itself
  ([v3.0](https://github.com/ogaworld369/quantus-android-node/releases/tag/v3.0)),
  and the author's production identity and its accumulated
  history were transferred into the node app, where accumulation
  continues. The companion sources remain in this repository as
  the standalone reference implementation of the recorder.
- **Independent reviews.** The design and the implementation have
  been through six independent external review rounds. The most
  recent round confirmed the fix round that addressed all 11
  findings (5 medium, 6 low; no critical or high findings) of the
  previous round.
- **What this does not prove.** A valid bundle shows the internal
  consistency of a signed observation record bound to block hashes;
  it is not a cryptographic proof of past continuous uptime. The
  scorer's effective-time anchoring bounds backdating to the moment
  the aggregation first saw a checkpoint, and nothing more. See
  "Known limitations" above and §7 of the SPEC.
- **Not yet done.** Chain cross-checks are not implemented (see
  above), witness-based scoring is specified but inactive, and the
  public aggregation pilot has not started — the only submissions in
  this repository are the worked example under `submissions/`.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
