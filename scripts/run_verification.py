#!/usr/bin/env python3
"""Run the full DePIN aggregation pipeline locally.

This is the same procedure the GitHub Actions workflow
(.github/workflows/verify.yml) runs:

  1. Discover submissions under submissions/<account>/.
  2. Verify every submitted proof bundle with the reference verifier
     (schema, signature, sequential hash chain -- SPEC v0.3 section 6).
  3. Run the scorer over all submissions (SPEC v0.3 section 8-11).
  4. Report the chain cross-check status. Those checks are NOT
     IMPLEMENTED yet (see tools/chain_checks.py); the report says so
     explicitly instead of pretending they ran.

Outputs (under results/):
  scores.json   - full scorer output plus per-bundle verification
                  results and the chain-check report
  summary.md    - human-readable summary (also appended to the
                  GitHub Actions step summary by the workflow)

Usage:
  python3 scripts/run_verification.py [--scored-at-unix N]
                                      [--profile production|test]

The scoring time is operator-supplied (or the current time); it is
never derived from submission data (SPEC v0.3 section 8, H4).
Standard library only.
"""

import argparse
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import depin_core as core          # noqa: E402
import depin_scorer as scorer      # noqa: E402
import chain_checks                # noqa: E402

SUBMISSIONS_DIR = os.path.join(ROOT, "submissions")
RESULTS_DIR = os.path.join(ROOT, "results")


def discover_submissions():
    """Find participant directories and their bundles + metadata.

    Convention (see submissions/README.md):
      submissions/<account>/submission.json   - metadata (required)
      submissions/<account>/*.json           - proof bundles
    submission.json lists its bundle file names under "bundles".
    """
    found = []
    if not os.path.isdir(SUBMISSIONS_DIR):
        return found
    for account in sorted(os.listdir(SUBMISSIONS_DIR)):
        adir = os.path.join(SUBMISSIONS_DIR, account)
        meta_path = os.path.join(adir, "submission.json")
        if not os.path.isdir(adir) or not os.path.isfile(meta_path):
            continue
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        bundles = []
        for name in meta.get("bundles", []):
            bpath = os.path.join(adir, name)
            with open(bpath, "r", encoding="utf-8") as f:
                bundles.append((name, json.load(f)))
        found.append({
            "account": meta.get("account", account),
            "account_age_days": meta.get("account_age_days", 0),
            "submitted_at_unix": meta.get("submitted_at_unix", 0),
            "spot_checks": meta.get("spot_checks", {}),
            "bundles": bundles,
        })
    return found


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scored-at-unix", type=int,
                    help="scoring time (operator-supplied; default: now)")
    ap.add_argument("--profile", choices=sorted(core.PARAM_PROFILES),
                    default="production",
                    help="parameter profile for v0.3 bundle verification "
                         "(default: production; never use 'test' for "
                         "real aggregation)")
    args = ap.parse_args(argv)

    scored_at = args.scored_at_unix or int(time.time())
    participants = discover_submissions()

    # Step 1+2: verify each bundle individually and record the result.
    verification = []
    scorer_input = []
    all_bundles = []
    for p in participants:
        for name, bundle in p["bundles"]:
            all_bundles.append(bundle)
            ok, errors = core.verify_bundle(bundle, profile=args.profile)
            verification.append({
                "account": p["account"],
                "file": name,
                "device_id": bundle.get("device_id"),
                "version": bundle.get("version"),
                "valid": ok,
                "errors": errors,
            })
            sub = {
                "bundle": bundle,
                "account": p["account"],
                "account_age_days": p["account_age_days"],
                "submitted_at_unix": p["submitted_at_unix"],
            }
            spot = p["spot_checks"].get(bundle.get("bundle_hash"))
            if spot is not None:
                sub["spot_check"] = spot
            scorer_input.append(sub)

    # Step 3: aggregate scoring. Spot-check expectations are NOT read
    # here: this public pipeline has no trusted expectations channel,
    # so spot checks are recorded as not evaluated (SPEC v0.3 s.11).
    scores = scorer.score_submissions(
        scorer_input, scored_at_unix=scored_at, profile=args.profile,
        spot_expectations=None)

    # Step 4: chain cross-checks -- explicitly not implemented.
    chain_report = chain_checks.chain_check_report(all_bundles)

    os.makedirs(RESULTS_DIR, exist_ok=True)
    out = {
        "scored_at_unix": scored_at,
        "profile": args.profile,
        "verification": verification,
        "scores": scores,
        "chain_checks": chain_report,
    }
    scores_path = os.path.join(RESULTS_DIR, "scores.json")
    with open(scores_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
        f.write("\n")

    summary = scores["summary"]
    lines = [
        "# DePIN verification run",
        "",
        "- Scored at (unix): %d" % scored_at,
        "- Parameter profile: %s" % args.profile,
        "- Bundles verified: %d valid / %d total"
        % (sum(1 for v in verification if v["valid"]), len(verification)),
        "- Raw node count: %d" % summary["raw_node_count"],
        "- Total adjusted weight: %.4f" % summary["total_adjusted_weight"],
        "- Disqualified: %d" % summary["disqualified_count"],
        "- Submissions rejected (unattributed): %d" % summary["rejected_count"],
        "- Duplicate submissions ignored: %d" % summary["duplicates_ignored"],
        "- Closed clusters capped: %d" % summary["closed_clusters_capped"],
        "",
        "## Chain cross-checks",
        "",
        "**NOT IMPLEMENTED.** Checkpoint block hashes have not been "
        "compared with the real Quantus chain, and spot-check expected "
        "values are not computed from chain data. Spot checks in this "
        "run are recorded as not evaluated. See tools/chain_checks.py.",
        "",
        "## Nodes",
        "",
    ]
    for n in scores["nodes"]:
        lines.append("- `%s` (%s): status=%s, adjusted weight=%.4f, "
                     "spot check=%s"
                     % (n["device_id"], n["account"], n["status"],
                        n["adjusted_weight"],
                        n["spot_check"] or "not_evaluated"))
    if scores["rejected_submissions"]:
        lines += ["", "## Rejected submissions", ""]
        for r in scores["rejected_submissions"]:
            lines.append("- %s" % json.dumps(r, ensure_ascii=False))
    summary_md = "\n".join(lines) + "\n"
    with open(os.path.join(RESULTS_DIR, "summary.md"), "w",
              encoding="utf-8") as f:
        f.write(summary_md)

    print(summary_md)
    print("wrote %s" % scores_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
