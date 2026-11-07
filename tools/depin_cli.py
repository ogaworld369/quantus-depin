#!/usr/bin/env python3
"""CLI for the Quantus DePIN proof format v0.5 reference implementation.

Subcommands:
  keygen   - generate a device key file (0600, secret never printed)
  sample   - write synthetic observations JSON (no real chain involved)
  generate - build and sign a proof bundle from observations
  verify   - verify a proof bundle (exit 0 = valid, 1 = invalid;
             legacy bundles only with the explicit --allow-legacy)
  bench    - measure sequential SHA-256 iterations/sec on this machine
  score    - aggregate-score submissions (SPEC v0.5: weights, witness
             cross-checks, disqualifications) to a JSON report

Standard library only. Run: python3 depin_cli.py <subcommand> ...
"""

import argparse
import hashlib
import json
import math
import os
import stat
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import depin_core as core
import depin_scorer as scorer
import ed25519_rfc8032 as ed


def _load_key(path):
    # L1: refuse to read a secret from a file that group/other can
    # access; keygen creates key files with mode 0600.
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        raise ValueError(
            "key file %s has mode %o; permissions must be 0600 "
            "(no group/other access)" % (path, mode))
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return bytes.fromhex(data["secret_seed_hex"])


def _save_key(path, seed):
    pubkey = ed.publickey_from_seed(seed)
    data = {
        "format": "quantus-depin-device-key",
        "version": core.VERSION,
        "device_id": core.device_id_from_pubkey(pubkey),
        "pubkey": pubkey.hex(),
        "secret_seed_hex": seed.hex(),
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    return data["device_id"], pubkey.hex()


def cmd_keygen(args):
    if os.path.exists(args.out):
        print("refusing to overwrite existing key file: %s" % args.out)
        return 1
    seed = os.urandom(32)
    device_id, pubkey = _save_key(args.out, seed)
    mode = stat.S_IMODE(os.stat(args.out).st_mode)
    print("device_id: %s" % device_id)
    print("pubkey:    %s" % pubkey)
    print("key file:  %s (mode %o, secret not shown)" % (args.out, mode))
    return 0


def cmd_sample(args):
    observations = []
    base_number = 350000
    base_ts = 1762000000
    for i in range(args.count):
        number = base_number + i * 100
        block_hash = hashlib.sha256(
            ("quantus-synthetic-block-%d" % number).encode()).hexdigest()
        observations.append({
            "timestamp_unix": base_ts + i * args.interval,
            "best_block_number": number,
            "best_block_hash": block_hash,
            "observed_peers": 8 + (i % 5),
            # v0.2+ bundles need a finalized number for checkpoints
            # to be corroborated at scoring time (SPEC v0.5, H5).
            "finalized_block_number": number - 10,
        })
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(observations, f, indent=2)
        f.write("\n")
    print("wrote %d synthetic observations to %s" % (len(observations), args.out))
    return 0


def cmd_generate(args):
    seed = _load_key(args.key)
    with open(args.observations, "r", encoding="utf-8") as f:
        observations = json.load(f)
    bundle = core.build_bundle(
        seed, observations,
        iterations=args.iterations, interval_sec=args.interval,
        profile=args.profile)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)
        f.write("\n")
    print("device_id:   %s" % bundle["device_id"])
    print("checkpoints: %d" % len(bundle["checkpoints"]))
    print("bundle_hash: %s" % bundle["bundle_hash"])
    print("wrote proof bundle to %s" % args.out)
    return 0


def cmd_verify(args):
    with open(args.bundle, "r", encoding="utf-8") as f:
        text = f.read()
    try:
        # Strict intake (v0.8, L-01): NaN/Infinity constants and
        # duplicate object keys are refused at load, matching the
        # Android implementation's parser.
        bundle = core.strict_json_loads(text)
    except ValueError as exc:
        print("INVALID: bundle file refused at load: %s" % exc)
        return 1
    ok, errors = core.verify_bundle(
        bundle, profile=args.profile, allow_legacy=args.allow_legacy)
    if ok:
        print("VALID: %d checkpoints, device %s"
              % (len(bundle["checkpoints"]), bundle["device_id"]))
        return 0
    print("INVALID:")
    for e in errors:
        print("  - %s" % e)
    return 1


# Bound on the deferral-drain passes in one score invocation
# (v0.9, F-01): each pass chain-verifies at most the scorer's
# 512-content-key safety valve, so 128 passes drain up to
# 65,536 distinct deferred keys; beyond that the invocation
# reports provisional instead of running unboundedly.
_MAX_SCORE_PASSES = 128


def cmd_score(args):
    """Score submissions (SPEC v0.5 aggregation).

    Input JSON: a list of objects, or {"submissions": [...]}. Each
    submission: {"bundle_path": "...", "account": "...",
    "account_age_days": N, "submitted_at_unix": N, "spot_check": {...}?}.
    bundle_path is resolved relative to the input file's directory.

    The scoring time is NEVER read from the input file (H4): it is
    the operator-supplied --scored-at-unix, or the current time.
    Spot-check expectations are read only from the separate
    operator-trusted --spot-expectations file (H7), never from the
    submission records.

    M-03 (v0.4): each submission file is loaded and parsed in
    isolation. A missing file, a bad path or invalid JSON lands in
    the report's rejected_submissions with its reason and never
    aborts the whole scoring run (the v0.3 loader let one broken
    submission kill the batch before scoring even started).

    L-01 (v0.8): every JSON intake here - the submissions list,
    each bundle file, the spot-expectations file - goes through
    core.strict_json_loads, which refuses NaN/Infinity constants
    and duplicate object keys, matching the Android
    implementation's parser. A bundle file refused at load lands
    in rejected_submissions like any other load error.

    F-08 (v0.9): load failures used to compact the submission
    list before scoring, so the scorer's rejected/deferred
    indices pointed at the compacted positions, not the
    operator's original ones ([missing, {}] reported [0, 0]).
    An explicit map from loaded positions back to original
    item indices is kept, and every reported index is
    translated through it.

    F-01 (v0.9): a single scorer pass verifies at most the
    safety-valve number of distinct content keys and DEFERS
    the rest; the v0.8 CLI ran exactly one pass and never fed
    the deferrals back, so with more keys than the valve the
    same submissions were deferred by every invocation,
    forever. The CLI now loops passes inside one invocation:
    each pass scores only the submissions still deferred,
    with their content keys passed as carried_over_keys
    (carry-over priority preserved, exactly as across separate
    API runs), and accumulates nodes and rejected records
    across passes. The loop ends when a pass defers nothing
    (the invocation is complete), when a pass resolves nothing
    new (e.g. a verification that keeps being interrupted -
    the invocation stays provisional with the remaining
    deferred listed), or at _MAX_SCORE_PASSES. Note the
    accumulation is per pass exact, as across separate runs:
    a device whose submissions straddle passes is scored from
    the fragment each pass saw, and a later pass's record for
    a device replaces the earlier one. The scoring time is
    pinned once for the whole invocation so every pass judges
    the same instant.

    F-02 (v0.9): the scorer's records are sanitised at
    construction; as a second line the serialised report is
    passed through core.sanitize_output_string before it is
    written or printed, so no echoed submitter string can
    raise UnicodeEncodeError and destroy the output.
    """
    with open(args.input, "r", encoding="utf-8") as f:
        data = core.strict_json_loads(f.read())
    if isinstance(data, dict):
        items = data["submissions"]
    else:
        items = data
    spot_expectations = None
    if args.spot_expectations:
        with open(args.spot_expectations, "r", encoding="utf-8") as f:
            spot_expectations = core.strict_json_loads(f.read())
    base = os.path.dirname(os.path.abspath(args.input))
    loaded = []        # scorer-shaped submissions, in load order
    orig_index = []    # loaded position -> original item index
    load_rejected = []
    for idx, item in enumerate(items):
        try:
            if not isinstance(item, dict):
                raise ValueError("submission is not an object")
            path = item["bundle_path"]
            if not os.path.isabs(path):
                path = os.path.join(base, path)
            with open(path, "r", encoding="utf-8") as f:
                bundle = core.strict_json_loads(f.read())
        except Exception as exc:
            load_rejected.append(core.sanitize_output_record({
                "index": idx,
                "claimed_device_id": None,
                "account": item.get("account")
                if isinstance(item, dict) else None,
                "reasons": ["submission load error: %s" % exc],
            }))
            continue
        sub = {
            "bundle": bundle,
            "account": item.get("account"),
            "account_age_days": item.get("account_age_days", 0),
            "submitted_at_unix": item.get("submitted_at_unix", 0),
        }
        if "spot_check" in item:
            sub["spot_check"] = item["spot_check"]
        loaded.append(sub)
        orig_index.append(idx)
    # Pin the scoring time for the whole invocation (F-01):
    # every pass must judge the same instant, and the scorer
    # only defaults to "now" per call.
    scored_at = args.scored_at_unix
    if scored_at is None:
        scored_at = int(time.time())
    # Multi-pass deferral drain (F-01). Single-pass behaviour
    # is the degenerate case: one pass, nothing deferred, and
    # the accumulated result equals that pass's result (with
    # indices translated back to the original positions, F-08).
    pending = list(range(len(loaded)))
    carried_keys = None
    passes = 0
    acc_nodes = {}
    acc_rejected = []
    final_deferred = []
    total_duplicates = 0
    total_clusters_capped = 0
    total_keys_verified = 0
    while True:
        passes += 1
        result = scorer.score_submissions(
            [loaded[p] for p in pending],
            scored_at_unix=scored_at, profile=args.profile,
            spot_expectations=spot_expectations,
            carried_over_keys=carried_keys)
        for node in result["nodes"]:
            acc_nodes[node["device_id"]] = node
        total_duplicates += result["summary"]["duplicates_ignored"]
        total_clusters_capped += \
            result["summary"]["closed_clusters_capped"]
        total_keys_verified += \
            result["summary"]["content_keys_verified"]
        for entry in result["rejected_submissions"]:
            entry = dict(entry)
            entry["index"] = orig_index[pending[entry["index"]]]
            acc_rejected.append(entry)
        if not result["deferred_submissions"]:
            final_deferred = []
            break
        next_pending = []
        remapped_deferred = []
        for entry in result["deferred_submissions"]:
            local_index = entry["index"]
            entry = dict(entry)
            entry["index"] = orig_index[pending[local_index]]
            remapped_deferred.append(entry)
            next_pending.append(pending[local_index])
        final_deferred = remapped_deferred
        if passes >= _MAX_SCORE_PASSES or \
                set(next_pending) == set(pending):
            # No progress (e.g. a chain verification that keeps
            # being interrupted defers the same submissions
            # again) or the pass bound is hit: stop and report
            # the invocation as provisional, with the remaining
            # deferred listed - never loop forever.
            break
        carried_keys = set()
        for p in next_pending:
            try:
                carried_keys.add(core.bundle_content_key(
                    loaded[p]["bundle"], profile=args.profile))
            except Exception:
                # A deferred submission's key is computable in
                # every reachable case (it passed stage A, or is
                # an exact duplicate of one that did); if it ever
                # were not, losing carry-over priority for it is
                # safe - the pass structure still drains by
                # subset, only the priority is weaker.
                pass
        pending = next_pending
    nodes_out = [acc_nodes[d] for d in sorted(acc_nodes)]
    all_rejected = sorted(
        load_rejected + acc_rejected, key=lambda e: e["index"])
    deferred_keys_remaining = set()
    for entry in final_deferred:
        p = orig_index.index(entry["index"])
        try:
            deferred_keys_remaining.add(core.bundle_content_key(
                loaded[p]["bundle"], profile=args.profile))
        except Exception:
            pass
    summary = {
        "raw_node_count": sum(
            n["raw_count"] for n in nodes_out),
        "total_adjusted_weight": math.fsum(
            n["adjusted_weight"] for n in nodes_out),
        "disqualified_count": sum(
            1 for n in nodes_out if n["status"] == "disqualified"),
        "closed_clusters_capped": total_clusters_capped,
        "duplicates_ignored": total_duplicates,
        "rejected_count": len(all_rejected),
        "deferred_count": len(final_deferred),
        "complete": len(final_deferred) == 0,
        "content_keys_verified": total_keys_verified,
        "content_keys_deferred": len(deferred_keys_remaining),
    }
    if passes > 1:
        summary["scoring_passes"] = passes
    result = {
        "scored_at_unix": scored_at,
        "nodes": nodes_out,
        "rejected_submissions": all_rejected,
        "deferred_submissions": final_deferred,
        "summary": summary,
    }
    text = core.sanitize_output_string(
        json.dumps(result, indent=2, ensure_ascii=False))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print("wrote scores to %s" % args.out)
    else:
        print(text)
    return 0


def cmd_bench(args):
    state = b"\x00" * 32
    n = args.iterations
    t0 = time.perf_counter()
    for _ in range(n):
        state = hashlib.sha256(state).digest()
    dt = time.perf_counter() - t0
    rate = n / dt
    print("sequential SHA-256 (32-byte state):")
    print("  %d iterations in %.3f s -> %s it/s" % (n, dt, format(int(rate), ",")))
    default = core.DEFAULT_ITERATIONS
    print("  default N=%d per checkpoint -> ~%.2f s at this rate"
          % (default, default / rate))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="Quantus DePIN proof v0.5 CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("keygen")
    sp.add_argument("--out", required=True)
    sp.set_defaults(func=cmd_keygen)

    sp = sub.add_parser("sample")
    sp.add_argument("--out", required=True)
    sp.add_argument("--count", type=int, default=8)
    sp.add_argument("--interval", type=int, default=core.DEFAULT_INTERVAL_SEC)
    sp.set_defaults(func=cmd_sample)

    sp = sub.add_parser("generate")
    sp.add_argument("--key", required=True)
    sp.add_argument("--observations", required=True)
    sp.add_argument("--out", required=True)
    sp.add_argument("--iterations", type=int)
    sp.add_argument("--interval", type=int)
    sp.add_argument("--profile", choices=sorted(core.PARAM_PROFILES),
                    default="production",
                    help="parameter profile (default: production)")
    sp.set_defaults(func=cmd_generate)

    sp = sub.add_parser("verify")
    sp.add_argument("--bundle", required=True)
    sp.add_argument("--profile", choices=sorted(core.PARAM_PROFILES),
                    default="production",
                    help="parameter profile (default: production)")
    sp.add_argument("--allow-legacy", action="store_true",
                    help="also verify legacy bundles (v0.1-v0.4); "
                         "archival use only - legacy bundles are "
                         "never scored (H-02)")
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("score")
    sp.add_argument("--input", required=True)
    sp.add_argument("--out")
    sp.add_argument("--scored-at-unix", type=int,
                    help="scoring time (operator-supplied; default: now). "
                         "Never taken from the input file.")
    sp.add_argument("--spot-expectations",
                    help="operator-trusted spot-check expectations JSON "
                         "({bundle_hash: {challenge_block_hash, expected}})")
    sp.add_argument("--profile", choices=sorted(core.PARAM_PROFILES),
                    default="production",
                    help="parameter profile (default: production)")
    sp.set_defaults(func=cmd_score)

    sp = sub.add_parser("bench")
    sp.add_argument("--iterations", type=int, default=200000)
    sp.set_defaults(func=cmd_bench)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
