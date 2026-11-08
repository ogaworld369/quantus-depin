"""Regression tests for the SPEC v0.9 fix round (fifth review,
bug audit of v0.8, 2026-11-08). The bundle format does NOT
change (version stays "0.5"); the fixes are in the Python scorer's
result hygiene and the CLI's score driver:

  F-01  the CLI never passed carried_over_keys and offered no way
        to drain the deferral queue: with 513 distinct verifiable
        bundles (one more than the 512 content-key safety valve)
        every CLI run accepted 512, deferred the same 1, and
        reported complete: false - forever. The scorer API drains
        correctly across runs (carried keys go first); the CLI
        now loops passes inside one invocation, feeding each
        pass's deferred keys back as carried_over_keys and
        accumulating results, until a pass defers nothing
        (complete) or no pass makes progress / a pass bound is
        hit (the invocation stays provisional).
  F-02  a rejected submission's submitter-controlled strings
        (claimed_device_id holding a lone surrogate, from a
        bundle whose device_id is the JSON string "\\ud800")
        flowed into the report unchanged, and the CLI's
        ensure_ascii=False JSON write then raised
        UnicodeEncodeError: exit 1, a 0-byte output file, and NO
        results at all - one malformed submission destroyed the
        whole run's output. Result records now sanitise echoed
        strings at construction (lone surrogates and any other
        non-UTF-8-encodable code points become U+FFFD), and the
        CLI sanitises the serialised report as a second line.
  F-08  the CLI compacted away load failures before scoring, so
        the scorer's rejected/deferred indices pointed at the
        COMPACTED list, not the operator's original submissions
        ([missing, {}] reported [0, 0]). The CLI now keeps an
        original-index map and translates every reported index
        back.

Run: python3 -m unittest discover -s tests -v   (from depin/)
Standard library only.
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import depin_cli as cli
import depin_core as core
import depin_scorer as scorer
import ed25519_rfc8032 as ed

SLOT = core.SLOT_SEC
DAY = 86400
SCORED_AT = 1_800_000_000
PROFILE = "test"


def make_bundle_for_seed(seed, start_ts, count, start_number=400000):
    obs = []
    ts = start_ts
    for i in range(count):
        number = start_number + i * 10
        obs.append({
            "timestamp_unix": ts,
            "best_block_number": number,
            "best_block_hash": hashlib.sha256(
                ("v09-%s-%d" % (seed.hex()[:12], number)).encode()
            ).hexdigest(),
            "observed_peers": 9,
            "finalized_block_number": number - 10,
        })
        ts += SLOT
    return core.build_bundle(seed, obs, profile=PROFILE)


def make_bundle(seed_byte, start_ts, count):
    return make_bundle_for_seed(
        bytes([seed_byte]) * 32, start_ts, count)


def device_id_of(bundle):
    return bundle["device_id"]


def run_cli_score(tmp, items, extra_args=()):
    """Write bundle files are the caller's job; here items is the
    submissions list for input.json. Returns (rc, report dict)."""
    input_path = os.path.join(tmp, "input.json")
    with open(input_path, "w", encoding="utf-8") as f:
        json.dump({"submissions": items}, f)
    out_path = os.path.join(tmp, "report.json")
    rc = cli.main(["score", "--input", input_path,
                   "--out", out_path,
                   "--scored-at-unix", str(SCORED_AT),
                   "--profile", PROFILE] + list(extra_args))
    report = None
    if os.path.exists(out_path):
        with open(out_path, "r", encoding="utf-8") as f:
            report = json.load(f)
    return rc, report, out_path


def write_bundle(tmp, name, bundle):
    path = os.path.join(tmp, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(bundle))
    return name


# ------------------------------------------------------------------
# F-01: the CLI drains the deferral queue within one invocation
# ------------------------------------------------------------------

class TestCliDeferralDrain(unittest.TestCase):

    def test_513_bundles_complete_via_cli(self):
        # The audit's scenario: 513 distinct, fully valid
        # 1-checkpoint bundles from 513 distinct devices - one
        # more distinct content key than the 512 safety valve.
        bundles = []
        for i in range(513):
            seed = hashlib.sha256(
                ("f01-device-%d" % i).encode()).digest()
            bundles.append(make_bundle_for_seed(
                seed, SCORED_AT - 40 * DAY, 1,
                start_number=400000 + i * 100))
        with tempfile.TemporaryDirectory() as tmp:
            items = []
            for i, bundle in enumerate(bundles):
                name = write_bundle(tmp, "b%03d.json" % i, bundle)
                items.append({
                    "bundle_path": name,
                    "account": "acct-%d" % i,
                    "submitted_at_unix":
                        bundle["checkpoints"][-1]["timestamp_unix"]
                        + 3600,
                })
            rc, report, _out = run_cli_score(tmp, items)
        self.assertEqual(rc, 0)
        self.assertIsNotNone(report)
        # Every submission resolved: nothing rejected, nothing
        # left deferred, and the invocation reports complete.
        self.assertEqual(report["rejected_submissions"], [])
        self.assertEqual(report["deferred_submissions"], [])
        self.assertTrue(report["summary"]["complete"])
        self.assertEqual(report["summary"]["deferred_count"], 0)
        # All 513 devices scored.
        self.assertEqual(len(report["nodes"]), 513)
        self.assertEqual(report["summary"]["raw_node_count"], 513)
        self.assertEqual(
            {n["device_id"] for n in report["nodes"]},
            {device_id_of(b) for b in bundles})


# ------------------------------------------------------------------
# F-02: a poisoned claimed_device_id cannot destroy the output
# ------------------------------------------------------------------

class TestOutputSurrogateSafety(unittest.TestCase):

    def test_lone_surrogate_device_id_still_produces_report(self):
        good = make_bundle(7, SCORED_AT - 40 * DAY, 4)
        broken = dict(good)
        broken["device_id"] = "\ud800"
        with tempfile.TemporaryDirectory() as tmp:
            good_name = write_bundle(tmp, "good.json", good)
            broken_name = write_bundle(tmp, "broken.json", broken)
            rc, report, out_path = run_cli_score(tmp, [
                {"bundle_path": good_name, "account": "good"},
                {"bundle_path": broken_name, "account": "broken"},
            ])
            # The whole point: writing the report must not raise,
            # and the file must be complete, valid UTF-8 JSON.
            self.assertEqual(rc, 0)
            with open(out_path, "rb") as f:
                raw = f.read()
            self.assertGreater(len(raw), 0)
            text = raw.decode("utf-8")  # must not raise
            report = json.loads(text)
        self.assertIsNotNone(report)
        self.assertEqual(
            [n["device_id"] for n in report["nodes"]],
            [device_id_of(good)])
        self.assertEqual(len(report["rejected_submissions"]), 1)
        entry = report["rejected_submissions"][0]
        self.assertEqual(entry["index"], 1)
        # The echoed claimed id is sanitised, not the raw
        # surrogate: U+FFFD stands where the lone surrogate was.
        self.assertEqual(entry["claimed_device_id"], "�")
        self.assertEqual(report["summary"]["rejected_count"], 1)

    def test_scorer_records_are_sanitised_at_construction(self):
        # Same poison, straight through the scorer API: the
        # returned records themselves must already be clean (the
        # CLI write is only the second line of defence).
        good = make_bundle(8, SCORED_AT - 40 * DAY, 4)
        broken = dict(good)
        broken["device_id"] = "\ud800"
        result = scorer.score_submissions(
            [{"bundle": good, "account": "good",
              "account_age_days": 0, "submitted_at_unix": 0},
             {"bundle": broken, "account": "broken-\ud800",
              "account_age_days": 0, "submitted_at_unix": 0}],
            scored_at_unix=SCORED_AT, profile=PROFILE)
        self.assertEqual(len(result["rejected_submissions"]), 1)
        entry = result["rejected_submissions"][0]
        self.assertEqual(entry["claimed_device_id"], "�")
        self.assertEqual(entry["account"], "broken-�")
        # And the whole result serialises and encodes cleanly.
        text = json.dumps(result, indent=2, ensure_ascii=False)
        text.encode("utf-8")  # must not raise


# ------------------------------------------------------------------
# F-08: reported indices are the ORIGINAL submission positions
# ------------------------------------------------------------------

class TestCliIndexMapping(unittest.TestCase):

    def test_missing_and_empty_report_original_indices(self):
        # The audit's pair: a missing file and a file whose
        # content is {}. Expected rejected indices [0, 1]; the
        # pre-fix CLI reported [0, 0].
        with tempfile.TemporaryDirectory() as tmp:
            empty_path = os.path.join(tmp, "empty.json")
            with open(empty_path, "w", encoding="utf-8") as f:
                f.write("{}")
            rc, report, _out = run_cli_score(tmp, [
                {"bundle_path": "missing.json", "account": "a"},
                {"bundle_path": "empty.json", "account": "b"},
            ])
        self.assertEqual(rc, 0)
        indices = sorted(
            e["index"] for e in report["rejected_submissions"])
        self.assertEqual(indices, [0, 1])
        by_index = {e["index"]: e
                    for e in report["rejected_submissions"]}
        self.assertIn("load error", by_index[0]["reasons"][0])

    def test_deferred_index_points_at_original_after_missing(self):
        # A missing file before a set whose tail submission can
        # never verify (its chain verification keeps raising, so
        # the scorer defers it as interrupted): the deferred
        # entry must carry the ORIGINAL index 2, and the run
        # must terminate provisional instead of looping.
        good = make_bundle(11, SCORED_AT - 40 * DAY, 4)
        stuck = make_bundle(12, SCORED_AT - 40 * DAY, 4)
        orig_chain = core.verify_bundle_chain

        def flaky_chain(bundle, profile="production"):
            if bundle["bundle_hash"] == stuck["bundle_hash"]:
                raise RuntimeError("simulated interrupted verify")
            return orig_chain(bundle, profile=profile)

        with tempfile.TemporaryDirectory() as tmp:
            good_name = write_bundle(tmp, "good.json", good)
            stuck_name = write_bundle(tmp, "stuck.json", stuck)
            with mock.patch.object(core, "verify_bundle_chain",
                                   flaky_chain):
                rc, report, _out = run_cli_score(tmp, [
                    {"bundle_path": "missing.json", "account": "a"},
                    {"bundle_path": good_name, "account": "b"},
                    {"bundle_path": stuck_name, "account": "c"},
                ])
        self.assertEqual(rc, 0)
        self.assertEqual(
            [n["device_id"] for n in report["nodes"]],
            [device_id_of(good)])
        self.assertEqual(len(report["deferred_submissions"]), 1)
        entry = report["deferred_submissions"][0]
        self.assertEqual(entry["index"], 2)
        self.assertEqual(entry["claimed_device_id"],
                         device_id_of(stuck))
        self.assertFalse(report["summary"]["complete"])
        self.assertEqual(report["summary"]["deferred_count"], 1)


if __name__ == "__main__":
    unittest.main()
