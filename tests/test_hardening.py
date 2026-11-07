"""Adversarial tests for the SPEC v0.3 / v0.4 hardening.

Each test reproduces an attack from the independent reviews
of v0.2 and v0.3 (or a regression they imply) and pins the fixed
behaviour:

  C1  participant-chosen interval/iterations minting a full weight
  C2  disqualification framing via re-submission / tampered copies
  H3  closed-cluster evasion via one-directional external mention
  H4  future-dated submission metadata skipping the settlement wait
  H6  Ed25519 weak keys (identity / small order) and the x=0 sign bug
  H8  verifier work budget enforced at schema time
  H9  a broken submission mixed into a batch never aborts scoring
  M1  split submissions of one device merged deterministically
  M2  uppercase (non-canonical) hex cannot dodge duplicate handling
  L1  key files with loose permissions are refused

v0.4 round (review of v0.3):
  C-01 unsigned spot-check response framing the bundle owner
  H-01 time-shifted duplicate bundles inflating settled days
  H-02 freshly minted legacy bundles bypassing current defences
  H-03 one-directional mentions dragging honest pairs into a cap
  H-05 verifier burning chain work after a bundle_hash mismatch
  M-03 one broken submission file aborting the CLI scoring run
  L-02 finalized_block_number range vs its i64 encoding

v0.5 round (re-audit of v0.4): the regressions for R-C01, R-H01,
R-H02, R-M05 and the v0.4-joins-legacy policy live in
tests/test_v05.py. The bundles built by make_bundle below are
format v0.5; tests that pin a historical format say so explicitly.

Run: python3 -m unittest discover -s tests -v   (from the depin/ dir)
"""

import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import depin_core as core
import depin_scorer as scorer
import ed25519_rfc8032 as ed

SLOT = core.SLOT_SEC
DAY = 86400
SCORED_AT = 1_800_000_000
PROFILE = "test"


def make_bundle(seed_byte, start_ts, count, step=SLOT, lag=10,
                witnesses=None, start_number=400000):
    seed = bytes([seed_byte]) * 32
    obs = []
    ts = start_ts
    for i in range(count):
        number = start_number + i * 10
        o = {
            "timestamp_unix": ts,
            "best_block_number": number,
            "best_block_hash": hashlib.sha256(
                ("hblk-%d-%d" % (seed_byte, number)).encode()).hexdigest(),
            "observed_peers": 9,
            "finalized_block_number": number - lag,
        }
        if witnesses:
            o["witness_peers"] = witnesses
        obs.append(o)
        ts += step
    return core.build_bundle(seed, obs, version="0.5", profile=PROFILE)


def submission(bundle, account, submitted_at=None):
    # v0.8 max-rule: unspecified means "submitted promptly", one
    # hour after the bundle's last checkpoint (see test_scorer).
    if submitted_at is None:
        submitted_at = bundle["checkpoints"][-1]["timestamp_unix"] + 3600
    return {"bundle": bundle, "account": account,
            "account_age_days": 0, "submitted_at_unix": submitted_at}


def score(subs, **kw):
    kw.setdefault("scored_at_unix", SCORED_AT)
    kw.setdefault("profile", PROFILE)
    return scorer.score_submissions(subs, **kw)


def node_by_id(result, device_id):
    for n in result["nodes"]:
        if n["device_id"] == device_id:
            return n
    raise AssertionError("node %s missing" % device_id)


class TestC1FixedParameters(unittest.TestCase):
    def test_legacy_single_checkpoint_year_interval_is_not_scored(
            self):
        # The v0.2 C1 reproduction (one checkpoint claiming a
        # 365-day interval), replayed under the v0.4 version policy
        # (H-02): a legacy bundle is not scored at all, whatever
        # weight any historical rule would have given it. It is
        # rejected unattributed, with the reason recorded.
        seed = bytes([77]) * 32
        obs = [{
            "timestamp_unix": SCORED_AT - 40 * DAY,
            "best_block_number": 400000,
            "best_block_hash": hashlib.sha256(b"c1-blk").hexdigest(),
            "observed_peers": 9,
            "finalized_block_number": 400000 - 10,
        }]
        bundle = core.build_bundle(
            seed, obs, iterations=100, interval_sec=365 * DAY,
            version="0.2")
        result = score([submission(bundle, "c1-attacker")])
        self.assertEqual(result["nodes"], [])
        self.assertEqual(result["summary"]["rejected_count"], 1)
        self.assertIn("not scored",
                      result["rejected_submissions"][0]["reasons"][0])

    def test_v05_profile_mismatch_rejected(self):
        bundle = make_bundle(78, SCORED_AT - 40 * DAY, 8)
        # Built under the test profile; production verification (the
        # default) must refuse it - the participant cannot pick the
        # cheap parameter set for production scoring.
        ok, errors = core.verify_bundle(bundle)
        self.assertFalse(ok)
        self.assertTrue(any("profile" in e for e in errors), errors)
        ok, errors = core.verify_bundle(bundle, profile=PROFILE)
        self.assertTrue(ok, errors)

    def test_builder_refuses_free_parameters_for_v05(self):
        obs = [{
            "timestamp_unix": SCORED_AT - 40 * DAY,
            "best_block_number": 400000,
            "best_block_hash": hashlib.sha256(b"x").hexdigest(),
            "observed_peers": 9,
        }]
        with self.assertRaises(ValueError):
            core.build_bundle(bytes([79]) * 32, obs, iterations=12345,
                              version="0.5", profile=PROFILE)
        with self.assertRaises(ValueError):
            core.build_bundle(bytes([79]) * 32, obs, interval_sec=99999,
                              version="0.5", profile=PROFILE)


class TestC2Framing(unittest.TestCase):
    def test_uppercase_hex_copy_rejected_victim_unaffected(self):
        # M2/C2: resubmitting the victim's bundle with the bundle_hash
        # uppercased must neither count as a second bundle nor frame
        # the victim; canonical-form schema rejects it, unattributed.
        victim = make_bundle(88, SCORED_AT - 40 * DAY, 48)
        evil = copy.deepcopy(victim)
        evil["bundle_hash"] = evil["bundle_hash"].upper()
        result = score([submission(victim, "victim"),
                        submission(evil, "attacker")])
        n = node_by_id(result, victim["device_id"])
        self.assertEqual(n["status"], "ok")
        self.assertGreater(n["adjusted_weight"], 0.0)
        self.assertEqual(result["summary"]["rejected_count"], 1)
        self.assertEqual(result["summary"]["duplicates_ignored"], 0)

    def test_resubmission_under_other_account_is_still_idempotent(self):
        victim = make_bundle(89, SCORED_AT - 40 * DAY, 48)
        result = score([submission(victim, "victim"),
                        submission(victim, "attacker-account")])
        self.assertEqual(len(result["nodes"]), 1)
        self.assertEqual(result["nodes"][0]["status"], "ok")
        self.assertEqual(result["summary"]["duplicates_ignored"], 1)
        self.assertEqual(result["summary"]["disqualified_count"], 0)


class TestH3OneDirectionalEvasion(unittest.TestCase):
    def test_external_mention_without_reciprocation_still_capped(self):
        # Farm of 5 mutually witnessing nodes; one of them also
        # *claims* to witness an honest outsider who never mentions
        # them back. Under v0.2 this opened the cluster and dodged
        # the cap; closedness is now judged on mutual edges only.
        honest = make_bundle(90, SCORED_AT - 60 * DAY, 30 * 144)
        farm_seeds = [91, 92, 93, 94, 95]
        farm_ids = [core.device_id_from_pubkey(
            ed.publickey_from_seed(bytes([s]) * 32)) for s in farm_seeds]
        farm = []
        for s in farm_seeds:
            witnesses = list(farm_ids)
            if s == 91:
                witnesses.append(honest["device_id"])  # one-directional
            farm.append(make_bundle(
                s, SCORED_AT - 11 * DAY, 144, witnesses=witnesses,
                start_number=500000))
        subs = [submission(honest, "honest")]
        subs += [submission(b, "farm-%d" % s)
                 for s, b in zip(farm_seeds, farm)]
        result = score(subs)
        for b in farm:
            n = node_by_id(result, b["device_id"])
            self.assertTrue(
                any(f.startswith("closed_cluster_discount")
                    for f in n["flags"]),
                "farm node %s escaped the cluster cap" % b["device_id"])
            self.assertAlmostEqual(n["adjusted_weight"], 0.4, places=6)
        h = node_by_id(result, honest["device_id"])
        self.assertFalse(any(f.startswith("closed_cluster_discount")
                             for f in h["flags"]))
        self.assertGreater(h["adjusted_weight"], 5.0)


class TestH4TrustedScoringTime(unittest.TestCase):
    def test_future_submission_metadata_cannot_skip_settlement(self):
        # Bundle ends 1 day before scoring time (inside the 7-day
        # settlement wait). A submitted_at a year in the future must
        # not settle it: scored_at comes only from the caller.
        bundle = make_bundle(96, SCORED_AT - 2 * DAY, 144)
        sub = submission(bundle, "impatient",
                         submitted_at=SCORED_AT + 365 * DAY)
        result = score([sub])
        n = result["nodes"][0]
        self.assertEqual(n["adjusted_weight"], 0.0)
        self.assertTrue(any(f.startswith("settlement_pending")
                            for f in n["flags"]))


class TestH6WeakKeys(unittest.TestCase):
    def test_identity_key_forgery_rejected(self):
        # Classic small-order forgery: for A = identity, [k]A is the
        # identity, so choosing R = [S]B satisfies the verification
        # equation for any S. Must be rejected by the small-order
        # check, not by luck.
        identity_pk = bytes.fromhex("01" + "00" * 31)
        msg = b"forged message"
        S = 12345
        R_enc = ed._encode_point(ed._scalarmult(ed._B, S))
        sig = R_enc + S.to_bytes(32, "little")
        self.assertFalse(ed.verify(identity_pk, msg, sig))

    def test_order2_key_forgery_rejected(self):
        # A = point of order 2 (y = 0 encoding). [k]A is identity for
        # even k, so iterating S until k is even forges a signature
        # unless small-order keys are rejected.
        pk = bytes(32)  # y = 0, an order-2 point encoding
        msg = b"forged message"
        forged = None
        for S in range(1, 200):
            R_enc = ed._encode_point(ed._scalarmult(ed._B, S))
            k = ed._hint(R_enc + pk + msg) % ed._l
            if k % 2 == 0:
                forged = R_enc + S.to_bytes(32, "little")
                break
        self.assertIsNotNone(forged)
        self.assertFalse(ed.verify(pk, msg, forged))

    def test_x_zero_negative_zero_encoding_rejected(self):
        # y = 1 with the sign bit set is the non-canonical "negative
        # zero" identity encoding; decoding must raise (H6 bug fix).
        bad = bytearray(bytes.fromhex("01" + "00" * 31))
        bad[31] |= 0x80
        with self.assertRaises(ValueError):
            ed._decode_point(bytes(bad))
        self.assertFalse(ed.verify(bytes(bad), b"m", bytes(64)))

    def test_small_order_R_rejected(self):
        seed = bytes(range(1, 33))
        pk = ed.publickey_from_seed(seed)
        sig = bytearray(ed.sign(seed, b"m"))
        sig[:32] = bytes.fromhex("01" + "00" * 31)  # R = identity
        self.assertFalse(ed.verify(pk, b"m", bytes(sig)))


class TestH8WorkBudget(unittest.TestCase):
    def test_legacy_work_bomb_rejected_at_schema(self):
        # A legacy bundle claiming 5M iterations x 100 checkpoints
        # (500M total > budget) must be refused during schema
        # validation, before any chain recomputation happens.
        bundle = make_bundle(97, SCORED_AT - 40 * DAY, 4)
        legacy = copy.deepcopy(bundle)
        legacy["version"] = "0.2"
        legacy["params"]["iterations_per_checkpoint"] = 5_000_000
        for cp in legacy["checkpoints"]:
            cp["iterations"] = 5_000_000
        legacy["checkpoints"] = legacy["checkpoints"] * 25
        ok, errors = core.verify_bundle(legacy)
        self.assertFalse(ok)
        self.assertTrue(any("budget" in e for e in errors), errors)


class TestH9BatchIsolation(unittest.TestCase):
    def test_broken_submissions_do_not_abort_scoring(self):
        honest = make_bundle(98, SCORED_AT - 40 * DAY, 96)
        subs = [
            "not-a-dict",
            {"account": "no-bundle-here"},
            {"bundle": {"format": "quantus-depin-proof",
                        "version": "0.4",
                        "checkpoints": "not-a-list"},
             "account": "garbage"},
            {"bundle": None, "account": "none-bundle"},
            submission(honest, "honest"),
        ]
        result = score(subs)
        n = node_by_id(result, honest["device_id"])
        self.assertEqual(n["status"], "ok")
        self.assertGreater(n["adjusted_weight"], 0.0)
        self.assertGreaterEqual(result["summary"]["rejected_count"], 3)


class TestM1Merge(unittest.TestCase):
    def test_split_bundles_merge_to_full_weight(self):
        start = SCORED_AT - 40 * DAY
        part_a = make_bundle(99, start, 288)
        part_b = make_bundle(99, start + 288 * SLOT, 288,
                             start_number=400000 + 288 * 10)
        whole = make_bundle(99, start, 576)
        merged = score([submission(part_a, "dev"),
                        submission(part_b, "dev")])
        single = score([submission(whole, "dev")])
        m = node_by_id(merged, part_a["device_id"])
        s = node_by_id(single, whole["device_id"])
        self.assertEqual(m["metrics"]["bundles_merged"], 2)
        self.assertEqual(m["metrics"]["checkpoints"], 576)
        self.assertAlmostEqual(m["adjusted_weight"],
                               s["adjusted_weight"], places=9)

    def test_overlapping_periods_not_double_counted(self):
        start = SCORED_AT - 40 * DAY
        part_a = make_bundle(100, start, 288)
        overlap = make_bundle(100, start + 144 * SLOT, 288,
                              start_number=400000 + 144 * 10)
        result = score([submission(part_a, "dev"),
                        submission(overlap, "dev")])
        n = node_by_id(result, part_a["device_id"])
        # Union of timestamps: 288 + 144 new ones.
        self.assertEqual(n["metrics"]["checkpoints"], 432)


class TestL1KeyPermissions(unittest.TestCase):
    def test_load_key_refuses_loose_permissions(self):
        import depin_cli as cli
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "key.json")
            cli._save_key(path, bytes([42]) * 32)
            os.chmod(path, 0o644)
            with self.assertRaises(ValueError):
                cli._load_key(path)
            os.chmod(path, 0o600)
            self.assertEqual(cli._load_key(path), bytes([42]) * 32)


class TestH2ChainBinding(unittest.TestCase):
    def test_v04_chain_binds_pubkey_and_slot(self):
        # This test pins the LEGACY v0.4 format explicitly (its
        # byte contract must not drift, so archived v0.4 bundles
        # keep verifying under allow_legacy).
        ts = SCORED_AT - 40 * DAY
        obs = [{
            "timestamp_unix": ts,
            "best_block_number": 400000,
            "best_block_hash": hashlib.sha256(b"bind").hexdigest(),
            "observed_peers": 9,
            "finalized_block_number": 400000 - 10,
        }]
        bundle = core.build_bundle(bytes([111]) * 32, obs,
                                   version="0.4", profile=PROFILE)
        cp = bundle["checkpoints"][0]
        pubkey = bytes.fromhex(bundle["pubkey"])
        other = ed.publickey_from_seed(bytes([112]) * 32)
        block_hash = bytes.fromhex(cp["best_block_hash"])
        slot = ts // SLOT
        state = core.sequential_chain_v04(
            core.ZERO32, block_hash, 0, 400000, cp["iterations"],
            pubkey, slot, 400000 - 10, 9)
        self.assertEqual(state.hex(), cp["chain_state"])
        # A different identity cannot reuse the computed segment.
        state_other = core.sequential_chain_v04(
            core.ZERO32, block_hash, 0, 400000, cp["iterations"],
            other, slot, 400000 - 10, 9)
        self.assertNotEqual(state_other.hex(), cp["chain_state"])
        # Nor can the same segment be re-timestamped into another
        # slot (the v0.4 addition behind H-01).
        state_other_slot = core.sequential_chain_v04(
            core.ZERO32, block_hash, 0, 400000, cp["iterations"],
            pubkey, slot + 1, 400000 - 10, 9)
        self.assertNotEqual(state_other_slot.hex(), cp["chain_state"])


# ------------------------------------------------------------------
# v0.4 round: regressions for the review of v0.3
# ------------------------------------------------------------------

class TestH01SlotDeduplication(unittest.TestCase):
    def test_time_shifted_copies_do_not_inflate_settled_days(self):
        # The v0.3 H-01 reproduction, replayed against the fix:
        # one settled day (144 checkpoints) expanded into 600
        # bundles shifted by 0..599 seconds scored, in v0.3, 600
        # settled days and weight 19.1050 (the maturity cap). With
        # slot-index deduplication in the scorer (and the slot bound
        # into the v0.4 chain seed), all copies collapse onto the
        # same 144 slots. Measured on the fixed implementation:
        # 144 merged checkpoints, settled_days exactly 1.0, weight
        # exactly 1.0 - the honest single-day values.
        start = SCORED_AT - 10 * DAY
        variants = [make_bundle(120, start + s, 144)
                    for s in range(600)]
        result = score([submission(b, "attacker") for b in variants])
        n = node_by_id(result, variants[0]["device_id"])
        self.assertEqual(n["metrics"]["checkpoints"], 144)
        self.assertAlmostEqual(n["metrics"]["settled_days"], 1.0,
                               places=6)
        self.assertAlmostEqual(n["adjusted_weight"], 1.0, places=6)


class TestH02LegacyVersionPolicy(unittest.TestCase):
    def _legacy_v03_bundle(self):
        obs = [{
            "timestamp_unix": SCORED_AT - 40 * DAY,
            "best_block_number": 400000,
            "best_block_hash": hashlib.sha256(b"legacy").hexdigest(),
            "observed_peers": 9,
            "finalized_block_number": 400000 - 10,
        }]
        return core.build_bundle(bytes([121]) * 32, obs,
                                 version="0.3", profile=PROFILE)

    def test_v03_bundle_rejected_by_default(self):
        legacy = self._legacy_v03_bundle()
        ok, errors = core.verify_bundle(legacy, profile=PROFILE)
        self.assertFalse(ok)
        self.assertTrue(any("legacy" in e for e in errors), errors)

    def test_v03_bundle_verifies_with_allow_legacy(self):
        # Archival verification remains available, explicitly.
        legacy = self._legacy_v03_bundle()
        ok, errors = core.verify_bundle(legacy, profile=PROFILE,
                                        allow_legacy=True)
        self.assertTrue(ok, errors)

    def test_scorer_rejects_legacy_bundle_unattributed(self):
        legacy = self._legacy_v03_bundle()
        result = score([submission(legacy, "legacy-user")])
        self.assertEqual(result["nodes"], [])
        self.assertEqual(result["summary"]["disqualified_count"], 0)
        self.assertEqual(result["summary"]["rejected_count"], 1)
        self.assertIn("not scored",
                      result["rejected_submissions"][0]["reasons"][0])


class TestH03MutualOnlyComponents(unittest.TestCase):
    def test_one_directional_mention_does_not_drag_honest_pairs(self):
        # The v0.3 H-03 reproduction, replayed: two honest mutual
        # pairs (A<->B, C<->D) and an attacker X who merely mentions
        # A and C one-directionally. In v0.3 the claimed-graph
        # component merged all five devices and halved the honest
        # weights (measured 0.2635 -> 0.1318). With mutual-only
        # components, X belongs to no component and the pairs are
        # untouched: a pair's total (2W) does not exceed the 2.0x
        # cap on its strongest member, so no discount applies.
        seeds = {"A": 131, "B": 132, "C": 133, "D": 134, "X": 135}
        ids = {k: core.device_id_from_pubkey(
            ed.publickey_from_seed(bytes([s]) * 32))
            for k, s in seeds.items()}

        def wb(key, witnesses):
            return make_bundle(seeds[key], SCORED_AT - 10 * DAY, 10,
                               witnesses=witnesses)

        a, b = wb("A", [ids["B"]]), wb("B", [ids["A"]])
        c, d = wb("C", [ids["D"]]), wb("D", [ids["C"]])
        x = wb("X", [ids["A"], ids["C"]])
        control = score([submission(a, "a"), submission(b, "b"),
                         submission(c, "c"), submission(d, "d")])
        attacked = score([submission(a, "a"), submission(b, "b"),
                          submission(c, "c"), submission(d, "d"),
                          submission(x, "x")])
        for key, bundle in (("A", a), ("B", b), ("C", c), ("D", d)):
            n0 = node_by_id(control, bundle["device_id"])
            n1 = node_by_id(attacked, bundle["device_id"])
            self.assertAlmostEqual(n0["adjusted_weight"],
                                   n1["adjusted_weight"], places=9)
            self.assertGreater(n1["adjusted_weight"], 0.0)
            self.assertFalse(any(
                f.startswith("closed_cluster_discount")
                for f in n1["flags"]), n1["flags"])


class TestH05FailFastVerification(unittest.TestCase):
    def test_bundle_hash_tamper_never_recomputes_chain(self):
        # v0.3 H-05: after a bundle_hash mismatch the verifier kept
        # going and recomputed the whole chain whenever the (public,
        # genuine) signature still verified. Instrument the chain
        # function: a tampered bundle must now fail with the single
        # bundle_hash error and zero chain calls.
        bundle = make_bundle(122, SCORED_AT - 40 * DAY, 8)
        tampered = copy.deepcopy(bundle)
        tampered["created_at_unix"] += 1  # breaks bundle_hash only
        calls = []
        orig = core.sequential_chain_v05

        def counting(*a, **kw):
            calls.append(1)
            return orig(*a, **kw)

        core.sequential_chain_v05 = counting
        try:
            ok, errors = core.verify_bundle(tampered, profile=PROFILE)
        finally:
            core.sequential_chain_v05 = orig
        self.assertFalse(ok)
        self.assertEqual(errors, ["bundle_hash recomputation mismatch"])
        self.assertEqual(calls, [])


class TestM03CliLoadIsolation(unittest.TestCase):
    def test_broken_submission_files_do_not_abort_cli_scoring(self):
        # v0.3 M-03: cmd_score loaded every bundle file up front
        # with no isolation, so one missing/corrupt file killed the
        # run before scoring started.
        import depin_cli as cli
        good = make_bundle(123, SCORED_AT - 40 * DAY, 24)
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "good.json"), "w") as f:
                json.dump(good, f)
            with open(os.path.join(td, "bad.json"), "w") as f:
                f.write("{not json")
            subs_path = os.path.join(td, "subs.json")
            with open(subs_path, "w") as f:
                json.dump({"submissions": [
                    {"bundle_path": "missing.json", "account": "ghost"},
                    {"bundle_path": "bad.json", "account": "broken"},
                    {"account": "no-path-at-all"},
                    {"bundle_path": "good.json", "account": "honest"},
                ]}, f)
            out_path = os.path.join(td, "out.json")
            rc = cli.main(["score", "--input", subs_path,
                           "--out", out_path, "--profile", PROFILE,
                           "--scored-at-unix", str(SCORED_AT)])
            self.assertEqual(rc, 0)
            with open(out_path) as f:
                result = json.load(f)
        self.assertEqual(len(result["nodes"]), 1)
        self.assertEqual(result["nodes"][0]["device_id"],
                         good["device_id"])
        self.assertGreater(result["nodes"][0]["adjusted_weight"], 0.0)
        self.assertGreaterEqual(result["summary"]["rejected_count"], 3)
        self.assertTrue(any(
            "load error" in reason
            for rej in result["rejected_submissions"]
            for reason in rej["reasons"]),
            result["rejected_submissions"])


class TestL02FinalizedRange(unittest.TestCase):
    def test_finalized_at_2_to_the_63_is_rejected_not_crashing(self):
        # v0.3 L-02: the schema allowed finalized_block_number up
        # to 2**64 - 1 while the checkpoint-hash encoding packs it
        # as i64, so this input died with struct.error inside
        # verification instead of returning errors. The schema range
        # now matches the encoding (max 2**63 - 1).
        bundle = make_bundle(124, SCORED_AT - 40 * DAY, 4)
        bundle["checkpoints"][0]["finalized_block_number"] = 2**63
        ok, errors = core.verify_bundle(bundle, profile=PROFILE)
        self.assertFalse(ok)
        self.assertTrue(any("finalized_block_number" in e
                            for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
