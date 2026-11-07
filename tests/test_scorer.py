"""Attack-simulation and scoring tests for the SPEC v0.5 aggregator.

Run: python3 -m unittest discover -s tests -v   (from the depin/ directory)
Standard library only.

Changes reflected here (intentional spec changes, see SPEC v0.5
and the progress memos):
  * bundles are built as format v0.5 under the "test" parameter
    profile; the checkpoint step is the fixed slot (600 s) and
    counts are in checkpoints, because earned days now come only
    from gate-passing checkpoint counts x the fixed slot (C1)
  * re-submitting an identical bundle is idempotent, not a
    disqualification (C2)
  * an invalid bundle is rejected unattributed and disqualifies
    nobody (C2)
  * spot checks disqualify only against operator-trusted
    expectations supplied separately (H7), and only when the
    response is owner-signed under spot protocol v2 (C-01 /
    R-C01 / R-M05; see TestSpotChecks)
"""

import hashlib
import os
import sys
import unittest

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import depin_core as core
import depin_scorer as scorer

SLOT = core.SLOT_SEC
HOUR = 3600
DAY = 86400
SCORED_AT = 1_800_000_000  # fixed scoring time for determinism
PROFILE = "test"


def make_bundle(seed_byte, start_ts, count, step=SLOT, lag=10,
                witnesses=None, start_number=400000):
    """Build a v0.5 bundle (test profile) from synthetic observations.

    step: seconds between consecutive observation timestamps. Making
    step > SLOT models missing checkpoints (gaps): coverage falls.
    """
    seed = bytes([seed_byte]) * 32
    obs = []
    ts = start_ts
    for i in range(count):
        number = start_number + i * 10
        o = {
            "timestamp_unix": ts,
            "best_block_number": number,
            "best_block_hash": hashlib.sha256(
                ("blk-%d-%d" % (seed_byte, number)).encode()).hexdigest(),
            "observed_peers": 9,
            "finalized_block_number": number - lag,
        }
        if witnesses:
            o["witness_peers"] = witnesses
        obs.append(o)
        ts += step
    return core.build_bundle(seed, obs, version="0.5", profile=PROFILE)


def submission(bundle, account, age_days, submitted_at=None):
    # v0.8 max-rule: an unspecified submitted_at means "submitted
    # promptly", i.e. one hour after the bundle's last checkpoint.
    # (submitted_at = scored_at for a whole history would, under
    # max(recorded, first-seen), anchor every checkpoint at the
    # scoring instant and collapse its effective span.)
    if submitted_at is None:
        submitted_at = bundle["checkpoints"][-1]["timestamp_unix"] + 3600
    return {
        "bundle": bundle,
        "account": account,
        "account_age_days": age_days,
        "submitted_at_unix": submitted_at,
    }


def score(subs, **kw):
    kw.setdefault("scored_at_unix", SCORED_AT)
    kw.setdefault("profile", PROFILE)
    return scorer.score_submissions(subs, **kw)


def node_by_id(result, device_id):
    for n in result["nodes"]:
        if n["device_id"] == device_id:
            return n
    raise AssertionError("node %s missing" % device_id)


class TestHonestBeatsFarm(unittest.TestCase):
    """One honest long-lived node outweighs a fresh 50-node Sybil farm
    that only witnesses itself (closed cluster) and started together."""

    @classmethod
    def setUpClass(cls):
        # Honest node: 180 days at the fixed 600 s slot, ended 30
        # days ago. Witnesses one outside (non-participant) peer, so
        # it is not part of any closed cluster. Submission account
        # ages below are deliberately varied (400 vs 11 days) but
        # must not matter: the time wall is participation maturity
        # alone.
        cls.honest = make_bundle(
            7, SCORED_AT - 210 * DAY, 180 * 144,
            witnesses=["external-peer-not-a-participant"])
        # Farm: 50 nodes, each 1 day at the fixed slot, started 11
        # days ago at the same instant, witnessing only each other.
        cls.farm = []
        farm_ids = []
        seeds = list(range(50, 100))
        # device_ids are needed before building (witness lists), so
        # derive them from the seeds first.
        import ed25519_rfc8032 as ed
        for s in seeds:
            pk = ed.publickey_from_seed(bytes([s]) * 32)
            farm_ids.append(core.device_id_from_pubkey(pk))
        for s in seeds:
            others = [d for d in farm_ids]
            cls.farm.append(make_bundle(
                s, SCORED_AT - 11 * DAY, 144, witnesses=others))
        subs = [submission(cls.honest, "honest-gh", 400)]
        subs += [submission(b, "farm-%d" % i, 11)
                 for i, b in enumerate(cls.farm)]
        cls.result = score(subs)

    def test_honest_outweighs_whole_farm(self):
        honest_id = self.honest["device_id"]
        honest_w = node_by_id(self.result, honest_id)["adjusted_weight"]
        farm_total = sum(
            n["adjusted_weight"] for n in self.result["nodes"]
            if n["device_id"] != honest_id)
        self.assertGreater(honest_w, farm_total,
                           "honest %.4f should exceed farm total %.4f"
                           % (honest_w, farm_total))
        self.assertGreater(honest_w, 10.0)

    def test_farm_flagged_and_cluster_capped(self):
        flagged = [n for n in self.result["nodes"]
                   if any(f.startswith("closed_cluster_discount")
                          for f in n["flags"])]
        self.assertEqual(len(flagged), 50)
        sync = [n for n in self.result["nodes"]
                if any(f.startswith("synchronized_start")
                       for f in n["flags"])]
        self.assertEqual(len(sync), 50)
        # raw count still shows all 51 nodes; the adjusted view is what
        # shrinks the farm.
        self.assertEqual(self.result["summary"]["raw_node_count"], 51)
        self.assertEqual(
            self.result["summary"]["closed_clusters_capped"], 1)


class TestRejectionAndDuplicates(unittest.TestCase):
    """C2: framing is impossible. Invalid bundles are rejected
    unattributed; duplicates are idempotent."""

    def test_duplicate_submission_is_idempotent(self):
        bundle = make_bundle(201, SCORED_AT - 40 * DAY, 48)
        subs = [submission(bundle, "alice", 300),
                submission(bundle, "bob", 300)]
        result = score(subs)
        self.assertEqual(len(result["nodes"]), 1)
        n = result["nodes"][0]
        self.assertEqual(n["status"], "ok")
        self.assertEqual(n["raw_count"], 1)
        self.assertGreater(n["adjusted_weight"], 0.0)
        self.assertEqual(result["summary"]["duplicates_ignored"], 1)

    def test_invalid_bundle_rejected_without_attribution(self):
        bundle = make_bundle(202, SCORED_AT - 40 * DAY, 48)
        bundle["checkpoints"][3]["observed_peers"] = 999  # breaks hashes
        result = score([submission(bundle, "mallory", 300)])
        # No node is created for the claimed identity, nobody is
        # disqualified, and the rejection is recorded unattributed.
        self.assertEqual(result["nodes"], [])
        self.assertEqual(result["summary"]["disqualified_count"], 0)
        self.assertEqual(result["summary"]["rejected_count"], 1)
        rej = result["rejected_submissions"][0]
        self.assertEqual(rej["claimed_device_id"], bundle["device_id"])

    def test_tampered_copy_does_not_frame_victim(self):
        victim = make_bundle(204, SCORED_AT - 40 * DAY, 48)
        tampered = make_bundle(204, SCORED_AT - 40 * DAY, 48)
        tampered["checkpoints"][0]["observed_peers"] = 12345
        subs = [submission(victim, "victim", 300),
                submission(tampered, "attacker", 1)]
        result = score(subs)
        n = node_by_id(result, victim["device_id"])
        self.assertEqual(n["status"], "ok")
        self.assertGreater(n["adjusted_weight"], 0.0)
        self.assertEqual(result["summary"]["rejected_count"], 1)


def signed_spot_record(bundle, seed_byte, challenge, target, value,
                       revision=0):
    """Build an owner-signed spot-check record (protocol v2): the
    signature is made with the bundle's own device seed over the
    v0.5 spot-response message (target_seq and revision bound),
    exactly as a real participant's app would produce it."""
    seed = bytes([seed_byte]) * 32
    sig = core.sign_spot_response(
        seed, bytes.fromhex(bundle["bundle_hash"]), challenge,
        value, target, revision=revision)
    return {
        "challenge_block_hash": challenge.hex(),
        "target_seq": target,
        "revision": revision,
        "response": value.hex(),
        "signature": sig.hex(),
    }


class TestSpotChecks(unittest.TestCase):
    """H7: expectations come only from the operator's trusted
    channel, never from the submission record. C-01: only
    owner-signed responses are evaluated at all (protocol v2
    since v0.5: mandatory signed target_seq + revision)."""

    def _bundle_and_spot(self, seed_byte=203):
        bundle = make_bundle(seed_byte, SCORED_AT - 40 * DAY, 48)
        challenge = hashlib.sha256(b"future-finalized-block").digest()
        target = scorer.derive_spot_target_index(
            len(bundle["checkpoints"]), challenge)
        good_value = scorer.spot_response_value(
            bytes.fromhex(
                bundle["checkpoints"][target]["best_block_hash"]),
            b"synthetic-block-body")
        return bundle, challenge, target, good_value

    def _expectations(self, bundle, challenge, good_value):
        return {
            bundle["bundle_hash"]: {
                "challenge_block_hash": challenge.hex(),
                "expected": good_value.hex(),
            },
        }

    def test_signed_failure_disqualifies_with_trusted_expectation(
            self):
        bundle, challenge, target, good_value = self._bundle_and_spot()
        sub = submission(bundle, "cheater", 300)
        sub["spot_check"] = signed_spot_record(
            bundle, 203, challenge, target,
            hashlib.sha256(b"wrong").digest())
        result = score(
            [sub],
            spot_expectations=self._expectations(
                bundle, challenge, good_value))
        n = result["nodes"][0]
        self.assertEqual(n["status"], "disqualified")
        self.assertTrue(any("spot check" in r
                            for r in n["disqualify_reasons"]))

    def test_signed_spot_check_passes_with_trusted_expectation(self):
        bundle, challenge, target, good_value = self._bundle_and_spot()
        sub = submission(bundle, "honest", 300)
        sub["spot_check"] = signed_spot_record(
            bundle, 203, challenge, target, good_value)
        result = score(
            [sub],
            spot_expectations=self._expectations(
                bundle, challenge, good_value))
        n = result["nodes"][0]
        self.assertEqual(n["status"], "ok")
        self.assertEqual(n["spot_check"], "passed")

    def test_unsigned_response_never_disqualifies(self):
        # The v0.3 C-01 reproduction, replayed: an attacker attaches
        # an unsigned bogus response to a copy of the victim's
        # bundle. In v0.3 this disqualified the victim; now the
        # record is ignored (flagged) and the victim is untouched.
        bundle, challenge, target, good_value = self._bundle_and_spot()
        sub = submission(bundle, "attacker", 1)
        sub["spot_check"] = {"response": "00"}  # no signature at all
        result = score(
            [sub],
            spot_expectations=self._expectations(
                bundle, challenge, good_value))
        n = result["nodes"][0]
        self.assertEqual(n["status"], "ok")
        self.assertGreater(n["adjusted_weight"], 0.0)
        self.assertTrue(any("unsigned" in f for f in n["flags"]),
                        n["flags"])

    def test_later_signed_response_overrides_earlier_unsigned(self):
        # Attacker's unsigned forgery arrives FIRST (attached to a
        # copy of the victim's bundle); the victim's genuine signed
        # response arrives later on a duplicate submission. Bundle
        # dedupe must not swallow the genuine response.
        bundle, challenge, target, good_value = self._bundle_and_spot()
        evil = submission(bundle, "attacker", 1)
        evil["spot_check"] = {"response": "00"}
        genuine = submission(bundle, "victim", 300)
        genuine["spot_check"] = signed_spot_record(
            bundle, 203, challenge, target, good_value)
        result = score(
            [evil, genuine],
            spot_expectations=self._expectations(
                bundle, challenge, good_value))
        n = result["nodes"][0]
        self.assertEqual(n["status"], "ok")
        self.assertEqual(n["spot_check"], "passed")
        self.assertEqual(result["summary"]["duplicates_ignored"], 1)

    def test_submission_carried_expectation_is_never_trusted(self):
        # Even with a wrong response AND a self-supplied "expected",
        # without an operator-trusted expectation nothing happens:
        # the spot check is recorded as not evaluated.
        bundle, challenge, target, good_value = self._bundle_and_spot()
        sub = submission(bundle, "mallory", 300)
        sub["spot_check"] = {
            "challenge_block_hash": challenge.hex(),
            "target_seq": target,
            "response": hashlib.sha256(b"wrong").hexdigest(),
            "expected": good_value.hex(),
        }
        result = score([sub])
        n = result["nodes"][0]
        self.assertEqual(n["status"], "ok")
        self.assertEqual(n["spot_check"], "not_evaluated")
        self.assertGreater(n["adjusted_weight"], 0.0)


class TestDecayAndGate(unittest.TestCase):
    def test_gappy_node_weight_visibly_decays(self):
        start = SCORED_AT - 40 * DAY
        dense = make_bundle(211, start, 30 * 144)
        # Same 30-day span, but a checkpoint only every 4 slots:
        # coverage 0.25. The sparse history is submitted
        # INCREMENTALLY - six 5-day bundles, each sent promptly
        # (the submission() default) - as a live participant's
        # submissions would arrive. This matters under the v0.8
        # first-seen rule (max(recorded, first seen)): a history
        # delivered in ONE batch is witnessed at a single
        # instant, its internal gaps are unverifiable by the
        # aggregation, and only the checkpoint count decays the
        # weight (that alone would give exactly sqrt(1/4) =
        # 0.5x here). Incremental arrival preserves the
        # witnessed span, so the coverage decay applies.
        subs = [submission(dense, "dense", 400)]
        sparse_id = None
        for k in range(6):
            part = make_bundle(212, start + k * 720 * SLOT,
                               180, step=4 * SLOT)
            sparse_id = part["device_id"]
            subs.append(submission(part, "sparse", 400))
        result = score(subs)
        d = node_by_id(result, dense["device_id"])["adjusted_weight"]
        s = node_by_id(result, sparse_id)["adjusted_weight"]
        self.assertGreater(d, 0.0)
        self.assertLess(s, 0.5 * d,
                        "sparse %.4f should be well under dense %.4f"
                        % (s, d))

    def test_quality_gate_invalidates_lagging_segments(self):
        start = SCORED_AT - 40 * DAY
        clean = make_bundle(221, start, 96, lag=10)
        lagging = make_bundle(222, start, 96,
                              lag=scorer.MAX_FINALIZED_LAG + 500)
        subs = [submission(clean, "clean", 400),
                submission(lagging, "lagging", 400)]
        result = score(subs)
        c = node_by_id(result, clean["device_id"])
        g = node_by_id(result, lagging["device_id"])
        self.assertEqual(g["metrics"]["gate_passing_checkpoints"], 0)
        self.assertEqual(g["adjusted_weight"], 0.0)
        self.assertGreater(c["adjusted_weight"], 0.0)
        self.assertEqual(c["metrics"]["gate_passing_checkpoints"], 96)

    def test_missing_finalized_is_uncorroborated_in_v05(self):
        # H5: a current-version checkpoint without
        # finalized_block_number earns nothing (not gate-exempt).
        seed = bytes([223]) * 32
        obs = []
        for i in range(48):
            number = 400000 + i * 10
            obs.append({
                "timestamp_unix": SCORED_AT - 40 * DAY + i * SLOT,
                "best_block_number": number,
                "best_block_hash": hashlib.sha256(
                    ("nf-%d" % number).encode()).hexdigest(),
                "observed_peers": 9,
            })
        bundle = core.build_bundle(seed, obs, version="0.5",
                                   profile=PROFILE)
        result = score([submission(bundle, "nofin", 400)])
        n = result["nodes"][0]
        self.assertEqual(n["metrics"]["gate_passing_checkpoints"], 0)
        self.assertEqual(n["adjusted_weight"], 0.0)


class TestAccountAgeIgnored(unittest.TestCase):
    """Account age is reference metadata only (no entry barriers).

    A brand-new GitHub account (age 0) with the same participation
    history must earn exactly the same weight as an ancient account.
    The time wall is participation maturity alone.
    """

    def test_age_does_not_change_weight(self):
        start = SCORED_AT - 40 * DAY
        young = make_bundle(231, start, 96)
        old = make_bundle(232, start, 96)
        subs = [submission(young, "brand-new", 0),
                submission(old, "veteran", 10000)]
        result = score(subs)
        y = node_by_id(result, young["device_id"])["adjusted_weight"]
        o = node_by_id(result, old["device_id"])["adjusted_weight"]
        self.assertGreater(y, 0.0)
        self.assertAlmostEqual(y, o)


if __name__ == "__main__":
    unittest.main()
