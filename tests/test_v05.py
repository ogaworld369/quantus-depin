"""Regression tests for the SPEC v0.5 round (re-audit of
v0.4, 2026-11-07):

  R-C01  field injection into a genuine signed spot-check record
         (v0.4's absent/-1 target_seq ambiguity) must break the
         signature, so the record is ignored and the victim is
         untouched; verbatim replay of the owner's record is
         harmless; an owner-signed WRONG response still fails
  R-M05  spot-check ordering is authenticated by the signed
         revision counter: a correction (higher revision) wins
         regardless of submission order; two different responses
         at the highest revision are equivocation and fail
  R-H01  duplicate submissions are deduplicated BEFORE full
         verification: core.verify_bundle runs at most once per
         distinct bundle_hash per scoring run, for accepted and
         rejected bundles alike; duplicates still contribute
         spot-check records to the pool
  R-H02  closed-component cap basis is the second-largest weight:
         the laundering attack (farm + one mutual edge to an
         honest mature node) yields farm 2.0000 / honest 13.4164
         (v0.4 gave 21.1561 / 5.6768); three equal mature mutual
         nodes share the 2x cap. NOTE: the star-farm expectation
         of this round (capped at 2.0) was superseded in v0.6 -
         under block-local caps a star is all size-2 blocks and
         stays uncapped as a DOCUMENTED RESIDUAL (SPEC v0.6
         section 7); see the updated test below and test_v06.py
  legacy v0.4 bundles are rejected by default with a version
         reason, verify with allow_legacy, and are never scored

Run: python3 -m unittest discover -s tests -v   (from depin/)
Standard library only.
"""

import hashlib
import os
import sys
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
                witnesses=None, start_number=400000, version="0.5"):
    seed = bytes([seed_byte]) * 32
    obs = []
    ts = start_ts
    for i in range(count):
        number = start_number + i * 10
        o = {
            "timestamp_unix": ts,
            "best_block_number": number,
            "best_block_hash": hashlib.sha256(
                ("v05-%d-%d" % (seed_byte, number)).encode()).hexdigest(),
            "observed_peers": 9,
            "finalized_block_number": number - lag,
        }
        if witnesses:
            o["witness_peers"] = witnesses
        obs.append(o)
        ts += step
    return core.build_bundle(seed, obs, version=version, profile=PROFILE)


def device_id(seed_byte):
    return core.device_id_from_pubkey(
        ed.publickey_from_seed(bytes([seed_byte]) * 32))


def submission(bundle, account, spot_check=None):
    # v0.8 max-rule: "submitted promptly", one hour after the
    # bundle's last checkpoint (see test_scorer.submission).
    prompt = bundle["checkpoints"][-1]["timestamp_unix"] + 3600
    sub = {"bundle": bundle, "account": account,
           "account_age_days": 0, "submitted_at_unix": prompt}
    if spot_check is not None:
        sub["spot_check"] = spot_check
    return sub


def score(subs, **kw):
    kw.setdefault("scored_at_unix", SCORED_AT)
    kw.setdefault("profile", PROFILE)
    return scorer.score_submissions(subs, **kw)


def node_by_id(result, did):
    for n in result["nodes"]:
        if n["device_id"] == did:
            return n
    raise AssertionError("node %s missing" % did)


def spot_setup(seed_byte=33, count=48):
    bundle = make_bundle(seed_byte, SCORED_AT - 40 * DAY, count)
    challenge = hashlib.sha256(b"v05-challenge").digest()
    target = scorer.derive_spot_target_index(count, challenge)
    good = scorer.spot_response_value(
        bytes.fromhex(bundle["checkpoints"][target]["best_block_hash"]),
        b"synthetic-block-body")
    expectations = {bundle["bundle_hash"]: {
        "challenge_block_hash": challenge.hex(),
        "expected": good.hex()}}
    return bundle, challenge, target, good, expectations


def owner_record(bundle, seed_byte, challenge, target, value,
                 revision=0):
    sig = core.sign_spot_response(
        bytes([seed_byte]) * 32, bytes.fromhex(bundle["bundle_hash"]),
        challenge, value, target, revision=revision)
    return {"response": value.hex(), "signature": sig.hex(),
            "target_seq": target, "revision": revision}


# ------------------------------------------------------------------
# protocol v2 helpers (core)
# ------------------------------------------------------------------

class TestSpotV2Helpers(unittest.TestCase):
    def setUp(self):
        self.seed = bytes([44]) * 32
        self.pubkey = ed.publickey_from_seed(self.seed)
        self.bh = hashlib.sha256(b"bundle").digest()
        self.ch = hashlib.sha256(b"challenge").digest()
        self.resp = hashlib.sha256(b"response").digest()

    def test_sign_raises_on_missing_or_negative_target(self):
        for bad in (None, -1, -100, "3", 1.5, True):
            with self.assertRaises(ValueError, msg="target %r" % (bad,)):
                core.sign_spot_response(
                    self.seed, self.bh, self.ch, self.resp, bad)

    def test_sign_raises_on_negative_revision(self):
        with self.assertRaises(ValueError):
            core.sign_spot_response(
                self.seed, self.bh, self.ch, self.resp, 0, revision=-1)

    def test_verify_rejects_revision_and_target_tampering(self):
        sig = core.sign_spot_response(
            self.seed, self.bh, self.ch, self.resp, 3, revision=0)
        self.assertTrue(core.verify_spot_response(
            self.pubkey, self.bh, self.ch, self.resp, 3, sig,
            revision=0))
        self.assertFalse(core.verify_spot_response(
            self.pubkey, self.bh, self.ch, self.resp, 3, sig,
            revision=1))
        self.assertFalse(core.verify_spot_response(
            self.pubkey, self.bh, self.ch, self.resp, None, sig,
            revision=0))
        self.assertFalse(core.verify_spot_response(
            self.pubkey, self.bh, self.ch, self.resp, -1, sig,
            revision=0))


# ------------------------------------------------------------------
# R-C01: field injection into a genuine record
# ------------------------------------------------------------------

class TestSpotFieldInjection(unittest.TestCase):
    def test_injected_fields_break_signature_victim_untouched(self):
        bundle, challenge, target, good, exp = spot_setup()
        genuine = owner_record(bundle, 33, challenge, target, good)
        subs = [submission(bundle, "victim", genuine)]
        # Attacker copies with ONE field altered each time. In
        # v0.4, adding "target_seq": -1 kept the signature valid
        # and disqualified the victim; in v2 every alteration
        # breaks the signature, so these records are ignored.
        for mutate in (
                lambda r: r.update(target_seq=target + 1),
                lambda r: r.update(target_seq=-1),
                lambda r: r.update(revision=9),
                lambda r: r.update(
                    response=hashlib.sha256(b"x").hexdigest())):
            evil = dict(genuine)
            mutate(evil)
            subs.append(submission(bundle, "attacker", evil))
        result = score(subs, spot_expectations=exp)
        n = node_by_id(result, bundle["device_id"])
        self.assertEqual(n["status"], "ok")
        self.assertEqual(n["spot_check"], "passed")
        self.assertGreater(n["adjusted_weight"], 0.0)
        self.assertTrue(any("unsigned" in f for f in n["flags"]),
                        n["flags"])
        self.assertEqual(result["summary"]["duplicates_ignored"], 4)

    def test_verbatim_replay_of_owner_record_is_harmless(self):
        # Replaying the owner's genuine record verbatim (even
        # repeatedly, even from another account) changes nothing:
        # it IS the owner's correct answer.
        bundle, challenge, target, good, exp = spot_setup()
        genuine = owner_record(bundle, 33, challenge, target, good)
        subs = [submission(bundle, "victim"),
                submission(bundle, "someone-else", genuine),
                submission(bundle, "victim", dict(genuine))]
        result = score(subs, spot_expectations=exp)
        n = node_by_id(result, bundle["device_id"])
        self.assertEqual(n["status"], "ok")
        self.assertEqual(n["spot_check"], "passed")
        self.assertEqual(result["summary"]["duplicates_ignored"], 2)

    def test_owner_signed_wrong_response_still_fails(self):
        # Control: the protocol still catches a genuinely wrong
        # owner-signed answer (spot checks are not toothless).
        bundle, challenge, target, good, exp = spot_setup()
        wrong = owner_record(bundle, 33, challenge, target,
                             hashlib.sha256(b"wrong").digest())
        result = score([submission(bundle, "owner", wrong)],
                       spot_expectations=exp)
        n = node_by_id(result, bundle["device_id"])
        self.assertEqual(n["status"], "disqualified")
        self.assertEqual(n["adjusted_weight"], 0.0)


# ------------------------------------------------------------------
# R-M05: signed revision ordering
# ------------------------------------------------------------------

class TestSpotRevisionOrdering(unittest.TestCase):
    def test_correction_wins_regardless_of_submission_order(self):
        bundle, challenge, target, good, exp = spot_setup()
        wrong0 = owner_record(bundle, 33, challenge, target,
                              hashlib.sha256(b"wrong").digest(),
                              revision=0)
        right1 = owner_record(bundle, 33, challenge, target, good,
                              revision=1)
        for subs in (
                [submission(bundle, "owner", wrong0),
                 submission(bundle, "owner", right1)],
                [submission(bundle, "owner", right1),
                 submission(bundle, "attacker", wrong0)]):
            result = score(subs, spot_expectations=exp)
            n = node_by_id(result, bundle["device_id"])
            self.assertEqual(n["status"], "ok")
            self.assertEqual(n["spot_check"], "passed")

    def test_equivocation_at_highest_revision_fails(self):
        bundle, challenge, target, good, exp = spot_setup()
        right = owner_record(bundle, 33, challenge, target, good,
                             revision=1)
        wrong_same_rev = owner_record(
            bundle, 33, challenge, target,
            hashlib.sha256(b"wrong").digest(), revision=1)
        result = score([submission(bundle, "owner", right),
                        submission(bundle, "owner", wrong_same_rev)],
                       spot_expectations=exp)
        n = node_by_id(result, bundle["device_id"])
        self.assertEqual(n["status"], "disqualified")
        self.assertTrue(any("equivocation" in r
                            for r in n["disqualify_reasons"]),
                        n["disqualify_reasons"])
        # Same rule when the conflict is in the target instead.
        other_target = owner_record(bundle, 33, challenge,
                                    (target + 1) % 48, good,
                                    revision=1)
        result = score([submission(bundle, "owner", right),
                        submission(bundle, "owner", other_target)],
                       spot_expectations=exp)
        n = node_by_id(result, bundle["device_id"])
        self.assertEqual(n["status"], "disqualified")


# ------------------------------------------------------------------
# R-H01: dedupe before verification
# ------------------------------------------------------------------

class TestDedupeBeforeVerify(unittest.TestCase):
    def _counting_verify(self):
        calls = []
        orig = core.verify_bundle

        def counting(bundle, **kw):
            calls.append(bundle["bundle_hash"])
            return orig(bundle, **kw)

        return calls, orig, counting

    def test_valid_bundle_verified_once_for_five_submissions(self):
        bundle, _, _, _, _ = spot_setup(seed_byte=55, count=24)
        calls, orig, counting = self._counting_verify()
        core.verify_bundle = counting
        try:
            result = score([submission(bundle, "a%d" % i)
                            for i in range(5)])
        finally:
            core.verify_bundle = orig
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["summary"]["duplicates_ignored"], 4)
        n = node_by_id(result, bundle["device_id"])
        self.assertEqual(n["status"], "ok")
        self.assertGreater(n["adjusted_weight"], 0.0)

    def test_rejected_bundle_verified_once(self):
        bundle, _, _, _, _ = spot_setup(seed_byte=56, count=24)
        # Corrupt the signature only: the declared bundle_hash
        # still recomputes (the signature is not part of it), so
        # the bundle reaches full verification - and fails there.
        bad = dict(bundle)
        sig = bytearray(bytes.fromhex(bundle["signature"]))
        sig[0] ^= 0x01
        bad["signature"] = bytes(sig).hex()
        calls, orig, counting = self._counting_verify()
        core.verify_bundle = counting
        try:
            result = score([submission(bad, "a%d" % i)
                            for i in range(3)])
        finally:
            core.verify_bundle = orig
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["nodes"], [])
        self.assertEqual(result["summary"]["rejected_count"], 3)
        reasons = [r["reasons"][0]
                   for r in result["rejected_submissions"]]
        self.assertIn("invalid bundle", reasons[0])
        self.assertTrue(all("duplicate of a rejected bundle" in r
                            for r in reasons[1:]), reasons)

    def test_duplicates_still_contribute_spot_records(self):
        # The R-H01 restructure must not lose the C-01 property:
        # a genuine response that arrives on a DUPLICATE submission
        # still joins the pool and is evaluated.
        bundle, challenge, target, good, exp = spot_setup(seed_byte=57)
        genuine = owner_record(bundle, 57, challenge, target, good)
        calls, orig, counting = self._counting_verify()
        core.verify_bundle = counting
        try:
            result = score(
                [submission(bundle, "owner"),
                 submission(bundle, "owner", genuine)],
                spot_expectations=exp)
        finally:
            core.verify_bundle = orig
        self.assertEqual(len(calls), 1)
        n = node_by_id(result, bundle["device_id"])
        self.assertEqual(n["spot_check"], "passed")


# ------------------------------------------------------------------
# R-H02: cap basis is the second-largest weight
# ------------------------------------------------------------------

class TestClusterCapV2(unittest.TestCase):
    def test_laundering_attack_neutralised(self):
        # The v0.4 R-H02 reproduction: a closed farm of 50 nodes
        # (1 settled day each, base weight 1.0) plus ONE mutual
        # edge from farm[0] to an honest 180-day node (13.4164).
        # v0.4: farm total 21.1561, honest dragged to 5.6768.
        # v0.5: the honest node is the unique strongest member,
        # hence exempt; the farm pool is capped by the
        # second-largest weight (1.0) at 2.0000, as if the honest
        # node were not there.
        honest_id = device_id(99)
        farm_seeds = list(range(40, 90))
        farm_ids = [device_id(s) for s in farm_seeds]
        honest = make_bundle(99, SCORED_AT - 190 * DAY, 180 * 144,
                             witnesses=[farm_ids[0]])
        farm = []
        for i, s in enumerate(farm_seeds):
            w = list(farm_ids)
            if i == 0:
                w.append(honest_id)
            farm.append(make_bundle(s, SCORED_AT - 11 * DAY, 144,
                                    witnesses=w))
        subs = [submission(honest, "honest")]
        subs += [submission(b, "farm-%d" % s)
                 for s, b in zip(farm_seeds, farm)]
        result = score(subs)
        h = node_by_id(result, honest_id)
        self.assertAlmostEqual(h["adjusted_weight"], 13.4164,
                               places=4)
        self.assertFalse(any(f.startswith("closed_cluster_discount")
                             for f in h["flags"]), h["flags"])
        farm_total = sum(node_by_id(result, d)["adjusted_weight"]
                         for d in farm_ids)
        self.assertAlmostEqual(farm_total, 2.0, places=4)

    def test_star_farm_uncapped_documented_residual(self):
        # v0.5 expectation was a total of 2.0 under the
        # component-wide pool. v0.6 (B3-F1) replaced the pool
        # with BLOCK-LOCAL caps: in a star every biconnected
        # block is a size-2 edge block, and a size-2 block can
        # never bind (cap = 2 x max >= both bases), so the star
        # now stays at its full base total of 51.0. This is a
        # DOCUMENTED RESIDUAL of the block-local design (SPEC
        # v0.6 section 7: hub/star topologies evade caps), not
        # a defect to be "fixed" back into existence: the
        # component-wide pool that capped the star is the same
        # pool that diluted bridged honest groups (B3-F1).
        center_id = device_id(150)
        leaf_seeds = list(range(151, 201))
        leaf_ids = [device_id(s) for s in leaf_seeds]
        center = make_bundle(150, SCORED_AT - 11 * DAY, 144,
                             witnesses=leaf_ids)
        subs = [submission(center, "center")]
        for s, lid in zip(leaf_seeds, leaf_ids):
            subs.append(submission(
                make_bundle(s, SCORED_AT - 11 * DAY, 144,
                            witnesses=[center_id]),
                "leaf-%d" % s))
        result = score(subs)
        total = sum(n["adjusted_weight"] for n in result["nodes"])
        self.assertAlmostEqual(total, 51.0, places=4)
        for n in result["nodes"]:
            self.assertFalse(any(f.startswith("closed_cluster")
                                 for f in n["flags"]), n["flags"])
        self.assertEqual(
            result["summary"]["closed_clusters_capped"], 0)

    def test_three_equal_mature_nodes_share_cap(self):
        seeds = [210, 211, 212]
        ids = [device_id(s) for s in seeds]
        subs = [submission(
            make_bundle(s, SCORED_AT - 40 * DAY, 30 * 144,
                        witnesses=ids), "n-%d" % s) for s in seeds]
        result = score(subs)
        import math
        for n in result["nodes"]:
            self.assertAlmostEqual(n["adjusted_weight"],
                                   math.sqrt(30) * 2.0 / 3.0,
                                   places=4)

    def test_honest_mutual_pair_uncapped(self):
        a_id, b_id = device_id(220), device_id(221)
        subs = [submission(make_bundle(220, SCORED_AT - 10 * DAY, 10,
                                       witnesses=[b_id]), "a"),
                submission(make_bundle(221, SCORED_AT - 10 * DAY, 10,
                                       witnesses=[a_id]), "b")]
        result = score(subs)
        import math
        expected = math.sqrt(10 * SLOT / DAY)
        for n in result["nodes"]:
            self.assertAlmostEqual(n["adjusted_weight"], expected,
                                   places=6)
            self.assertFalse(any(
                f.startswith("closed_cluster") for f in n["flags"]),
                n["flags"])


# ------------------------------------------------------------------
# version policy: v0.4 is legacy now
# ------------------------------------------------------------------

class TestLegacyV04Policy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = make_bundle(230, SCORED_AT - 40 * DAY, 8,
                                 version="0.4")

    def test_v04_rejected_by_default_with_version_reason(self):
        ok, errors = core.verify_bundle(self.bundle, profile=PROFILE)
        self.assertFalse(ok)
        self.assertTrue(any("legacy" in e for e in errors), errors)

    def test_v04_verifies_with_allow_legacy(self):
        ok, errors = core.verify_bundle(self.bundle, profile=PROFILE,
                                        allow_legacy=True)
        self.assertTrue(ok, errors)

    def test_v04_is_never_scored(self):
        result = score([submission(self.bundle, "legacy-user")])
        self.assertEqual(result["nodes"], [])
        self.assertEqual(result["summary"]["rejected_count"], 1)
        self.assertIn("not scored",
                      result["rejected_submissions"][0]["reasons"][0])


if __name__ == "__main__":
    unittest.main()
