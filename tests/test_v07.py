"""Regression tests for the SPEC v0.7 rules revision (independent re-audit of v0.6, 2026-11-07). The bundle format does
NOT change in this round (version stays "0.5"); only the scorer's
verification procedure, its budgets, and the SPEC's stated
guarantees change:

  H-01  v0.6 keyed its dedupe/rejection table on bundle_hash,
        which excludes the signature - so a signature-broken copy
        of a public bundle, processed first, poisoned the genuine
        bundle ("duplicate of a rejected bundle", never verified).
        Verification is now two-stage: stage A authenticates each
        submission itself and records failure ONLY against that
        exact submission; stage B verifies the chain once per
        content key. Submission order no longer matters, and spot
        records are pooled only from accepted submissions.
  H-02  a created_at-only rewrap (new bundle_hash, fresh
        signature, same chain) forced a full chain verification
        per copy. The content key excludes created_at_unix and
        the signature, so K rewraps share ONE chain verification.
        [v0.7 also added aggregation budgets - a per-device cap
        on distinct authenticated submissions and a global cap
        on distinct content keys verified per run, excess
        rejected with an explicit reason. The v0.7 re-audit
        showed those rejection budgets were themselves
        exclusion weapons (new H-01), so v0.8 replaced them
        with a deferral safety valve; TestBudgets below became
        TestDeferralValve, and the full v0.8 regression suite
        is tests/test_v08.py.]
  M-08  no scorer behaviour change: the cap guarantee is pinned
        at its exact scope - the audit's two-triangle worked
        example (5 nodes, base 1 each) totals 10/3, each block's
        member sum stays <= its cap (2.0), and the withdrawn
        farm-wide "twice the strongest" reading would give 2.0.
  L-01  scoring output must be byte-identical across processes
        with different PYTHONHASHSEED values (float sums iterate
        in sorted order via math.fsum).

Run: python3 -m unittest discover -s tests -v   (from depin/)
Standard library only.
"""

import copy
import hashlib
import json
import math
import os
import subprocess
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
                witnesses=None, start_number=400000, version="0.5",
                created_at_unix=None):
    seed = bytes([seed_byte]) * 32
    obs = []
    ts = start_ts
    for i in range(count):
        number = start_number + i * 10
        o = {
            "timestamp_unix": ts,
            "best_block_number": number,
            "best_block_hash": hashlib.sha256(
                ("v07-%d-%d" % (seed_byte, number)).encode()).hexdigest(),
            "observed_peers": 9,
            "finalized_block_number": number - lag,
        }
        if witnesses:
            o["witness_peers"] = witnesses
        obs.append(o)
        ts += step
    return core.build_bundle(seed, obs, version=version, profile=PROFILE,
                             created_at_unix=created_at_unix)


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


def days_bundle(seed_byte, days, witnesses=None, end_days_ago=10):
    """A bundle of `days` settled days (weight sqrt(days))."""
    return make_bundle(seed_byte,
                       SCORED_AT - (end_days_ago + days) * DAY,
                       days * 144, witnesses=witnesses)


def broken_signature_copy(bundle):
    """The H-01 attack copy: identical to the genuine bundle
    except for one flipped signature bit. The bundle_hash is
    unchanged (the signature is not part of it)."""
    bad = copy.deepcopy(bundle)
    sig = bytearray(bytes.fromhex(bundle["signature"]))
    sig[0] ^= 0x01
    bad["signature"] = bytes(sig).hex()
    assert bad["bundle_hash"] == bundle["bundle_hash"]
    return bad


# ------------------------------------------------------------------
# H-01: submission order must not matter
# ------------------------------------------------------------------

class TestH01OrderIndependence(unittest.TestCase):

    def setUp(self):
        self.bundle = make_bundle(42, SCORED_AT - 40 * DAY, 48)
        self.bad = broken_signature_copy(self.bundle)
        self.did = self.bundle["device_id"]

    def test_broken_first_genuine_still_accepted(self):
        result = score([submission(self.bad, "attacker"),
                        submission(self.bundle, "victim")])
        n = node_by_id(result, self.did)
        self.assertEqual(n["status"], "ok")
        self.assertAlmostEqual(n["adjusted_weight"],
                               math.sqrt(48 * SLOT / DAY), places=6)
        self.assertEqual(result["summary"]["rejected_count"], 1)
        reason = result["rejected_submissions"][0]["reasons"][0]
        self.assertIn("invalid bundle", reason)
        self.assertIn("signature", reason)

    def test_genuine_first_broken_rejected_alone(self):
        result = score([submission(self.bundle, "victim"),
                        submission(self.bad, "attacker")])
        n = node_by_id(result, self.did)
        self.assertEqual(n["status"], "ok")
        self.assertEqual(result["summary"]["rejected_count"], 1)

    def test_both_orders_give_identical_results(self):
        r1 = score([submission(self.bad, "attacker"),
                    submission(self.bundle, "victim")])
        r2 = score([submission(self.bundle, "victim"),
                    submission(self.bad, "attacker")])
        self.assertEqual(
            [(n["device_id"], n["status"], n["adjusted_weight"])
             for n in r1["nodes"]],
            [(n["device_id"], n["status"], n["adjusted_weight"])
             for n in r2["nodes"]])
        self.assertEqual(r1["summary"]["rejected_count"],
                         r2["summary"]["rejected_count"])

    def test_broken_only_no_node(self):
        result = score([submission(self.bad, "attacker")])
        self.assertEqual(result["nodes"], [])
        self.assertEqual(result["summary"]["rejected_count"], 1)

    def test_repeated_broken_copy_still_never_poisons(self):
        # The broken copy twice (its repeat is a fingerprint
        # duplicate) plus the genuine bundle in the middle.
        result = score([submission(self.bad, "attacker"),
                        submission(self.bundle, "victim"),
                        submission(self.bad, "attacker")])
        n = node_by_id(result, self.did)
        self.assertEqual(n["status"], "ok")
        reasons = [r["reasons"][0]
                   for r in result["rejected_submissions"]]
        self.assertEqual(len(reasons), 2)
        self.assertIn("duplicate of a rejected bundle", reasons[1])

    def test_two_genuine_resignatures_merge_into_one_node(self):
        # Same chain, two created_at values, both owner-signed:
        # both are accepted as distinct submissions and merge
        # into the single node for that device.
        obs_bundle = make_bundle(43, SCORED_AT - 40 * DAY, 48,
                                 created_at_unix=SCORED_AT - 1000)
        resign = make_bundle(43, SCORED_AT - 40 * DAY, 48,
                             created_at_unix=SCORED_AT - 500)
        self.assertNotEqual(obs_bundle["bundle_hash"],
                            resign["bundle_hash"])
        self.assertEqual(
            core.bundle_content_key(obs_bundle, profile=PROFILE),
            core.bundle_content_key(resign, profile=PROFILE))
        result = score([submission(obs_bundle, "owner"),
                        submission(resign, "owner")])
        self.assertEqual(len(result["nodes"]), 1)
        n = result["nodes"][0]
        self.assertEqual(n["status"], "ok")
        self.assertEqual(n["metrics"]["bundles_merged"], 2)
        self.assertAlmostEqual(n["adjusted_weight"],
                               math.sqrt(48 * SLOT / DAY), places=6)
        self.assertEqual(result["summary"]["duplicates_ignored"], 0)


# ------------------------------------------------------------------
# H-02: content-key reuse and budgets
# ------------------------------------------------------------------

class TestH02ContentKeyReuse(unittest.TestCase):

    def _counting_chain(self):
        calls = []
        orig = core.verify_bundle_chain

        def counting(bundle, **kw):
            calls.append(bundle["bundle_hash"])
            return orig(bundle, **kw)

        return calls, orig, counting

    def _counting_auth(self):
        calls = []
        orig = core.verify_bundle

        def counting(bundle, **kw):
            calls.append(kw.get("verify_chain", True))
            return orig(bundle, **kw)

        return calls, orig, counting

    def test_five_rewraps_one_chain_verification(self):
        rewraps = [make_bundle(44, SCORED_AT - 40 * DAY, 48,
                               created_at_unix=SCORED_AT - 5000 + i)
                   for i in range(5)]
        self.assertEqual(
            len({b["bundle_hash"] for b in rewraps}), 5)
        self.assertEqual(
            len({core.bundle_content_key(b, profile=PROFILE)
                 for b in rewraps}), 1)
        chain_calls, orig_chain, counting_chain = self._counting_chain()
        auth_calls, orig_auth, counting_auth = self._counting_auth()
        core.verify_bundle_chain = counting_chain
        core.verify_bundle = counting_auth
        try:
            result = score([submission(b, "owner") for b in rewraps])
        finally:
            core.verify_bundle_chain = orig_chain
            core.verify_bundle = orig_auth
        # The chain is verified exactly once...
        self.assertEqual(len(chain_calls), 1)
        # ...while every copy still gets its own stage-A
        # signature authentication.
        self.assertEqual(auth_calls, [False] * 5)
        # One merged node results, weight of the single chain.
        self.assertEqual(len(result["nodes"]), 1)
        n = result["nodes"][0]
        self.assertEqual(n["status"], "ok")
        self.assertAlmostEqual(n["adjusted_weight"],
                               math.sqrt(48 * SLOT / DAY), places=6)
        self.assertEqual(result["summary"]["content_keys_verified"], 1)
        self.assertEqual(result["summary"]["duplicates_ignored"], 0)

    def test_distinct_chains_verify_separately(self):
        b1 = make_bundle(45, SCORED_AT - 40 * DAY, 48)
        b2 = make_bundle(45, SCORED_AT - 90 * DAY, 48)
        chain_calls, orig_chain, counting_chain = self._counting_chain()
        core.verify_bundle_chain = counting_chain
        try:
            result = score([submission(b1, "owner"),
                            submission(b2, "owner")])
        finally:
            core.verify_bundle_chain = orig_chain
        self.assertEqual(len(chain_calls), 2)
        self.assertEqual(result["summary"]["content_keys_verified"], 2)
        self.assertEqual(len(result["nodes"]), 1)


class TestDeferralValve(unittest.TestCase):
    """Was TestBudgets in v0.7. The v0.7 rejection budgets - a
    per-device cap on distinct authenticated submissions and a
    global content-key cap, excess REJECTED - were removed in
    v0.8 after the re-audit showed they excluded genuine
    submissions (new H-01): the global cap counted failed keys,
    and the per-device cap could be burned by replaying a
    victim's own published bundles. What remains is a run-level
    safety valve with deferral semantics; the full v0.8 suite
    (flood-then-genuine, shuffle invariance) is test_v08.py."""

    def test_no_per_device_intake_cap(self):
        # Six DISTINCT chains from one device all merge: there
        # is no per-device submission cap anymore.
        subs = [submission(make_bundle(46, SCORED_AT - (40 + 30 * i) * DAY,
                                       48), "owner")
                for i in range(6)]
        result = score(subs)
        n = node_by_id(result, device_id(46))
        self.assertEqual(n["status"], "ok")
        self.assertEqual(n["metrics"]["bundles_merged"], 6)
        self.assertEqual(result["rejected_submissions"], [])
        self.assertEqual(result["deferred_submissions"], [])

    def test_global_valve_defers_never_rejects(self):
        subs = [submission(make_bundle(50 + i, SCORED_AT - 40 * DAY, 48),
                           "owner%d" % i)
                for i in range(3)]
        result = score(subs, max_content_keys=2)
        self.assertEqual(len(result["nodes"]), 2)
        self.assertEqual(result["rejected_submissions"], [])
        self.assertEqual(len(result["deferred_submissions"]), 1)
        self.assertEqual(result["summary"]["content_keys_verified"], 2)
        self.assertEqual(result["summary"]["content_keys_deferred"], 1)
        self.assertEqual(result["summary"]["deferred_count"], 1)
        self.assertNotIn("budget_rejections", result["summary"])
        reason = result["deferred_submissions"][0]["reasons"][0]
        self.assertIn("deferred", reason)
        # Arrival order cannot change WHO is deferred: with no
        # carried-over keys, the valve allocates round-robin
        # across devices in device_id order (v0.8 design review
        # A2 - pure key order would let smaller keys starve a
        # deferred key forever).
        reversed_result = score(list(reversed(subs)), max_content_keys=2)
        self.assertEqual(
            {d["claimed_device_id"]
             for d in result["deferred_submissions"]},
            {d["claimed_device_id"]
             for d in reversed_result["deferred_submissions"]})
        self.assertEqual(
            {n["device_id"] for n in result["nodes"]},
            {n["device_id"] for n in reversed_result["nodes"]})

    def test_unauthenticated_copies_consume_no_verification_slots(self):
        # Broken-signature copies fail stage A, so they never
        # become content keys and cannot consume the valve: with
        # room for exactly the two genuine chains, both are
        # still verified and accepted after the attack copies.
        genuine = make_bundle(47, SCORED_AT - 40 * DAY, 48)
        other = make_bundle(47, SCORED_AT - 90 * DAY, 48)
        bad = broken_signature_copy(genuine)
        subs = [submission(bad, "attacker"),
                submission(bad, "attacker"),
                submission(genuine, "victim"),
                submission(other, "victim")]
        result = score(subs, max_content_keys=2)
        n = node_by_id(result, device_id(47))
        self.assertEqual(n["status"], "ok")
        self.assertEqual(n["metrics"]["bundles_merged"], 2)
        self.assertEqual(result["deferred_submissions"], [])
        self.assertEqual(len(result["rejected_submissions"]), 2)

    def test_exact_duplicates_consume_no_verification_slots(self):
        bundle = make_bundle(48, SCORED_AT - 40 * DAY, 48)
        subs = [submission(bundle, "owner") for _ in range(5)]
        result = score(subs, max_content_keys=1)
        n = node_by_id(result, device_id(48))
        self.assertEqual(n["status"], "ok")
        self.assertEqual(result["summary"]["duplicates_ignored"], 4)
        self.assertEqual(result["summary"]["content_keys_verified"], 1)
        self.assertEqual(result["deferred_submissions"], [])


# ------------------------------------------------------------------
# H-01 (pooling): spot records come only from accepted submissions
# ------------------------------------------------------------------

def spot_setup(seed_byte=60, count=48):
    bundle = make_bundle(seed_byte, SCORED_AT - 40 * DAY, count)
    challenge = hashlib.sha256(b"v07-challenge").digest()
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


class TestSpotPoolingAuthenticatedOnly(unittest.TestCase):

    def test_record_on_rejected_copy_is_never_pooled(self):
        # The attacker attaches the owner's WRONG signed response
        # (e.g. harvested from elsewhere) to a signature-broken
        # copy of the victim's bundle. The copy is rejected at
        # stage A, so its record never enters the pool and the
        # victim is untouched.
        bundle, challenge, target, good, exp = spot_setup()
        wrong = owner_record(bundle, 60, challenge, target,
                             hashlib.sha256(b"wrong").digest())
        bad = broken_signature_copy(bundle)
        result = score([submission(bad, "attacker", wrong),
                        submission(bundle, "victim")],
                       spot_expectations=exp)
        n = node_by_id(result, bundle["device_id"])
        self.assertEqual(n["status"], "ok")
        self.assertNotEqual(n["spot_check"], "failed")
        self.assertEqual(n["disqualify_reasons"], [])

    def test_same_record_on_genuine_submission_still_fails(self):
        # Control: the same owner-signed wrong response, carried
        # by the genuine submission, disqualifies as before -
        # the pooling rule did not defang spot checks.
        bundle, challenge, target, good, exp = spot_setup()
        wrong = owner_record(bundle, 60, challenge, target,
                             hashlib.sha256(b"wrong").digest())
        result = score([submission(bundle, "owner", wrong)],
                       spot_expectations=exp)
        n = node_by_id(result, bundle["device_id"])
        self.assertEqual(n["status"], "disqualified")
        self.assertEqual(n["adjusted_weight"], 0.0)


# ------------------------------------------------------------------
# M-08: the cap guarantee at its exact scope (worked example)
# ------------------------------------------------------------------

class TestM08WorkedExample(unittest.TestCase):

    def test_two_triangles_sharing_one_vertex(self):
        # SPEC v0.7 section 7 boundary case: five nodes, base
        # weight 1 each; triangles {h,a,b} and {h,c,d} share only
        # h. Each block: base sum 3, cap 2 x 1 = 2, factor 2/3.
        # Farm total = 10/3 (~ 3.333), NOT the withdrawn
        # farm-wide reading of "twice the strongest" (= 2.0).
        h, a, b, c, d = (device_id(s) for s in (70, 71, 72, 73, 74))
        subs = [
            submission(days_bundle(70, 1, witnesses=[a, b, c, d]), "h"),
            submission(days_bundle(71, 1, witnesses=[h, b]), "a"),
            submission(days_bundle(72, 1, witnesses=[h, a]), "b"),
            submission(days_bundle(73, 1, witnesses=[h, d]), "c"),
            submission(days_bundle(74, 1, witnesses=[h, c]), "d"),
        ]
        result = score(subs)
        weights = {n["device_id"]: n["adjusted_weight"]
                   for n in result["nodes"]}
        self.assertEqual(len(weights), 5)
        for did, w in weights.items():
            # (i) adjusted <= base (base is 1.0 for one day).
            self.assertLessEqual(w, 1.0)
            self.assertAlmostEqual(w, 2.0 / 3.0, places=4)
        # (ii) per-block bound: each triangle's member sum <= cap.
        self.assertLessEqual(weights[h] + weights[a] + weights[b],
                             2.0 + 1e-9)
        self.assertLessEqual(weights[h] + weights[c] + weights[d],
                             2.0 + 1e-9)
        # The farm total is exactly 10/3 - beyond any farm-wide
        # "twice the strongest member" bound (which would be 2).
        total = math.fsum(weights.values())
        self.assertAlmostEqual(total, 10.0 / 3.0, places=4)
        self.assertGreater(total, 2.0)
        # (iii) global bound: total <= sum of base weights (5).
        self.assertLessEqual(total, 5.0)


# ------------------------------------------------------------------
# L-01: determinism across hash seeds
# ------------------------------------------------------------------

def build_determinism_scenario():
    """A fixed scenario exercising the cap pass with non-round
    float weights: two triangles sharing a vertex (varied days),
    plus a bridged clique. Built identically in every process."""
    days = {80: 3, 81: 5, 82: 7, 83: 11, 84: 13, 85: 2, 86: 17}
    ids = {s: device_id(s) for s in days}
    subs = [
        submission(days_bundle(80, days[80],
                               witnesses=[ids[81], ids[82], ids[83],
                                          ids[84]]), "n80"),
        submission(days_bundle(81, days[81],
                               witnesses=[ids[80], ids[82]]), "n81"),
        submission(days_bundle(82, days[82],
                               witnesses=[ids[80], ids[81]]), "n82"),
        submission(days_bundle(83, days[83],
                               witnesses=[ids[80], ids[84]]), "n83"),
        submission(days_bundle(84, days[84],
                               witnesses=[ids[80], ids[83]]), "n84"),
        submission(days_bundle(85, days[85],
                               witnesses=[ids[86], ids[81]]), "n85"),
        submission(days_bundle(86, days[86],
                               witnesses=[ids[85], ids[81]]), "n86"),
    ]
    return subs


def score_scenario_json():
    result = scorer.score_submissions(
        build_determinism_scenario(),
        scored_at_unix=SCORED_AT, profile=PROFILE)
    return json.dumps(result, sort_keys=True)


class TestDeterminism(unittest.TestCase):

    def test_byte_identical_across_hash_seeds(self):
        here = os.path.dirname(os.path.abspath(__file__))
        src_dir = os.path.join(here, "..", "src")
        code = ("import sys; sys.path.insert(0, %r); "
                "sys.path.insert(0, %r); "
                "import test_v07; print(test_v07.score_scenario_json())"
                % (src_dir, here))
        outputs = []
        for seed in ("0", "1", "12345"):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            proc = subprocess.run(
                [sys.executable, "-c", code],
                capture_output=True, text=True, env=env, check=True)
            outputs.append(proc.stdout)
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(outputs[0], outputs[2])
        # And identical to this process's own rendering.
        self.assertEqual(outputs[0].strip(), score_scenario_json())


if __name__ == "__main__":
    unittest.main()
