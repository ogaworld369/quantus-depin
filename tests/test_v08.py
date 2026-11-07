"""Regression tests for the SPEC v0.8 rules revision (independent re-audit of v0.7, 2026-11-07). The bundle format does
NOT change in this round (version stays "0.5"); the scorer's
acceptance semantics, its content key, the intake discipline and
the SPEC's stated guarantees change:

  H-01' the v0.7 aggregation budgets were exclusion weapons: the
        global content-key cap counted FAILED keys, so signed
        garbage verified first exhausted it and later genuine
        submissions were rejected; the per-device cap could be
        burned by replaying a victim's own published bundles.
        v0.8 removes both rejection budgets. What remains is a
        run-level safety valve with DEFERRAL semantics: at most
        max_content_keys distinct canonical content keys are
        chain-verified per run, chosen in lexicographic key
        order, so the verified/deferred split cannot depend on
        arrival order; submissions beyond the valve are reported
        as DEFERRED, never rejected. Failed chain verdicts are
        cached by key, so the same garbage chain is verified
        once however many signed copies arrive.
  H-02' the v0.7 content key hashed the RAW bundle dict, so
        representation variants the verifier treats as identical
        - witness_peer_hashes omitted vs an explicit empty list,
        2^C variants over C checkpoints - each forced their own
        full chain verification. The key is now computed from
        the verifier's NORMALISED structure (the single
        _validate_schema normalisation, shared with
        verification), so every variant collapses onto one key
        and one chain verification.
  M-05  exact-duplicate spot records entered the pool N times
        and were signature-verified N times. The pool now
        deduplicates by fingerprint (bundle_hash + response
        signature) at harvest time, before any verification:
        one pool entry, one verification.
  L-01  Python's json module accepts NaN/Infinity and silently
        keeps the last of duplicate object keys; the Android
        implementation's parser rejects both. Bundle/spot intake
        (core.strict_json_loads, used by the CLI loaders) now
        refuses both forms at load.
  L-02  a node's spot_check summary was whatever its LAST
        processed bundle produced, so a disqualified node could
        report "passed". The summary is now a deterministic
        reduction over the per-bundle outcomes (failed >
        passed > unsigned > no_response > not_evaluated),
        independent of submission order.

Design-review amendments (design review of the v0.8
design, 2026-11-07 - depin-v08-design.md, appended section):
  A1    the spot dedupe fingerprint is the canonical hash of
        the ENTIRE record, not (bundle_hash + signature): a
        copied signature on a rewritten body is a distinct
        record, ignored on its own signature failure, and can
        never suppress a genuine correction pre-verification.
  A2/A3 deferral fairness: carried-over keys are verified
        before new keys (key order inside the class), new keys
        are allocated round-robin across devices, and a run
        with anything deferred is marked provisional
        (summary["complete"] is False).
  A5    failure caching covers only deterministic content
        verdicts, within the run (an interrupted verification
        defers its key instead of failing it).
  FS    first-seen anchoring: a checkpoint's effective
        timestamp for maturity/settlement is max(recorded,
        earliest submitted_at_unix among this run's accepted
        submissions containing its content) - the later of the
        claimed recording time and the first witnessed arrival
        (formula corrected min -> max, user-approved 2026-11-08:
        min could not stop back-computation).

Run: python3 -m unittest discover -s tests -v   (from depin/)
Standard library only.
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

import depin_cli as cli
import depin_core as core
import depin_scorer as scorer
import ed25519_rfc8032 as ed

SLOT = core.SLOT_SEC
DAY = 86400
SCORED_AT = 1_800_000_000
PROFILE = "test"


def make_bundle(seed_byte, start_ts, count, step=SLOT, lag=10,
                start_number=400000):
    # Same construction as tests/test_v07.py: build_bundle derives
    # the sequential chain states and checkpoint hashes itself.
    seed = bytes([seed_byte]) * 32
    obs = []
    ts = start_ts
    for i in range(count):
        number = start_number + i * 10
        obs.append({
            "timestamp_unix": ts,
            "best_block_number": number,
            "best_block_hash": hashlib.sha256(
                ("v08-%d-%d" % (seed_byte, number)).encode()).hexdigest(),
            "observed_peers": 9,
            "finalized_block_number": number - lag,
        })
        ts += step
    return core.build_bundle(seed, obs, profile=PROFILE)


def resign(bundle, seed_byte):
    """Recompute bundle_hash and re-sign after a mutation, so the
    result is a fully stage-A-authentic submission."""
    bundle["bundle_hash"] = core.compute_bundle_hash(bundle).hex()
    seed = bytes([seed_byte]) * 32
    bundle["signature"] = ed.sign(
        seed, core._bundle_domain(bundle["version"])
        + bytes.fromhex(bundle["bundle_hash"])).hex()
    return bundle


def signed_broken_chain(bundle, seed_byte):
    """A stage-A-authentic bundle whose CHAIN is invalid: one
    checkpoint's block hash is replaced, so the sequential state
    and the checkpoint hashes no longer verify. Signed by the
    device's own key, exactly like the audit's H-01' garbage:
    unauthenticated garbage cannot consume anything (it fails
    stage A), so the flood that matters is signed garbage."""
    broken = copy.deepcopy(bundle)
    broken["checkpoints"][5]["best_block_hash"] = "ab" * 32
    return resign(broken, seed_byte)


def submission(bundle, account, spot_check=None, submitted_at=None):
    # v0.8 max-rule: unspecified submitted_at means "submitted
    # promptly", one hour after the bundle's last checkpoint
    # (see test_scorer.submission). Tests that exercise the
    # first-seen anchor itself pass submitted_at explicitly.
    if submitted_at is None:
        submitted_at = bundle["checkpoints"][-1]["timestamp_unix"] + 3600
    sub = {"bundle": bundle, "account": account,
           "account_age_days": 0, "submitted_at_unix": submitted_at}
    if spot_check is not None:
        sub["spot_check"] = spot_check
    return sub


def score(subs, **kw):
    kw.setdefault("scored_at_unix", SCORED_AT)
    kw.setdefault("profile", PROFILE)
    return scorer.score_submissions(subs, **kw)


def node_by_id(result, device_id):
    for n in result["nodes"]:
        if n["device_id"] == device_id:
            return n
    return None


def device_id(seed_byte):
    return core.device_id_from_pubkey(
        ed.publickey_from_seed(bytes([seed_byte]) * 32))


def owner_record(bundle, seed_byte, challenge, target, value,
                 revision=0):
    """An owner-signed spot-check record (protocol v2), in the
    wire form parse_spot_record accepts."""
    sig = core.sign_spot_response(
        bytes([seed_byte]) * 32, bytes.fromhex(bundle["bundle_hash"]),
        challenge, value, target, revision=revision)
    return {"response": value.hex(), "signature": sig.hex(),
            "target_seq": target, "revision": revision}


def counting_chain():
    calls = []
    orig = core.verify_bundle_chain

    def wrapper(bundle, profile="production"):
        calls.append(bundle["bundle_hash"])
        return orig(bundle, profile=profile)

    return calls, orig, wrapper


# ------------------------------------------------------------------
# H-01' (a): flood-then-genuine, adequate cap
# ------------------------------------------------------------------

class TestFloodThenGenuine(unittest.TestCase):

    def test_genuine_scores_identically_after_signed_garbage(self):
        genuine = make_bundle(61, SCORED_AT - 40 * DAY, 48)
        garbage = signed_broken_chain(
            make_bundle(90, SCORED_AT - 40 * DAY, 48), 90)
        baseline = score([submission(genuine, "owner")])
        flooded = score([submission(garbage, "attacker"),
                         submission(genuine, "owner")])
        # The genuine node is byte-identical: same weight, same
        # metrics, same flags - the garbage changed nothing.
        self.assertEqual(node_by_id(baseline, device_id(61)),
                         node_by_id(flooded, device_id(61)))
        # The garbage is rejected for its OWN chain failure,
        # attributed to the attacker's claimed device, and it is
        # NOT deferred: deferral is only for unverified keys.
        self.assertEqual(flooded["deferred_submissions"], [])
        self.assertEqual(len(flooded["rejected_submissions"]), 1)
        rej = flooded["rejected_submissions"][0]
        self.assertEqual(rej["claimed_device_id"], device_id(90))
        self.assertIn("invalid bundle", rej["reasons"][0])

    def test_failed_chain_verdict_is_cached_by_key(self):
        # Three re-signed copies of ONE broken chain (created_at
        # rewraps): the failed verdict is cached by content key,
        # so the garbage chain is verified exactly once.
        garbage = signed_broken_chain(
            make_bundle(91, SCORED_AT - 40 * DAY, 48), 91)
        subs = []
        for i in range(3):
            rewrap = copy.deepcopy(garbage)
            rewrap["created_at_unix"] = garbage["created_at_unix"] + i
            subs.append(submission(resign(rewrap, 91), "attacker"))
        calls, orig, wrapper = counting_chain()
        core.verify_bundle_chain = wrapper
        try:
            result = score(subs)
        finally:
            core.verify_bundle_chain = orig
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["summary"]["content_keys_verified"], 1)
        self.assertEqual(len(result["rejected_submissions"]), 3)
        self.assertEqual(result["nodes"], [])


# ------------------------------------------------------------------
# H-01' (a): tiny cap - deferral, never rejection, order-free
# ------------------------------------------------------------------

class TestTinyCapDeferral(unittest.TestCase):

    def test_genuine_is_deferred_never_rejected_order_free(self):
        # Three devices, one chain each, cap 2. With no
        # carried-over keys, the valve allocates round-robin
        # across devices in device_id order, so the device whose
        # id sorts LAST is the one deferred - assign the genuine
        # bundle to it and signed garbage to the other two.
        candidates = {seed: make_bundle(seed, SCORED_AT - 40 * DAY, 48)
                      for seed in (61, 90, 91)}
        by_device = sorted(candidates.values(),
                           key=lambda b: b["device_id"])
        # The garbage must be signed by its OWN device key (an
        # unsigned forgery fails stage A and consumes nothing -
        # the flood that matters is signed garbage).
        seed_of = {b["device_id"]: s for s, b in candidates.items()}
        garbage = [signed_broken_chain(
            by_device[i], seed_of[by_device[i]["device_id"]])
            for i in range(2)]
        genuine = by_device[2]
        g1, g2 = garbage
        orders = [
            [submission(g1, "a1"), submission(g2, "a2"),
             submission(genuine, "owner")],
            [submission(genuine, "owner"), submission(g1, "a1"),
             submission(g2, "a2")],
            [submission(g2, "a2"), submission(genuine, "owner"),
             submission(g1, "a1")],
        ]
        deferred_sets = []
        for subs in orders:
            result = score(subs, max_content_keys=2)
            # Nothing scores: the garbage fails its chain, the
            # genuine bundle is deferred.
            self.assertEqual(result["nodes"], [])
            # The garbage is rejected (verified, failed); the
            # genuine bundle is NOT among the rejected.
            self.assertEqual(
                {r["claimed_device_id"]
                 for r in result["rejected_submissions"]},
                {g1["device_id"], g2["device_id"]})
            self.assertNotIn(
                genuine["device_id"],
                {r["claimed_device_id"]
                 for r in result["rejected_submissions"]})
            # The genuine bundle is deferred, with the deferral
            # stated as such, and the run is marked provisional.
            self.assertEqual(len(result["deferred_submissions"]), 1)
            deferred = result["deferred_submissions"][0]
            self.assertEqual(deferred["claimed_device_id"],
                             genuine["device_id"])
            self.assertIn("deferred", deferred["reasons"][0])
            self.assertEqual(result["summary"]["deferred_count"], 1)
            self.assertEqual(
                result["summary"]["content_keys_deferred"], 1)
            self.assertFalse(result["summary"]["complete"])
            deferred_sets.append(
                deferred["claimed_device_id"])
        # Deferral set membership is identical under every
        # arrival order.
        self.assertEqual(deferred_sets, [genuine["device_id"]] * 3)


# ------------------------------------------------------------------
# H-02' (b): representation variants collapse to one key
# ------------------------------------------------------------------

class TestRepresentationVariants(unittest.TestCase):

    def _variant_family(self):
        """One chain of 3 checkpoints with NO witnesses; the 8
        signed variants toggle, per checkpoint, whether the
        empty witness list is omitted or written explicitly -
        the audit's 2^C reproduction family."""
        base = make_bundle(71, SCORED_AT - 40 * DAY, 3)
        for cp in base["checkpoints"]:
            self.assertNotIn("witness_peer_hashes", cp)
        variants = []
        for mask in range(8):
            variant = copy.deepcopy(base)
            for i in range(3):
                if mask & (1 << i):
                    variant["checkpoints"][i][
                        "witness_peer_hashes"] = []
            variants.append(resign(variant, 71))
        return variants

    def test_variants_share_one_content_key(self):
        keys = {core.bundle_content_key(v, profile=PROFILE)
                for v in self._variant_family()}
        self.assertEqual(len(keys), 1)

    def test_variants_share_one_chain_verification(self):
        variants = self._variant_family()
        calls, orig, wrapper = counting_chain()
        core.verify_bundle_chain = wrapper
        try:
            result = score([submission(v, "owner") for v in variants])
        finally:
            core.verify_bundle_chain = orig
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["summary"]["content_keys_verified"], 1)
        # All 8 merge onto the single node of the one chain.
        self.assertEqual(len(result["nodes"]), 1)
        n = result["nodes"][0]
        self.assertEqual(n["device_id"], device_id(71))
        self.assertEqual(n["status"], "ok")
        self.assertEqual(result["rejected_submissions"], [])
        self.assertEqual(result["deferred_submissions"], [])


# ------------------------------------------------------------------
# M-05 (c): spot duplicates verified once, pooled once
# ------------------------------------------------------------------

class TestSpotDuplicates(unittest.TestCase):

    def test_five_copies_one_verification_one_pool_entry(self):
        bundle = make_bundle(81, SCORED_AT - 40 * DAY, 48)
        challenge = hashlib.sha256(b"v08-challenge").digest()
        target = scorer.derive_spot_target_index(48, challenge)
        value = scorer.spot_response_value(
            bytes.fromhex(
                bundle["checkpoints"][target]["best_block_hash"]),
            b"synthetic-block-body")
        record = owner_record(bundle, 81, challenge, target, value)
        expectations = {bundle["bundle_hash"]: {
            "challenge_block_hash": challenge.hex(),
            "expected": value.hex()}}

        verify_calls = []
        orig_verify = core.verify_spot_response

        def counting_verify(*a, **kw):
            verify_calls.append(1)
            return orig_verify(*a, **kw)

        pool_sizes = []
        orig_eval = scorer.evaluate_spot_records

        def capturing_eval(b, records, trusted):
            pool_sizes.append(len(records))
            return orig_eval(b, records, trusted)

        core.verify_spot_response = counting_verify
        scorer.evaluate_spot_records = capturing_eval
        try:
            result = score(
                [submission(bundle, "owner", spot_check=record)
                 for _ in range(5)],
                spot_expectations=expectations)
        finally:
            core.verify_spot_response = orig_verify
            scorer.evaluate_spot_records = orig_eval

        # Exactly ONE signature verification and ONE pool entry,
        # however many exact copies were submitted.
        self.assertEqual(len(verify_calls), 1)
        self.assertEqual(pool_sizes, [1])
        self.assertEqual(result["summary"]["duplicates_ignored"], 4)
        n = node_by_id(result, device_id(81))
        self.assertEqual(n["status"], "ok")
        self.assertEqual(n["spot_check"], "passed")


# ------------------------------------------------------------------
# L-01 (d): strict intake
# ------------------------------------------------------------------

class TestStrictIntake(unittest.TestCase):

    def test_strict_loader_refuses_nan_infinity_and_duplicate_keys(self):
        for text in ('{"a": NaN}', '{"a": Infinity}',
                     '{"a": -Infinity}', '{"a": 1, "a": 2}',
                     '{"outer": {"x": 1, "x": 2}}'):
            with self.assertRaises(ValueError, msg=text):
                core.strict_json_loads(text)
        ok = core.strict_json_loads('{"a": [1, 2.5, {"b": "x"}]}')
        self.assertEqual(ok["a"][2]["b"], "x")

    def test_cli_score_refuses_bad_bundle_files_at_load(self):
        genuine = make_bundle(83, SCORED_AT - 40 * DAY, 48)
        good_text = json.dumps(genuine)
        nan_text = good_text.replace(
            '"created_at_unix": %d' % genuine["created_at_unix"],
            '"created_at_unix": NaN')
        self.assertIn("NaN", nan_text)
        dup_text = '{"version": "0.5", ' + good_text[1:]
        with tempfile.TemporaryDirectory() as tmp:
            paths = {}
            for name, text in (("nan.json", nan_text),
                               ("dup.json", dup_text),
                               ("good.json", good_text)):
                paths[name] = os.path.join(tmp, name)
                with open(paths[name], "w", encoding="utf-8") as f:
                    f.write(text)
            input_path = os.path.join(tmp, "input.json")
            with open(input_path, "w", encoding="utf-8") as f:
                json.dump({"submissions": [
                    {"bundle_path": "nan.json", "account": "a"},
                    {"bundle_path": "dup.json", "account": "b"},
                    {"bundle_path": "good.json", "account": "c"},
                ]}, f)
            out_path = os.path.join(tmp, "report.json")
            rc = cli.main(["score", "--input", input_path,
                           "--out", out_path,
                           "--scored-at-unix", str(SCORED_AT),
                           "--profile", PROFILE])
            self.assertEqual(rc, 0)
            with open(out_path, "r", encoding="utf-8") as f:
                report = json.load(f)
        # Both poisoned files are refused at load with the strict
        # reason; the run completes and the clean bundle scores.
        load_rejected = [r for r in report["rejected_submissions"]
                         if "submission load error" in r["reasons"][0]]
        self.assertEqual(len(load_rejected), 2)
        for entry in load_rejected:
            self.assertIn("strict JSON", entry["reasons"][0])
        self.assertEqual(len(report["nodes"]), 1)
        self.assertEqual(report["nodes"][0]["device_id"],
                         device_id(83))


# ------------------------------------------------------------------
# L-02 (e): spot summary is order-independent
# ------------------------------------------------------------------

class TestSpotSummaryOrderIndependence(unittest.TestCase):

    def _signed_record(self, bundle, seed_byte, challenge, wrong=False):
        target = scorer.derive_spot_target_index(
            len(bundle["checkpoints"]), challenge)
        good = scorer.spot_response_value(
            bytes.fromhex(
                bundle["checkpoints"][target]["best_block_hash"]),
            b"synthetic-block-body")
        value = bytes([good[0] ^ 0xFF]) + good[1:] if wrong else good
        record = owner_record(bundle, seed_byte, challenge, target,
                              value)
        expectation = {"challenge_block_hash": challenge.hex(),
                       "expected": good.hex()}
        return record, expectation

    def test_disqualified_node_spot_check_failed_in_both_orders(self):
        failing = make_bundle(85, SCORED_AT - 40 * DAY, 48)
        passing = make_bundle(85, SCORED_AT - 90 * DAY, 48)
        chal_f = hashlib.sha256(b"v08-chal-fail").digest()
        chal_p = hashlib.sha256(b"v08-chal-pass").digest()
        rec_f, exp_f = self._signed_record(failing, 85, chal_f,
                                           wrong=True)
        rec_p, exp_p = self._signed_record(passing, 85, chal_p)
        expectations = {failing["bundle_hash"]: exp_f,
                        passing["bundle_hash"]: exp_p}
        orders = [
            [submission(failing, "owner", spot_check=rec_f),
             submission(passing, "owner", spot_check=rec_p)],
            [submission(passing, "owner", spot_check=rec_p),
             submission(failing, "owner", spot_check=rec_f)],
        ]
        for subs in orders:
            result = score(subs, spot_expectations=expectations)
            n = node_by_id(result, device_id(85))
            self.assertEqual(n["status"], "disqualified")
            self.assertEqual(n["spot_check"], "failed")
            self.assertEqual(n["adjusted_weight"], 0.0)

    def test_passed_beats_unsigned_in_both_orders(self):
        unsigned_bundle = make_bundle(86, SCORED_AT - 140 * DAY, 48)
        passing = make_bundle(86, SCORED_AT - 90 * DAY, 48)
        chal_u = hashlib.sha256(b"v08-chal-unsigned").digest()
        chal_p = hashlib.sha256(b"v08-chal-pass2").digest()
        _rec_u, exp_u = self._signed_record(unsigned_bundle, 86,
                                            chal_u)
        rec_p, exp_p = self._signed_record(passing, 86, chal_p)
        expectations = {unsigned_bundle["bundle_hash"]: exp_u,
                        passing["bundle_hash"]: exp_p}
        unsigned_record = {"response": "00"}  # not a signed record
        orders = [
            [submission(unsigned_bundle, "owner", spot_check=unsigned_record),
             submission(passing, "owner", spot_check=rec_p)],
            [submission(passing, "owner", spot_check=rec_p),
             submission(unsigned_bundle, "owner", spot_check=unsigned_record)],
        ]
        for subs in orders:
            result = score(subs, spot_expectations=expectations)
            n = node_by_id(result, device_id(86))
            self.assertEqual(n["status"], "ok")
            self.assertEqual(n["spot_check"], "passed")


# ------------------------------------------------------------------
# A1: a copied signature on a rewritten body cannot suppress the
# genuine correction (fingerprint = the whole record)
# ------------------------------------------------------------------

class TestSpotForgeryCannotSuppressCorrection(unittest.TestCase):

    def test_forgery_is_ignored_on_its_own_signature_failure(self):
        bundle = make_bundle(82, SCORED_AT - 40 * DAY, 48)
        challenge = hashlib.sha256(b"v08-a1-challenge").digest()
        target = scorer.derive_spot_target_index(48, challenge)
        good = scorer.spot_response_value(
            bytes.fromhex(
                bundle["checkpoints"][target]["best_block_hash"]),
            b"synthetic-block-body")
        wrong = bytes([good[0] ^ 0xFF]) + good[1:]
        expectations = {bundle["bundle_hash"]: {
            "challenge_block_hash": challenge.hex(),
            "expected": good.hex()}}
        # The owner's first answer is wrong (rev 0); the genuine
        # correction R2 (rev 1) fixes it. The attacker copies
        # R2's SIGNATURE onto a rewritten body (the wrong
        # response again) - R2' shares R2's signature and
        # revision but not its content.
        r_wrong = owner_record(bundle, 82, challenge, target, wrong,
                               revision=0)
        r2 = owner_record(bundle, 82, challenge, target, good,
                          revision=1)
        r2_forged = dict(r2)
        r2_forged["response"] = wrong.hex()
        self.assertEqual(r2_forged["signature"], r2["signature"])
        self.assertNotEqual(r2_forged["response"], r2["response"])

        pool_sizes = []
        orig_eval = scorer.evaluate_spot_records

        def capturing_eval(b, records, trusted):
            pool_sizes.append(len(records))
            return orig_eval(b, records, trusted)

        scorer.evaluate_spot_records = capturing_eval
        try:
            for records in ([r2_forged, r_wrong, r2],
                            [r2, r2_forged, r_wrong]):
                result = score(
                    [submission(bundle, "owner", spot_check=r)
                     for r in records],
                    spot_expectations=expectations)
                n = node_by_id(result, device_id(82))
                # The genuine correction survives and wins: the
                # forgery neither occupies its slot nor poisons
                # it - it is ignored on its OWN signature
                # failure, in either arrival order.
                self.assertEqual(n["status"], "ok")
                self.assertEqual(n["spot_check"], "passed")
        finally:
            scorer.evaluate_spot_records = orig_eval
        # All three records are distinct pool entries (the
        # forgery is NOT collapsed into the genuine record).
        self.assertEqual(pool_sizes, [3, 3])


# ------------------------------------------------------------------
# A2/A3: deferral carryover priority and provisional marking
# ------------------------------------------------------------------

class TestDeferralCarryover(unittest.TestCase):

    def test_carried_over_key_goes_before_new_smaller_keys(self):
        bundle_a = make_bundle(51, SCORED_AT - 40 * DAY, 48)
        bundle_b = make_bundle(52, SCORED_AT - 40 * DAY, 48)
        # Run 1, cap 1: one device is verified, the other is
        # deferred (round-robin by device order - which one does
        # not matter for what follows).
        run1 = score([submission(bundle_a, "a"),
                      submission(bundle_b, "b")], max_content_keys=1)
        self.assertFalse(run1["summary"]["complete"])
        self.assertEqual(run1["summary"]["deferred_count"], 1)
        self.assertEqual(len(run1["deferred_submissions"]), 1)
        deferred_id = run1["deferred_submissions"][0][
            "claimed_device_id"]
        deferred_bundle = bundle_a if bundle_a["device_id"] == \
            deferred_id else bundle_b
        carried_key = core.bundle_content_key(
            deferred_bundle, profile=PROFILE)
        # A brand-new device whose content key is SMALLER than
        # the carried key: under pure key order it would win the
        # single slot in run 2 and starve the carried key again.
        newcomer = None
        for seed_byte in range(100, 160):
            candidate = make_bundle(seed_byte, SCORED_AT - 40 * DAY,
                                    48)
            if core.bundle_content_key(
                    candidate, profile=PROFILE) < carried_key:
                newcomer = candidate
                break
        self.assertIsNotNone(newcomer)
        # Run 2: the carried-over key is processed FIRST, so the
        # previously deferred bundle is verified and scored; the
        # newcomer is deferred instead.
        run2 = score([submission(newcomer, "new"),
                      submission(deferred_bundle, "owner")],
                     max_content_keys=1,
                     carried_over_keys={carried_key})
        self.assertIsNotNone(node_by_id(run2, deferred_id))
        self.assertEqual(
            [d["claimed_device_id"]
             for d in run2["deferred_submissions"]],
            [newcomer["device_id"]])
        self.assertFalse(run2["summary"]["complete"])
        # Run 3: with room for everything, the run is complete.
        run3 = score([submission(newcomer, "new"),
                      submission(deferred_bundle, "owner")],
                     carried_over_keys={carried_key})
        self.assertTrue(run3["summary"]["complete"])
        self.assertEqual(run3["deferred_submissions"], [])


# ------------------------------------------------------------------
# A5: failure caching covers deterministic verdicts only
# ------------------------------------------------------------------

class TestFailureCacheClassification(unittest.TestCase):

    def test_interrupted_verification_defers_never_rejects(self):
        bundle = make_bundle(97, SCORED_AT - 40 * DAY, 48)
        orig = core.verify_bundle_chain

        def boom(b, profile="production"):
            raise TimeoutError("simulated interruption")

        core.verify_bundle_chain = boom
        try:
            result = score([submission(bundle, "owner")])
        finally:
            core.verify_bundle_chain = orig
        # An interruption is not a content verdict: the key is
        # deferred (and the run provisional), never rejected.
        self.assertEqual(result["rejected_submissions"], [])
        self.assertEqual(len(result["deferred_submissions"]), 1)
        self.assertIn("interrupted",
                      result["deferred_submissions"][0]["reasons"][0])
        self.assertFalse(result["summary"]["complete"])

    def test_deterministic_failure_is_a_rejection_not_deferral(self):
        broken = signed_broken_chain(
            make_bundle(98, SCORED_AT - 40 * DAY, 48), 98)
        result = score([submission(broken, "owner")])
        self.assertEqual(len(result["rejected_submissions"]), 1)
        self.assertEqual(result["deferred_submissions"], [])
        self.assertTrue(result["summary"]["complete"])


# ------------------------------------------------------------------
# First-seen anchoring: effective time = max(recorded, first seen)
# ------------------------------------------------------------------

class TestFirstSeenAnchoring(unittest.TestCase):
    """The effective existence time of a checkpoint is the LATER
    of its claimed recording time and the first time the
    aggregation witnessed its content (max rule, corrected from
    min with the user's approval on 2026-11-08: under min, a
    history back-computed today over old public block hashes
    kept its recorded - past - timestamps and matured in full).
    """

    def test_back_computed_history_earns_nothing_until_seen(self):
        # (a) Back-computation: a complete, old-looking history
        # (recorded timestamps a month in the past, long settled
        # under recorded-time semantics) that is FIRST submitted
        # at scoring time. Every checkpoint's effective time is
        # the first-seen instant, nothing is settled, and the
        # matured weight is zero: the history's clock starts
        # when the aggregation first saw it.
        bundle = make_bundle(96, SCORED_AT - 30 * DAY, 48)
        anchored = score([submission(bundle, "owner",
                                     submitted_at=SCORED_AT)])
        n = node_by_id(anchored, device_id(96))
        self.assertEqual(n["metrics"]["first_timestamp_unix"],
                         SCORED_AT)
        self.assertEqual(n["metrics"]["last_timestamp_unix"],
                         SCORED_AT)
        self.assertEqual(n["adjusted_weight"], 0.0)
        # Control: the SAME bundle with no arrival record at
        # all stands on its recorded timestamps and earns its
        # recorded-time maturity - the anchor, not the content,
        # is what zeroes the back-computed copy.
        bare = {"bundle": bundle, "account": "owner",
                "account_age_days": 0}
        unanchored = score([bare])
        n2 = node_by_id(unanchored, device_id(96))
        self.assertGreater(n2["adjusted_weight"], 0.0)
        self.assertEqual(n2["metrics"]["last_timestamp_unix"],
                         bundle["checkpoints"][-1]["timestamp_unix"])

    def test_future_dated_checkpoints_keep_their_claimed_time(self):
        # (b) Future-dated checkpoints under max: the anchor
        # does NOT pull a future claim back to first-seen (that
        # was the min rule). The effective time is the claimed
        # time itself, and nothing settles early relative to
        # it: scored now, the weight is zero.
        bundle = make_bundle(95, SCORED_AT + 10 * DAY, 48)
        recorded_first = bundle["checkpoints"][0]["timestamp_unix"]
        recorded_last = bundle["checkpoints"][-1]["timestamp_unix"]
        self.assertGreater(recorded_first, SCORED_AT)
        anchored = score([submission(bundle, "owner",
                                     submitted_at=SCORED_AT)])
        n = node_by_id(anchored, device_id(95))
        self.assertEqual(n["metrics"]["first_timestamp_unix"],
                         recorded_first)
        self.assertEqual(n["metrics"]["last_timestamp_unix"],
                         recorded_last)
        self.assertEqual(n["adjusted_weight"], 0.0)

    def test_prompt_submission_keeps_recorded_time_maturity(self):
        # (c) Prompt submission: a history recorded over two
        # days, submitted one hour after its last checkpoint
        # (the submission() default) and scored eighteen days
        # later. First-seen ~= recorded time, so it keeps the
        # maturity it would have had with no anchor at all.
        bundle = make_bundle(97, SCORED_AT - 20 * DAY, 288)
        recorded_last = bundle["checkpoints"][-1]["timestamp_unix"]
        anchored = score([submission(bundle, "owner")])
        n = node_by_id(anchored, device_id(97))
        self.assertGreater(n["adjusted_weight"], 0.0)
        # Batch anchoring: every checkpoint of the promptly
        # submitted bundle is witnessed at the submission
        # instant, so the effective span collapses to it.
        self.assertEqual(n["metrics"]["first_timestamp_unix"],
                         recorded_last + 3600)
        self.assertEqual(n["metrics"]["last_timestamp_unix"],
                         recorded_last + 3600)
        bare = {"bundle": bundle, "account": "owner",
                "account_age_days": 0}
        unanchored = score([bare])
        n2 = node_by_id(unanchored, device_id(97))
        self.assertAlmostEqual(n["adjusted_weight"],
                               n2["adjusted_weight"], places=9)


if __name__ == "__main__":
    unittest.main()
