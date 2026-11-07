"""Regression tests for the SPEC v0.6 rules revision (adversarial
battery against v0.5, 2026-11-07). The bundle format does NOT
change in this round (version stays "0.5"); only the scorer's
cap rule and the spot record's encoding discipline change:

  B3-F1  the v0.5 component-wide cap pool diluted every
         non-strongest honest member of a bridged honest mutual
         group (up to -86% in the battery). The cap is now
         BLOCK-LOCAL: closed mutual components are decomposed
         into vertex-biconnected blocks (Tarjan); each block's
         factor comes from the FULL sum of its members against
         a cap of 2x the strongest base weight among ALL its
         members, and a member's scale is the MINIMUM factor
         over all blocks containing it.
         AMENDMENT (v0.6, before any production scoring): the
         first v0.6 draft used a counting assignment - each
         member counted in exactly ONE of its blocks, the one
         minimising the strongest other member - and a
         randomized bridge check then showed the articulation
         escape: a clique member bridging to an honest node
         was counted in the never-binding bridge block instead
         of its clique (farm total 8.0 -> 10.77), and an honest
         member could likewise escape its own cluster's
         discount via a bridge. The min-factor rule above
         replaces the assignment; single-bridge invariance in
         both directions is pinned below, deterministically
         (cases d and e) and randomized (24 seeded scenarios).
         Case (a) of the round - the original R-H02 laundering
         setup (farm clique 50 x 1.0 + honest 13.4164 on one
         mutual edge -> farm 2.0000, honest untouched) - is
         pinned by test_v05.py::TestClusterCapV2.
         test_laundering_attack_neutralised, which still passes
         under the block rule; this file pins (b) the battery's
         minimal dilution case, (c) its amplification case,
         (d) the strongest-tie case, and (f) the ring, plus the
         block decomposition itself. The star case (g) lives in
         test_v05.py with its v0.6 expectation (uncapped,
         documented residual, SPEC v0.6 section 7).
  Fix 2  spot records must carry response/signature as
         lowercase canonical hex (battery 2's parity nit):
         uppercase or mixed-case hex classifies the record as
         "unsigned" - ignored, never disqualifying, never
         passing on its own. This file also holds, IN ONE
         PLACE, the full spot-record mutation family: field
         added / removed / rewritten / reordered, and
         omitted-vs-explicit forms.

Run: python3 -m unittest discover -s tests -v   (from depin/)
Standard library only.
"""

import hashlib
import math
import os
import random
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
                ("v06-%d-%d" % (seed_byte, number)).encode()).hexdigest(),
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


def days_bundle(seed_byte, days, witnesses=None, end_days_ago=10):
    """A bundle of `days` settled days (weight sqrt(days))."""
    return make_bundle(seed_byte,
                       SCORED_AT - (end_days_ago + days) * DAY,
                       days * 144, witnesses=witnesses)


def assert_uncapped(test_case, node, expected_weight):
    test_case.assertAlmostEqual(node["adjusted_weight"],
                                expected_weight, places=4)
    test_case.assertFalse(
        any(f.startswith("closed_cluster") for f in node["flags"]),
        node["flags"])


# ------------------------------------------------------------------
# block decomposition (unit level)
# ------------------------------------------------------------------

class TestBiconnectedBlocks(unittest.TestCase):
    def blocks(self, edges, nodes):
        mutual = {d: set() for d in nodes}
        for a, b in edges:
            mutual[a].add(b)
            mutual[b].add(a)
        return scorer._biconnected_blocks(sorted(nodes), mutual)

    def test_triangle_with_bridge_tail(self):
        got = self.blocks(
            [("a", "b"), ("b", "c"), ("c", "a"), ("c", "d")],
            "abcd")
        self.assertEqual(got, [frozenset("abc"), frozenset("cd")])

    def test_clique_with_bridge_and_leaf(self):
        nodes = "abcdef"
        edges = [(a, b) for i, a in enumerate("abcd")
                 for b in "abcd"[i + 1:]]
        edges += [("d", "e"), ("e", "f")]
        got = self.blocks(edges, nodes)
        self.assertEqual(got, [frozenset("abcd"), frozenset("de"),
                               frozenset("ef")])

    def test_star_is_all_size_two_blocks(self):
        got = self.blocks(
            [("o", "x"), ("o", "y"), ("o", "z")], "oxyz")
        self.assertEqual(got, [frozenset("ox"), frozenset("oy"),
                               frozenset("oz")])

    def test_ring_is_one_block(self):
        nodes = ["r%d" % i for i in range(5)]
        edges = [(nodes[i], nodes[(i + 1) % 5]) for i in range(5)]
        got = self.blocks(edges, nodes)
        self.assertEqual(got, [frozenset(nodes)])

    def test_two_triangles_sharing_a_vertex(self):
        got = self.blocks(
            [("a", "b"), ("b", "c"), ("c", "a"),
             ("a", "d"), ("d", "e"), ("e", "a")],
            "abcde")
        self.assertEqual(got, [frozenset("abc"), frozenset("ade")])


# ------------------------------------------------------------------
# B3-F1: block-local caps
# ------------------------------------------------------------------

class TestBlockLocalCap(unittest.TestCase):
    def test_b_battery_minimal_dilution_case(self):
        # Battery scenario 8, minimised: an honest pairwise-mutual
        # triangle {90d, 30d, 3d} plus ONE 20d farm node mutually
        # linked ONLY to the 30d node. v0.5 pooled the component
        # and cut the 30d node 5.4772 -> 5.1364 and the 3d node
        # 1.7321 -> 1.6243. Block-local: the bridge edge is its
        # own size-2 block, so nobody is scaled at all.
        h90, h30, h3, farm = (device_id(s)
                              for s in (160, 161, 162, 163))
        subs = [
            submission(days_bundle(160, 90, witnesses=[h30, h3]),
                       "h90"),
            submission(days_bundle(161, 30,
                                   witnesses=[h90, h3, farm]),
                       "h30"),
            submission(days_bundle(162, 3, witnesses=[h90, h30]),
                       "h3"),
            submission(days_bundle(163, 20, witnesses=[h30]),
                       "farm"),
        ]
        result = score(subs)
        assert_uncapped(self, node_by_id(result, h90), math.sqrt(90))
        assert_uncapped(self, node_by_id(result, h30), math.sqrt(30))
        assert_uncapped(self, node_by_id(result, h3), math.sqrt(3))
        assert_uncapped(self, node_by_id(result, farm), math.sqrt(20))
        self.assertEqual(
            result["summary"]["closed_clusters_capped"], 0)

    def test_c_battery_amplification_case(self):
        # Honest triangle {200d, 30d, 3d} plus a 30-node farm
        # clique of 6d nodes, one mutual edge from one farm node
        # to the 30d honest node. v0.5 cut the 30d node to
        # 0.7435 (-86.4%). Block-local: the honest triangle's
        # block never binds, the farm clique is capped inside
        # its own block at 2 x sqrt(6), the bridge binds nobody.
        h200, h30, h3 = (device_id(s) for s in (170, 171, 172))
        farm_seeds = list(range(180, 210))
        farm_ids = [device_id(s) for s in farm_seeds]
        subs = [
            submission(days_bundle(170, 200, witnesses=[h30, h3]),
                       "h200"),
            submission(days_bundle(
                171, 30, witnesses=[h200, h3, farm_ids[0]]), "h30"),
            submission(days_bundle(172, 3, witnesses=[h200, h30]),
                       "h3"),
        ]
        for i, s in enumerate(farm_seeds):
            w = list(farm_ids)
            if i == 0:
                w.append(h30)
            subs.append(submission(days_bundle(s, 6, witnesses=w),
                                   "farm-%d" % s))
        result = score(subs)
        assert_uncapped(self, node_by_id(result, h200),
                        math.sqrt(200))
        assert_uncapped(self, node_by_id(result, h30), math.sqrt(30))
        assert_uncapped(self, node_by_id(result, h3), math.sqrt(3))
        farm_total = sum(node_by_id(result, d)["adjusted_weight"]
                         for d in farm_ids)
        self.assertAlmostEqual(farm_total, 2.0 * math.sqrt(6),
                               places=4)
        for d in farm_ids:
            n = node_by_id(result, d)
            self.assertTrue(any(f.startswith("closed_cluster_discount")
                                for f in n["flags"]), n["flags"])
        self.assertEqual(
            result["summary"]["closed_clusters_capped"], 1)

    def test_d_strongest_tie_case(self):
        # Battery scenario 49 subtype: two honest nodes TIE for
        # strongest, which voided the v0.5 unique-strongest
        # exemption and pooled everyone. Honest triangle
        # {90d, 90d, 30d} plus a 20d farm node bridged to one of
        # the 90d nodes.
        #
        # AMENDED expectation (min-factor rule): the triangle is
        # a capped cluster ON ITS OWN (full sum 2*sqrt(90) +
        # sqrt(30) exceeds the cap 2*sqrt(90)), so its members
        # carry the cluster's own factor with or without the
        # bridge, and the bridge changes nothing at all. The
        # first v0.6 draft expected everyone at full base here -
        # but that outcome WAS the articulation escape: the
        # bridged 90d node was counted in the size-2 bridge
        # block, the triangle's counted sum dropped under its
        # cap, and the cluster's own discount vanished. The tie
        # itself remains irrelevant: no exemption concept exists
        # for it to void.
        ha, hb, h30, farm = (device_id(s)
                             for s in (215, 216, 217, 218))
        honest_subs = [
            submission(days_bundle(215, 90,
                                   witnesses=[hb, h30, farm]),
                       "ha"),
            submission(days_bundle(216, 90, witnesses=[ha, h30]),
                       "hb"),
            submission(days_bundle(217, 30, witnesses=[ha, hb]),
                       "h30"),
        ]
        farm_sub = submission(days_bundle(218, 20, witnesses=[ha]),
                              "farm")
        factor = (2.0 * math.sqrt(90)
                  / (2.0 * math.sqrt(90) + math.sqrt(30)))
        alone = score(honest_subs)
        bridged = score(honest_subs + [farm_sub])
        for did, days in ((ha, 90), (hb, 90), (h30, 30)):
            expected = math.sqrt(days) * factor
            self.assertAlmostEqual(
                node_by_id(alone, did)["adjusted_weight"],
                expected, places=4)
            self.assertAlmostEqual(
                node_by_id(bridged, did)["adjusted_weight"],
                expected, places=4)
        assert_uncapped(self, node_by_id(bridged, farm),
                        math.sqrt(20))

    def test_g_articulation_escape_farm_clique(self):
        # The parent's randomized-check case, pinned: a farm
        # clique of 30 x 6d nodes caps at T = 2*sqrt(6) standing
        # alone. Bridging ONE clique member to a lone honest
        # node by a single mutual edge must not move the farm
        # total at all. Under the counting assignment the
        # bridged member was counted in the size-2 bridge block:
        # it kept its full base outside the clique's cap AND
        # the clique's counted sum shrank, loosening everyone
        # else's scale. Under the min-factor rule the bridged
        # member belongs to the clique block for accounting no
        # matter what else it joins, so its scale is the
        # clique's factor.
        farm_seeds = list(range(40, 70))
        farm_ids = [device_id(s) for s in farm_seeds]
        honest_id = device_id(75)
        farm_subs = []
        for i, s in enumerate(farm_seeds):
            w = list(farm_ids)
            if i == 0:
                w.append(honest_id)
            farm_subs.append(submission(
                days_bundle(s, 6, witnesses=w), "farm-%d" % s))
        alone = score(farm_subs)
        t_alone = sum(node_by_id(alone, d)["adjusted_weight"]
                      for d in farm_ids)
        self.assertAlmostEqual(t_alone, 2.0 * math.sqrt(6),
                               places=4)
        bridged = score(farm_subs + [submission(
            days_bundle(75, 45, witnesses=[farm_ids[0]]),
            "honest")])
        t_bridged = sum(node_by_id(bridged, d)["adjusted_weight"]
                        for d in farm_ids)
        self.assertAlmostEqual(t_bridged, 2.0 * math.sqrt(6),
                               places=4)
        self.assertAlmostEqual(t_bridged, t_alone, places=9)
        assert_uncapped(self, node_by_id(bridged, honest_id),
                        math.sqrt(45))

    def test_h_honest_cluster_bridge_invariance(self):
        # Mirror image of the escape: a CAPPED honest cluster
        # (4 nodes in a cycle of 9d each: block sum 12.0 over
        # the cap 6.0, so everyone is scaled 0.5 standing
        # alone). Attaching an arbitrary single-edge farm
        # bridge to one member must leave every honest weight
        # IDENTICAL - the bridge cannot loosen the cluster's
        # own discount. (Under the counting assignment the
        # bridged member was counted in the bridge block and
        # the cycle's counted sum fell, loosening the rest.)
        seeds = [80, 81, 82, 83]
        ids = [device_id(s) for s in seeds]
        farm_id = device_id(85)
        honest_subs = []
        for i, s in enumerate(seeds):
            w = [ids[i - 1], ids[(i + 1) % len(ids)]]
            if i == 0:
                w.append(farm_id)
            honest_subs.append(submission(
                days_bundle(s, 9, witnesses=w), "h%d" % s))
        alone = score(honest_subs)
        for d in ids:
            self.assertAlmostEqual(
                node_by_id(alone, d)["adjusted_weight"], 1.5,
                places=4)
        bridged = score(honest_subs + [submission(
            days_bundle(85, 4, witnesses=[ids[0]]), "farm")])
        for d in ids:
            n = node_by_id(bridged, d)
            self.assertAlmostEqual(n["adjusted_weight"], 1.5,
                                   places=4)
            self.assertAlmostEqual(
                n["adjusted_weight"],
                node_by_id(alone, d)["adjusted_weight"], places=9)
        assert_uncapped(self, node_by_id(bridged, farm_id), 2.0)

    def test_f_ring_farm_is_a_single_capped_block(self):
        # A cycle has no articulation point, so the whole ring
        # is one biconnected block: the cap binds exactly as it
        # did for a component in v0.4/v0.5 (total 2 x max).
        seeds = list(range(230, 240))
        ids = [device_id(s) for s in seeds]
        subs = []
        for i, s in enumerate(seeds):
            w = [ids[i - 1], ids[(i + 1) % len(ids)]]
            subs.append(submission(
                days_bundle(s, 1, witnesses=w, end_days_ago=10),
                "ring-%d" % s))
        result = score(subs)
        total = sum(n["adjusted_weight"] for n in result["nodes"])
        self.assertAlmostEqual(total, 2.0, places=4)
        for n in result["nodes"]:
            self.assertAlmostEqual(n["adjusted_weight"], 0.2,
                                   places=4)
            self.assertTrue(any(
                f.startswith("closed_cluster_discount")
                for f in n["flags"]), n["flags"])
        self.assertEqual(
            result["summary"]["closed_clusters_capped"], 1)


# ------------------------------------------------------------------
# randomized single-bridge invariance (mirrors the parent's
# randomized bridge check at small scale)
# ------------------------------------------------------------------

class TestRandomizedBridgeInvariance(unittest.TestCase):
    def test_single_bridge_invariance_randomized(self):
        # 24 seeded scenarios: an honest group (clique or cycle)
        # and a farm clique, joined by exactly ONE mutual edge
        # between a randomly chosen pair. Invariants, both
        # directions: every honest weight equals its honest-only
        # value, and the farm total equals its farm-only value.
        # (The extra witness entry each side carries for the
        # bridge partner is inert in the group-only runs: the
        # partner is not a participant there, so no mutual edge
        # forms.) Small durations keep the scenario count cheap.
        rng = random.Random(20261107)
        for trial in range(24):
            hn = rng.randint(3, 5)
            fn = rng.randint(3, 6)
            h_days = [rng.randint(1, 8) for _ in range(hn)]
            f_days = [rng.randint(1, 6) for _ in range(fn)]
            h_seeds = [60 + i for i in range(hn)]
            f_seeds = [100 + i for i in range(fn)]
            h_ids = [device_id(s) for s in h_seeds]
            f_ids = [device_id(s) for s in f_seeds]
            hi = rng.randrange(hn)
            fi = rng.randrange(fn)
            cycle = rng.random() < 0.5
            h_subs = []
            for i, s in enumerate(h_seeds):
                if cycle:
                    w = [h_ids[i - 1], h_ids[(i + 1) % hn]]
                else:
                    w = list(h_ids)
                if i == hi:
                    w = w + [f_ids[fi]]
                h_subs.append(submission(
                    days_bundle(s, h_days[i], witnesses=w),
                    "h%d" % i))
            f_subs = []
            for j, s in enumerate(f_seeds):
                w = list(f_ids)
                if j == fi:
                    w = w + [h_ids[hi]]
                f_subs.append(submission(
                    days_bundle(s, f_days[j], witnesses=w),
                    "f%d" % j))
            combined = score(h_subs + f_subs)
            honest_only = score(h_subs)
            farm_only = score(f_subs)
            with self.subTest(trial=trial):
                for d in h_ids:
                    self.assertAlmostEqual(
                        node_by_id(combined, d)["adjusted_weight"],
                        node_by_id(honest_only, d)["adjusted_weight"],
                        delta=1e-6)
                t_combined = sum(
                    node_by_id(combined, d)["adjusted_weight"]
                    for d in f_ids)
                t_alone = sum(
                    node_by_id(farm_only, d)["adjusted_weight"]
                    for d in f_ids)
                self.assertAlmostEqual(t_combined, t_alone,
                                       delta=1e-6)


# ------------------------------------------------------------------
# spot records: canonical hex + the full mutation family, in
# ONE place (signed-protocol mutation-testing discipline)
# ------------------------------------------------------------------

def spot_setup(seed_byte=77, count=48):
    bundle = make_bundle(seed_byte, SCORED_AT - 40 * DAY, count)
    challenge = hashlib.sha256(b"v06-challenge").digest()
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


class TestSpotMutationFamily(unittest.TestCase):
    """Every mutation of a genuine owner-signed record, in one
    place. Rule (SPEC section 11): a mutation that touches the
    signed content (or the record's required form) makes the
    record "unsigned" - ignored, never disqualifying, never
    passing on its own; a mutation outside the signed content
    (unknown extra key, JSON key order) is inert and the record
    still speaks for the owner. A byte-exact genuine record
    passes; a genuinely wrong owner-signed answer fails (the
    control at the end)."""

    @classmethod
    def setUpClass(cls):
        (cls.bundle, cls.challenge, cls.target, cls.good,
         cls.exp) = spot_setup()
        cls.genuine = owner_record(cls.bundle, 77, cls.challenge,
                                   cls.target, cls.good)

    def run_records(self, records):
        subs = [submission(self.bundle, "submitter-%d" % i, r)
                for i, r in enumerate(records)]
        result = score(subs, spot_expectations=self.exp)
        return node_by_id(result, self.bundle["device_id"])

    def assert_ignored(self, record):
        # Alone: not passed, not disqualifying.
        n = self.run_records([record])
        self.assertEqual(n["status"], "ok")
        self.assertEqual(n["spot_check"], "unsigned")
        self.assertGreater(n["adjusted_weight"], 0.0)
        # Beside the genuine record, in either order: the
        # genuine record decides, the mutation changes nothing.
        for records in ([record, self.genuine],
                        [self.genuine, record]):
            n = self.run_records(records)
            self.assertEqual(n["status"], "ok")
            self.assertEqual(n["spot_check"], "passed")

    def test_field_added_unknown_key_is_inert(self):
        r = dict(self.genuine)
        r["comment"] = "attached by a third party"
        n = self.run_records([r])
        self.assertEqual(n["spot_check"], "passed")

    def test_fields_reordered_are_inert(self):
        r = dict(reversed(list(self.genuine.items())))
        n = self.run_records([r])
        self.assertEqual(n["spot_check"], "passed")

    def test_field_removed(self):
        for key in ("response", "signature", "target_seq",
                    "revision"):
            r = dict(self.genuine)
            del r[key]
            with self.subTest(removed=key):
                self.assert_ignored(r)

    def test_field_rewritten(self):
        cases = {}
        r = dict(self.genuine)
        r["response"] = hashlib.sha256(b"other").hexdigest()
        cases["response"] = r
        r = dict(self.genuine)
        sig = bytearray(bytes.fromhex(r["signature"]))
        sig[0] ^= 0x01
        r["signature"] = bytes(sig).hex()
        cases["signature"] = r
        r = dict(self.genuine)
        r["target_seq"] = self.target + 1
        cases["target_seq"] = r
        r = dict(self.genuine)
        r["revision"] = 1
        cases["revision"] = r
        for name, record in cases.items():
            with self.subTest(rewritten=name):
                self.assert_ignored(record)

    def test_omitted_vs_explicit_forms(self):
        # Explicit forms of "absent" that v0.4 conflated with a
        # signed -1: in protocol v2 all of them are malformed
        # (ignored), because target_seq/revision are required
        # exact integers >= 0 inside the signature.
        cases = {}
        r = dict(self.genuine)
        r["target_seq"] = -1
        cases["explicit_-1_target"] = r
        r = dict(self.genuine)
        r["target_seq"] = None
        cases["explicit_null_target"] = r
        r = dict(self.genuine)
        r["revision"] = None
        cases["explicit_null_revision"] = r
        r = dict(self.genuine)
        r["target_seq"] = str(self.target)
        cases["string_target"] = r
        r = dict(self.genuine)
        r["revision"] = True
        cases["bool_revision"] = r
        for name, record in cases.items():
            with self.subTest(form=name):
                self.assert_ignored(record)

    def test_noncanonical_hex_is_unsigned(self):
        # v0.6 (battery 2 parity nit): bytes.fromhex accepts
        # uppercase, but the record's hex fields follow the same
        # lowercase canonical discipline as the bundle schema.
        cases = {}
        r = dict(self.genuine)
        r["response"] = r["response"].upper()
        cases["uppercase_response"] = r
        r = dict(self.genuine)
        r["signature"] = r["signature"].upper()
        cases["uppercase_signature"] = r
        r = dict(self.genuine)
        resp = r["response"]
        r["response"] = "".join(
            c.upper() if i % 2 else c for i, c in enumerate(resp))
        cases["mixed_case_response"] = r
        r = dict(self.genuine)
        r["response"] = r["response"][:-1]  # odd length
        cases["odd_length_response"] = r
        r = dict(self.genuine)
        r["response"] = "0x" + r["response"]
        cases["prefixed_response"] = r
        for name, record in cases.items():
            with self.subTest(form=name):
                self.assert_ignored(record)

    def test_control_genuine_and_owner_wrong_answer(self):
        n = self.run_records([self.genuine])
        self.assertEqual(n["spot_check"], "passed")
        wrong = owner_record(self.bundle, 77, self.challenge,
                             self.target,
                             hashlib.sha256(b"wrong").digest())
        n = self.run_records([wrong])
        self.assertEqual(n["status"], "disqualified")
        self.assertEqual(n["adjusted_weight"], 0.0)


if __name__ == "__main__":
    unittest.main()
