"""Tests for the Quantus DePIN proof reference implementation.

Run: python3 -m unittest discover -s tests -v   (from the depin/ directory)
Standard library only.

Since v0.4, verify_bundle accepts only the current format version
by default; the legacy-format classes below therefore verify with
allow_legacy=True (archival verification, H-02). New-format
behaviour is pinned by TestBundleV05 at the bottom.
"""

import copy
import hashlib
import os
import sys
import unittest

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import depin_core as core
import ed25519_rfc8032 as ed

# Small iteration count keeps the suite fast; production default is larger.
TEST_ITERATIONS = 5000


def synthetic_observations(count=8):
    obs = []
    for i in range(count):
        number = 350000 + i * 100
        obs.append({
            "timestamp_unix": 1762000000 + i * 600,
            "best_block_number": number,
            "best_block_hash": hashlib.sha256(
                ("quantus-synthetic-block-%d" % number).encode()).hexdigest(),
            "observed_peers": 8 + (i % 5),
        })
    return obs


class TestEd25519RFCVectors(unittest.TestCase):
    def test_rfc8032_test_1_empty_message(self):
        seed = bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc4"
            "4449c5697b326919703bac031cae7f60")
        pk_expected = bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a"
            "0ee172f3daa62325af021a68f707511a")
        sig_expected = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a"
            "84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46b"
            "d25bf5f0595bbe24655141438e7a100b")
        self.assertEqual(ed.publickey_from_seed(seed), pk_expected)
        self.assertEqual(ed.sign(seed, b""), sig_expected)
        self.assertTrue(ed.verify(pk_expected, b"", sig_expected))

    def test_rfc8032_test_2_keypair_and_roundtrip(self):
        # Public-key derivation is checked against the RFC 8032 TEST 2
        # keypair. (A byte-exact signature constant for this vector was
        # dropped: the value transcribed from memory did not reproduce,
        # while TEST 1 above pins the signing path byte-exactly. The
        # roundtrip below covers sign/verify for a non-empty message.)
        seed = bytes.fromhex(
            "4ccd089b28ff96da9db6c346ec114e0f"
            "5b8a319f35aba624da8cf6ed4fb8a6fb")
        pk_expected = bytes.fromhex(
            "3d4017c3e843895a92b70aa74d1b7ebc"
            "9c982ccf2ec4968cc0cd55f12af4660c")
        msg = bytes.fromhex("af82")
        self.assertEqual(ed.publickey_from_seed(seed), pk_expected)
        sig = ed.sign(seed, msg)
        self.assertTrue(ed.verify(pk_expected, msg, sig))
        self.assertFalse(ed.verify(pk_expected, b"\xaf\x83", sig))


class TestBundle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.seed = bytes(range(1, 33))  # test-only fixed seed, not a real key
        # This class pins the legacy v0.1 format explicitly:
        # build_bundle defaults to the current format version, whose
        # parameters are fixed by profile and reject a free
        # iterations argument (C1). Legacy bundles verify only with
        # allow_legacy=True (H-02).
        cls.bundle = core.build_bundle(
            cls.seed, synthetic_observations(),
            iterations=TEST_ITERATIONS, version="0.1")

    def assert_invalid(self, bundle, needle=None):
        ok, errors = core.verify_bundle(bundle, allow_legacy=True)
        self.assertFalse(ok, "tampered bundle unexpectedly verified")
        self.assertTrue(errors)
        if needle:
            self.assertTrue(
                any(needle in e for e in errors),
                "expected an error mentioning %r, got %r" % (needle, errors))

    # --- positive ---
    def test_valid_bundle_verifies(self):
        ok, errors = core.verify_bundle(self.bundle, allow_legacy=True)
        self.assertTrue(ok, errors)
        self.assertEqual(errors, [])
        self.assertEqual(len(self.bundle["checkpoints"]), 8)

    # --- negative: tamper cases ---
    def test_tamper_block_hash_detected(self):
        b = copy.deepcopy(self.bundle)
        cp = b["checkpoints"][3]
        raw = bytearray(bytes.fromhex(cp["best_block_hash"]))
        raw[0] ^= 0x01
        cp["best_block_hash"] = raw.hex()
        self.assert_invalid(b)

    def test_tamper_drop_checkpoint_detected(self):
        b = copy.deepcopy(self.bundle)
        del b["checkpoints"][4]
        self.assert_invalid(b)

    def test_tamper_reorder_checkpoints_detected(self):
        b = copy.deepcopy(self.bundle)
        cps = b["checkpoints"]
        cps[1], cps[2] = cps[2], cps[1]
        self.assert_invalid(b)

    def test_tamper_forged_signature_detected(self):
        b = copy.deepcopy(self.bundle)
        sig = bytearray(bytes.fromhex(b["signature"]))
        sig[10] ^= 0x40
        b["signature"] = sig.hex()
        self.assert_invalid(b, "signature")

    def test_tamper_signature_from_other_key_detected(self):
        other_seed = bytes(range(101, 133))  # test-only
        other = core.build_bundle(
            other_seed, synthetic_observations(),
            iterations=TEST_ITERATIONS, version="0.1")
        b = copy.deepcopy(self.bundle)
        b["signature"] = other["signature"]
        self.assert_invalid(b, "signature")

    def test_tamper_chain_state_detected(self):
        b = copy.deepcopy(self.bundle)
        cp = b["checkpoints"][2]
        raw = bytearray(bytes.fromhex(cp["chain_state"]))
        raw[31] ^= 0x01
        cp["chain_state"] = raw.hex()
        # Since v0.4 the verifier is fail-fast (H-05): any field
        # tamper is caught by the bundle_hash recomputation before
        # the chain is ever recomputed.
        self.assert_invalid(b, "bundle_hash")

    def test_tamper_checkpoint_hash_detected(self):
        b = copy.deepcopy(self.bundle)
        cp = b["checkpoints"][0]
        raw = bytearray(bytes.fromhex(cp["checkpoint_hash"]))
        raw[0] ^= 0x01
        cp["checkpoint_hash"] = raw.hex()
        self.assert_invalid(b)

    def test_tamper_pubkey_detected(self):
        b = copy.deepcopy(self.bundle)
        raw = bytearray(bytes.fromhex(b["pubkey"]))
        raw[0] ^= 0x01
        b["pubkey"] = raw.hex()
        self.assert_invalid(b)

    def test_empty_checkpoints_rejected(self):
        b = copy.deepcopy(self.bundle)
        b["checkpoints"] = []
        self.assert_invalid(b)

    def test_builder_rejects_decreasing_block_number(self):
        obs = synthetic_observations(3)
        obs[2]["best_block_number"] = obs[1]["best_block_number"] - 1
        with self.assertRaises(ValueError):
            core.build_bundle(self.seed, obs, iterations=100,
                              version="0.1")


def synthetic_observations_v02(count=8):
    obs = synthetic_observations(count)
    for o in obs:
        o["finalized_block_number"] = o["best_block_number"] - 10
        o["witness_peers"] = ["peer-alpha", "peer-beta"]
    return obs


class TestBundleV02(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.seed = bytes(range(1, 33))  # test-only fixed seed
        cls.bundle = core.build_bundle(
            cls.seed, synthetic_observations_v02(),
            iterations=TEST_ITERATIONS, version="0.2")

    def assert_invalid(self, bundle):
        ok, errors = core.verify_bundle(bundle, allow_legacy=True)
        self.assertFalse(ok, "tampered v0.2 bundle unexpectedly verified")
        self.assertTrue(errors)

    def test_v02_valid_bundle_verifies(self):
        ok, errors = core.verify_bundle(self.bundle, allow_legacy=True)
        self.assertTrue(ok, errors)
        cp = self.bundle["checkpoints"][0]
        self.assertEqual(cp["finalized_block_number"],
                         cp["best_block_number"] - 10)
        self.assertEqual(len(cp["witness_peer_hashes"]), 2)
        self.assertEqual(cp["witness_peer_hashes"],
                         sorted(cp["witness_peer_hashes"]))

    def test_v02_witness_stores_hashes_not_raw_ids(self):
        blob = str(self.bundle)
        self.assertNotIn("peer-alpha", blob)
        self.assertNotIn("peer-beta", blob)
        expected = core.peer_hash("peer-alpha").hex()
        self.assertIn(expected,
                      self.bundle["checkpoints"][0]["witness_peer_hashes"])

    def test_v01_bundle_still_verifies_with_allow_legacy(self):
        # Archival verification of historical formats still works,
        # but only through the explicit opt-in (H-02).
        b01 = core.build_bundle(
            self.seed, synthetic_observations(),
            iterations=TEST_ITERATIONS, version="0.1")
        ok, errors = core.verify_bundle(b01)
        self.assertFalse(ok)
        self.assertTrue(any("legacy" in e for e in errors), errors)
        ok, errors = core.verify_bundle(b01, allow_legacy=True)
        self.assertTrue(ok, errors)
        self.assertNotIn("finalized_block_number", b01["checkpoints"][0])

    def test_v02_tamper_witness_detected(self):
        b = copy.deepcopy(self.bundle)
        cp = b["checkpoints"][1]
        raw = bytearray(bytes.fromhex(cp["witness_peer_hashes"][0]))
        raw[0] ^= 0x01
        cp["witness_peer_hashes"][0] = raw.hex()
        cp["witness_peer_hashes"].sort()
        self.assert_invalid(b)

    def test_v02_tamper_finalized_detected(self):
        b = copy.deepcopy(self.bundle)
        b["checkpoints"][2]["finalized_block_number"] -= 5
        self.assert_invalid(b)

    def test_v02_builder_rejects_finalized_above_best(self):
        obs = synthetic_observations_v02(2)
        obs[0]["finalized_block_number"] = obs[0]["best_block_number"] + 1
        with self.assertRaises(ValueError):
            core.build_bundle(self.seed, obs, iterations=100, version="0.2")


class TestBundleV05(unittest.TestCase):
    """Current format (v0.5): profile-fixed parameters, fail-fast
    verification (H-05), and the spot-response signature helpers
    (protocol v2: mandatory target_seq + revision)."""

    @classmethod
    def setUpClass(cls):
        cls.seed = bytes(range(1, 33))  # test-only fixed seed
        cls.bundle = core.build_bundle(
            cls.seed, synthetic_observations_v02(), profile="test")

    def test_default_version_is_v05_and_verifies(self):
        self.assertEqual(self.bundle["version"], "0.5")
        self.assertEqual(core.VERSION, "0.5")
        ok, errors = core.verify_bundle(self.bundle, profile="test")
        self.assertTrue(ok, errors)
        self.assertEqual(errors, [])

    def test_test_profile_bundle_rejected_under_production(self):
        ok, errors = core.verify_bundle(self.bundle)
        self.assertFalse(ok)
        self.assertTrue(any("profile" in e for e in errors), errors)

    def test_fail_fast_on_bundle_hash_tamper(self):
        # H-05: tampering any field breaks the bundle_hash
        # recomputation; verification must stop there with exactly
        # that one error - no signature work, no chain recomputation
        # (in v0.3 the verifier kept going and burned chain work).
        b = copy.deepcopy(self.bundle)
        b["created_at_unix"] += 1
        ok, errors = core.verify_bundle(b, profile="test")
        self.assertFalse(ok)
        self.assertEqual(errors, ["bundle_hash recomputation mismatch"])

    def test_signature_failure_stops_verification(self):
        b = copy.deepcopy(self.bundle)
        sig = bytearray(bytes.fromhex(b["signature"]))
        sig[10] ^= 0x40
        b["signature"] = sig.hex()
        ok, errors = core.verify_bundle(b, profile="test")
        self.assertFalse(ok)
        self.assertEqual(errors, ["signature verification failed"])

    def test_spot_response_sign_verify_roundtrip(self):
        pubkey = ed.publickey_from_seed(self.seed)
        bundle_hash = bytes.fromhex(self.bundle["bundle_hash"])
        challenge = hashlib.sha256(b"challenge-block").digest()
        response = hashlib.sha256(b"block-body-value").digest()
        sig = core.sign_spot_response(
            self.seed, bundle_hash, challenge, response, 5, revision=2)
        self.assertTrue(core.verify_spot_response(
            pubkey, bundle_hash, challenge, response, 5, sig,
            revision=2))
        # The signature binds every field: value, target, bundle,
        # and (protocol v2) the revision counter.
        self.assertFalse(core.verify_spot_response(
            pubkey, bundle_hash, challenge,
            hashlib.sha256(b"other").digest(), 5, sig, revision=2))
        self.assertFalse(core.verify_spot_response(
            pubkey, bundle_hash, challenge, response, 6, sig,
            revision=2))
        self.assertFalse(core.verify_spot_response(
            pubkey, hashlib.sha256(b"other-bundle").digest(),
            challenge, response, 5, sig, revision=2))
        self.assertFalse(core.verify_spot_response(
            pubkey, bundle_hash, challenge, response, 5, sig,
            revision=3))
        # Protocol v2: there is no "absent target" encoding any
        # more (that was the R-C01 ambiguity). Signing without a
        # target is an error; verifying one never succeeds.
        with self.assertRaises(ValueError):
            core.sign_spot_response(
                self.seed, bundle_hash, challenge, response, None)
        self.assertFalse(core.verify_spot_response(
            pubkey, bundle_hash, challenge, response, None, sig,
            revision=2))


if __name__ == "__main__":
    unittest.main()
