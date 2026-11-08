package app.quantusnode.depin;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Plain-JVM harness for the device-independent classes (no JUnit in
 * the VM, same approach as the sibling bench app). Pins:
 *  - SHA-256 / Ed25519 against published vectors,
 *  - the v0.5 chain / checkpoint / bundle encodings against values
 *    derived independently from the v0.5 contract text, with the
 *    v0.4 encodings pinned alongside (the parameterized legacy
 *    profiles must keep producing them bit-for-bit),
 *  - strict verification parity with the Python reference
 *    (8.0 rejection, uppercase-hex rejection, witness rules,
 *    null rejection, schema ranges, JSON number grammar),
 *  - the AES-GCM seed wrap and the no-cache seed vault semantics,
 *  - the authenticated JSONL journal (tamper drop,
 *    forged-signature drop, legacy migration for BOTH the v0.4 and
 *    v0.3 formats, partial-tail recovery),
 *  - the JSON layer and the RPC client (against a canned
 *    transport, including strict intake parsing, the deadline
 *    timeout function, and the plausibility state machine).
 */
public final class HarnessMain {
    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) throws Exception {
        testSha256();
        testEd25519RfcVectors();
        testEd25519WeakKeyRejection();
        testDepinVectorsV04();
        testDepinVectorsV05();
        testBundleRoundtripAndTamper();
        testVerifyStrictParity();
        testVerifyParityRound2();
        testSeedBox();
        testSeedBoxKeystorePairing();
        testSeedVaultNoCache();
        testCrashLog();
        testJournal();
        testJournalAuth();
        testJournalArchive();
        testJournalMigrationV04();
        testJournalPartialTail();
        testJournalHeaderRecovery();
        testJson();
        testJsonStrictRaw();
        testRpcAgainstStub();
        testRpcValidation();
        testRpcStrictParsing();
        testRpcAbsoluteDeadline();
        testPlausibility();
        testSegmentPolicyV08();
        testRpcHeaderDeadline();
        testJournalAppendRetry();
        testServiceGeneration();
        testJournalArchiveHeaderL03();
        testJournalHeaderNoNewline();
        testJournalVerifiedArchive();
        testJournalDeepNesting();
        testJsonDuplicateKeys();
        testObservedPeersU32();
        testArchiveHeaderRepairF04();
        testJournalCheckpointCap();
        testRpcChunkedBodyDeadline();
        testJournalAppendGeneration();
        testPendingExportHolder();
        testSegmentStartStreakF11();
        System.out.println("----");
        System.out.println("passed=" + passed + " failed=" + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    // ---------------- individual suites ----------------

    private static void testSha256() {
        check("sha256(abc)",
                Hex.encode(DepinCore.sha256("abc".getBytes(StandardCharsets.US_ASCII)))
                        .equals("ba7816bf8f01cfea414140de5dae2223"
                                + "b00361a396177a9cb410ff61f20015ad"));
    }

    private static void testEd25519RfcVectors() {
        // RFC 8032 TEST 1 (empty message): keypair and signature,
        // byte-exact, same constants as the Python suite.
        byte[] seed1 = Hex.decode(
                "9d61b19deffd5a60ba844af492ec2cc4"
                        + "4449c5697b326919703bac031cae7f60");
        byte[] pk1 = Hex.decode(
                "d75a980182b10ab7d54bfed3c964073a"
                        + "0ee172f3daa62325af021a68f707511a");
        byte[] sig1 = Hex.decode(
                "e5564300c360ac729086e2cc806e828a"
                        + "84877f1eb8e5d974d873e06522490155"
                        + "5fb8821590a33bacc61e39701cf9b46b"
                        + "d25bf5f0595bbe24655141438e7a100b");
        check("rfc8032 test1 pubkey", Arrays.equals(Ed25519.publickeyFromSeed(seed1), pk1));
        check("rfc8032 test1 signature",
                Arrays.equals(Ed25519.sign(seed1, new byte[0]), sig1));
        check("rfc8032 test1 verify",
                Ed25519.verify(pk1, new byte[0], sig1));

        // RFC 8032 TEST 2: keypair pinned; roundtrip over msg 0xaf82.
        byte[] seed2 = Hex.decode(
                "4ccd089b28ff96da9db6c346ec114e0f"
                        + "5b8a319f35aba624da8cf6ed4fb8a6fb");
        byte[] pk2 = Hex.decode(
                "3d4017c3e843895a92b70aa74d1b7ebc"
                        + "9c982ccf2ec4968cc0cd55f12af4660c");
        check("rfc8032 test2 pubkey", Arrays.equals(Ed25519.publickeyFromSeed(seed2), pk2));
        byte[] msg = Hex.decode("af82");
        byte[] sig2 = Ed25519.sign(seed2, msg);
        check("rfc8032 test2 roundtrip", Ed25519.verify(pk2, msg, sig2));
        check("rfc8032 test2 wrong message rejected",
                !Ed25519.verify(pk2, Hex.decode("af83"), sig2));
    }

    private static void testEd25519WeakKeyRejection() {
        // Identity point as public key: y=1, x=0 -> 0x01 then zeros.
        // A forged "signature" R=identity, S=0 satisfies the naive
        // verification equation for every message; the small-order
        // rejection (SPEC v0.3, H6) must refuse it.
        byte[] identity = new byte[32];
        identity[0] = 1;
        byte[] forged = new byte[64];
        forged[0] = 1; // R = identity, S = 0
        check("identity pubkey forgery rejected",
                !Ed25519.verify(identity, "anything".getBytes(StandardCharsets.UTF_8), forged));
    }

    private static List<DepinCore.Observation> syntheticObservations(int count) {
        // Identical inputs to the Python suite's synthetic data.
        List<DepinCore.Observation> obs = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            long number = 350000L + i * 100L;
            DepinCore.Observation o = new DepinCore.Observation();
            o.timestampUnix = 1762000000L + i * 600L;
            o.bestBlockNumber = number;
            o.bestBlockHash = DepinCore.sha256(
                    ("quantus-synthetic-block-" + number).getBytes(StandardCharsets.US_ASCII));
            o.observedPeers = 8 + (i % 5);
            o.finalizedBlockNumber = number - 10;
            obs.add(o);
        }
        return obs;
    }

    private static void testDepinVectorsV04() {
        // Expected values derived from the v0.4 contract text by an
        // independent Python implementation (see the v0.4 progress
        // memo), NOT from this Java code. The v0.4 profile is now a
        // LEGACY profile; these pins prove the parameterization
        // kept it bit-exact (journal migration verifies real v0.4
        // journals against exactly these formulas).
        byte[] seed = new byte[32];
        for (int i = 0; i < 32; i++) seed[i] = (byte) (i + 1);
        byte[] pub = Ed25519.publickeyFromSeed(seed);
        check("v0.4 vector: pubkey",
                Hex.encode(pub).equals(
                        "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"));
        check("v0.4 vector: device_id",
                DepinCore.deviceIdFromPubkey(pub).equals("qdp1-65b60673d6ed884bf01c2c22"));

        DepinCore.Observation o0 = syntheticObservations(1).get(0);
        byte[] state = DepinCore.sequentialChainV04(
                DepinCore.ZERO32, o0.bestBlockHash, 0, o0.bestBlockNumber,
                50, pub, o0.timestampUnix / DepinCore.SLOT_SEC,
                o0.finalizedBlockNumber, o0.observedPeers);
        check("v0.4 vector: chain state (50 iters)",
                Hex.encode(state).equals(
                        "1d584e4867a5fa7c65ed8f532dc6cfb6ea5924522071c4843d84a80610159463"));

        DepinCore.Checkpoint cp0 = DepinCore.makeCheckpoint(
                DepinCore.FMT_V04, 0, o0, DepinCore.ZERO32, DepinCore.ZERO32, 50, pub);
        check("v0.4 vector: checkpoint 0 hash",
                Hex.encode(cp0.checkpointHash).equals(
                        "77b13509d25ab8d51d1eb8fa7d58dac120abcb8681c912d78e95be7f6481ef65"));
        check("v0.4 vector: journal entry sig for checkpoint 0",
                Hex.encode(DepinCore.journalEntrySig(seed, cp0.checkpointHash, 0))
                        .equals("eca34bec483c785454b412d402bc76522bea8f73efe09984d8ef37547c3bc3e5"
                                + "bb0311a3ef08d2f53dfccc7045778fc3a1a256f1c05ef6fc0a733dc6947d130d"));

        Map<String, Object> bundle = DepinCore.buildBundle(
                DepinCore.FMT_V04, seed, syntheticObservations(8), 50, -1);
        check("v0.4 vector: bundle_hash (test profile)",
                "40f4cbc6af1bf70bdc3f32d9ba823dcc4b5bf6f318c29995644c184c5b5db850"
                        .equals(bundle.get("bundle_hash")));
        check("v0.4 vector: signature (test profile)",
                ("53eee21e0c592d245f62f123dc54e45e3ee6cad353f2dbfd08cf04a75cf6465cb1f8e4fe3adbd645c"
                        + "30e3d1603e91a7c44958b3f3f97e71ae96a32b69f7d1504")
                        .equals(bundle.get("signature")));

        // Witness-carrying checkpoint under the v0.4 profile (the
        // pin that lived in the parity suite when v0.4 was current).
        byte[] wA = DepinCore.sha256(
                "witness-peer-a".getBytes(StandardCharsets.US_ASCII));
        byte[] wB = DepinCore.sha256(
                "witness-peer-b".getBytes(StandardCharsets.US_ASCII));
        List<DepinCore.Observation> wobs = syntheticObservations(4);
        for (DepinCore.Observation o : wobs) {
            o.witnessPeerHashes = Arrays.asList(wB, wA, wB);
        }
        Map<String, Object> wBundle = DepinCore.buildBundle(
                DepinCore.FMT_V04, seed, wobs, 50, -1);
        Map<String, Object> wcp0 = Json.asObject(
                Json.asArray(wBundle.get("checkpoints")).get(0));
        check("v0.4 vector: witness checkpoint 0 hash",
                "6b2172100a06c7a35a42b5500cbd2ffedf99d5c64fadadfeac9de4b7c10eecf9"
                        .equals(wcp0.get("checkpoint_hash")));
        check("v0.4 vector: witness bundle verifies under the legacy profile",
                DepinCore.verifyBundleV04(wBundle, 50).isEmpty());
    }

    private static void testDepinVectorsV05() {
        // Expected values derived from the v0.5 contract text by a
        // throwaway independent Python script written directly
        // from the contract (domains QDP1/*/v0.5, v0.4 seed-input
        // layout), NOT from this Java code and NOT from the
        // reference implementation — see the v0.5 progress memo.
        byte[] seed = new byte[32];
        for (int i = 0; i < 32; i++) seed[i] = (byte) (i + 1);
        byte[] pub = Ed25519.publickeyFromSeed(seed);
        check("v0.5 vector: pubkey (version-independent)",
                Hex.encode(pub).equals(
                        "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"));
        check("v0.5 vector: device_id (version-independent)",
                DepinCore.deviceIdFromPubkey(pub).equals("qdp1-65b60673d6ed884bf01c2c22"));

        DepinCore.Observation o0 = syntheticObservations(1).get(0);
        byte[] state = DepinCore.sequentialChain(
                DepinCore.FMT_V05, DepinCore.ZERO32, o0.bestBlockHash, 0,
                o0.bestBlockNumber, 50, pub,
                o0.timestampUnix / DepinCore.SLOT_SEC,
                o0.finalizedBlockNumber, o0.observedPeers);
        check("v0.5 vector: chain state (50 iters)",
                Hex.encode(state).equals(
                        "7e16796b98584b1e4f22dec06c0ee7aed55453f333b448c92cc1f643a64ec061"));

        DepinCore.Checkpoint cp0 = DepinCore.makeCheckpoint(
                0, o0, DepinCore.ZERO32, DepinCore.ZERO32, 50, pub);
        check("v0.5 vector: checkpoint 0 hash",
                Hex.encode(cp0.checkpointHash).equals(
                        "afae17f0ed8c89997e0cd9202e953cbc872ccb910551883c1eb4dc098902222a"));
        check("v0.5 vector: journal entry sig for checkpoint 0",
                Hex.encode(DepinCore.journalEntrySig(seed, cp0.checkpointHash, 0))
                        .equals("fa4be744e21b0610b851bfaab53211a9a7aee9242750fec912f9dd6ab300f127"
                                + "9779cce663a8bd9c25695f6a544b2b38a7def4c78cb5a03796ac6dcce04a9c0f"));

        Map<String, Object> bundle = DepinCore.buildBundle(
                seed, syntheticObservations(8), 50, -1);
        check("v0.5 vector: bundle version is 0.5",
                "0.5".equals(bundle.get("version")));
        check("v0.5 vector: bundle_hash (test profile)",
                "a4b9ceaeeb3c7ccbe7b8d5c4a5031bbac9df5b1d454269e9bd3ede5a34ce4b3c"
                        .equals(bundle.get("bundle_hash")));
        check("v0.5 vector: signature (test profile)",
                ("022c93114716e3855831e6dcfb45a1e88cb5553fc2735465250cb2f5d643d52e913a7c819851b70a8c54c"
                        + "cead263c1013e76dd65dd9fea5a1a9bca2e74f27a0a")
                        .equals(bundle.get("signature")));

        // Witness-carrying checkpoint under the v0.5 profile.
        byte[] wA = DepinCore.sha256(
                "witness-peer-a".getBytes(StandardCharsets.US_ASCII));
        byte[] wB = DepinCore.sha256(
                "witness-peer-b".getBytes(StandardCharsets.US_ASCII));
        List<DepinCore.Observation> wobs = syntheticObservations(4);
        for (DepinCore.Observation o : wobs) {
            o.witnessPeerHashes = Arrays.asList(wB, wA, wB);
        }
        Map<String, Object> wBundle = DepinCore.buildBundle(seed, wobs, 50, -1);
        Map<String, Object> wcp0 = Json.asObject(
                Json.asArray(wBundle.get("checkpoints")).get(0));
        check("v0.5 vector: witness checkpoint 0 hash",
                "d999de8340bf6a48015072b26f0d6dde668d5f6cee1951b4b9974796ff184b49"
                        .equals(wcp0.get("checkpoint_hash")));
    }

    private static void testBundleRoundtripAndTamper() {
        byte[] seed = new byte[32];
        for (int i = 0; i < 32; i++) seed[i] = (byte) (i + 1);
        Map<String, Object> bundle = DepinCore.buildBundle(
                seed, syntheticObservations(4), 50, -1);
        check("java verify: own bundle valid",
                DepinCore.verifyBundle(bundle, 50).isEmpty());

        // Serialize -> parse -> verify: the JSON layer must preserve
        // everything the hashes cover.
        Map<String, Object> reparsed = Json.parseObject(Json.pretty(bundle));
        check("java verify: reparsed bundle valid",
                DepinCore.verifyBundle(reparsed, 50).isEmpty());

        // Tamper with one checkpoint's block number.
        Map<String, Object> tampered = Json.parseObject(Json.pretty(bundle));
        Map<String, Object> cp = Json.asObject(
                Json.asArray(tampered.get("checkpoints")).get(1));
        cp.put("best_block_number", Json.asLong(cp.get("best_block_number")) + 1);
        check("java verify: tampered checkpoint rejected",
                !DepinCore.verifyBundle(tampered, 50).isEmpty());

        // Wrong verifier profile (production iterations) must fail.
        check("java verify: wrong profile rejected",
                !DepinCore.verifyBundle(bundle, DepinCore.PRODUCTION_ITERATIONS).isEmpty());
    }

    private static void testVerifyStrictParity() {
        // M-01: the Java verifier must reach the SAME verdicts as
        // the Python reference on adversarial encodings.
        byte[] seed = new byte[32];
        for (int i = 0; i < 32; i++) seed[i] = (byte) (i + 1);
        Map<String, Object> bundle = DepinCore.buildBundle(
                seed, syntheticObservations(4), 50, -1);

        // observed_peers written as 8.0 (a JSON non-integer): the
        // reference rejects it at schema validation. The canonical
        // writer here would normalize 8.0 back to 8, so only the
        // strict type check can catch it — that is the point.
        Map<String, Object> frac = Json.parseObject(Json.pretty(bundle));
        Map<String, Object> fcp = Json.asObject(
                Json.asArray(frac.get("checkpoints")).get(0));
        fcp.put("observed_peers", 8.0d);
        check("parity: observed_peers 8.0 rejected",
                !DepinCore.verifyBundle(frac, 50).isEmpty());

        // Uppercase hex is not the canonical form: rejected.
        Map<String, Object> upper = Json.parseObject(Json.pretty(bundle));
        Map<String, Object> ucp = Json.asObject(
                Json.asArray(upper.get("checkpoints")).get(0));
        ucp.put("chain_state",
                Json.asString(ucp.get("chain_state")).toUpperCase(java.util.Locale.US));
        check("parity: uppercase hex rejected",
                !DepinCore.verifyBundle(upper, 50).isEmpty());

        // bundle_hash tamper (via an unsigned-metadata field) must
        // be rejected — and structurally returns before chain work.
        Map<String, Object> hashTampered = Json.parseObject(Json.pretty(bundle));
        hashTampered.put("created_at_unix",
                Json.asLong(hashTampered.get("created_at_unix")) + 1);
        check("parity: bundle_hash mismatch rejected",
                !DepinCore.verifyBundle(hashTampered, 50).isEmpty());

        // Params that disagree with the verifier profile: rejected.
        Map<String, Object> paramTampered = Json.parseObject(Json.pretty(bundle));
        Json.asObject(paramTampered.get("params"))
                .put("iterations_per_checkpoint", 51L);
        check("parity: params/profile mismatch rejected",
                !DepinCore.verifyBundle(paramTampered, 50).isEmpty());

        // A bundle carrying non-empty witness lists must verify
        // (v0.3's Java port silently dropped the field and then
        // rejected such bundles). Witnesses are supplied unsorted
        // and duplicated; the encoding dedups and sorts them.
        byte[] wA = DepinCore.sha256(
                "witness-peer-a".getBytes(StandardCharsets.US_ASCII));
        byte[] wB = DepinCore.sha256(
                "witness-peer-b".getBytes(StandardCharsets.US_ASCII));
        List<DepinCore.Observation> wobs = syntheticObservations(4);
        for (DepinCore.Observation o : wobs) {
            o.witnessPeerHashes = Arrays.asList(wB, wA, wB);
        }
        Map<String, Object> wBundle = DepinCore.buildBundle(seed, wobs, 50, -1);
        check("parity: non-empty witness bundle accepted",
                DepinCore.verifyBundle(wBundle, 50).isEmpty());
        Map<String, Object> wcp0 = Json.asObject(
                Json.asArray(wBundle.get("checkpoints")).get(0));
        check("parity: witness checkpoint 0 hash (contract vector)",
                "d999de8340bf6a48015072b26f0d6dde668d5f6cee1951b4b9974796ff184b49"
                        .equals(wcp0.get("checkpoint_hash")));
        List<Object> ws = Json.asArray(wcp0.get("witness_peer_hashes"));
        check("parity: witnesses stored sorted + deduplicated",
                ws.size() == 2
                        && "531325d98256d7f69b8dbfc40fdd67e392734922bb16be0d4f85afa99c3ae480"
                                .equals(ws.get(0))
                        && "d6722a925130d8c4ae32aa011f3ff8a4054ce59d7f8e719f9c2aabbfb6ea2528"
                                .equals(ws.get(1)));
    }

    private static Map<String, Object> cpOf(Map<String, Object> bundle, int i) {
        return Json.asObject(Json.asArray(bundle.get("checkpoints")).get(i));
    }

    private static void testVerifyParityRound2() {
        // R-M01: the divergences the v0.4 re-audit listed. Every
        // mutation below must be INVALID here exactly as the
        // Python reference judges it (the cross-check confirms the
        // reference side for the same mutation set).
        byte[] seed = new byte[32];
        for (int i = 0; i < 32; i++) seed[i] = (byte) (i + 1);
        Map<String, Object> bundle = DepinCore.buildBundle(
                seed, syntheticObservations(4), 50, -1);

        byte[] wA = DepinCore.sha256(
                "witness-peer-a".getBytes(StandardCharsets.US_ASCII));
        byte[] wB = DepinCore.sha256(
                "witness-peer-b".getBytes(StandardCharsets.US_ASCII));
        List<DepinCore.Observation> wobs = syntheticObservations(4);
        for (DepinCore.Observation o : wobs) {
            o.witnessPeerHashes = Arrays.asList(wB, wA, wB);
        }
        Map<String, Object> wBundle = DepinCore.buildBundle(seed, wobs, 50, -1);

        // (1a) witness list NOT sorted ascending on the wire.
        Map<String, Object> unsorted = Json.parseObject(Json.pretty(wBundle));
        List<Object> uw = Json.asArray(cpOf(unsorted, 0).get("witness_peer_hashes"));
        Object tmp = uw.get(0);
        uw.set(0, uw.get(1));
        uw.set(1, tmp);
        check("parity2: unsorted witness list rejected",
                !DepinCore.verifyBundle(unsorted, 50).isEmpty());

        // (1b) witness list with a duplicate entry.
        Map<String, Object> dup = Json.parseObject(Json.pretty(wBundle));
        List<Object> dw = Json.asArray(cpOf(dup, 0).get("witness_peer_hashes"));
        dw.set(1, dw.get(0));
        check("parity2: duplicate witness rejected",
                !DepinCore.verifyBundle(dup, 50).isEmpty());

        // (1c) witness list beyond the 512 cap.
        Map<String, Object> many = Json.parseObject(Json.pretty(wBundle));
        List<Object> mw = new ArrayList<>();
        for (int i = 0; i < 513; i++) {
            mw.add(Hex.encode(DepinCore.sha256(
                    ("witness-" + i).getBytes(StandardCharsets.US_ASCII))));
        }
        mw.sort(null);
        cpOf(many, 0).put("witness_peer_hashes", mw);
        check("parity2: 513 witnesses rejected",
                !DepinCore.verifyBundle(many, 50).isEmpty());

        // (1d) witness entry that is not canonical hex.
        Map<String, Object> badHex = Json.parseObject(Json.pretty(wBundle));
        List<Object> bw = Json.asArray(cpOf(badHex, 0).get("witness_peer_hashes"));
        bw.set(0, Json.asString(bw.get(0)).toUpperCase(java.util.Locale.US));
        check("parity2: uppercase witness hash rejected",
                !DepinCore.verifyBundle(badHex, 50).isEmpty());

        // (2) finalized_block_number present but JSON null: NOT
        // the same as absent (the reference rejects null in typed
        // fields). Text-level mutation so the null really is in
        // the parsed structure.
        String withNull = Json.pretty(bundle).replace(
                "\"finalized_block_number\": 349990",
                "\"finalized_block_number\": null");
        check("parity2: finalized null mutation applied",
                !withNull.equals(Json.pretty(bundle)));
        Map<String, Object> nullFin = Json.parseObject(withNull);
        check("parity2: finalized_block_number null rejected",
                !DepinCore.verifyBundle(nullFin, 50).isEmpty());

        // (2b) null in another typed field (a hex field).
        Map<String, Object> nullHex = Json.parseObject(Json.pretty(bundle));
        cpOf(nullHex, 0).put("chain_state", null);
        check("parity2: chain_state null rejected",
                !DepinCore.verifyBundle(nullHex, 50).isEmpty());

        // (3) schema ranges: negative values the reference refuses.
        Map<String, Object> negSeq = Json.parseObject(Json.pretty(bundle));
        cpOf(negSeq, 0).put("seq", -1L);
        check("parity2: seq -1 rejected",
                !DepinCore.verifyBundle(negSeq, 50).isEmpty());

        Map<String, Object> negTs = Json.parseObject(Json.pretty(bundle));
        cpOf(negTs, 0).put("timestamp_unix", -5L);
        check("parity2: timestamp_unix -5 rejected",
                !DepinCore.verifyBundle(negTs, 50).isEmpty());

        Map<String, Object> negBest = Json.parseObject(Json.pretty(bundle));
        cpOf(negBest, 0).put("best_block_number", -1L);
        check("parity2: best_block_number -1 rejected",
                !DepinCore.verifyBundle(negBest, 50).isEmpty());

        Map<String, Object> negCreated = Json.parseObject(Json.pretty(bundle));
        negCreated.put("created_at_unix", -1L);
        check("parity2: created_at_unix -1 rejected",
                !DepinCore.verifyBundle(negCreated, 50).isEmpty());

        // Legacy profiles still verify under their own profile —
        // and ONLY there: the current verifier refuses both.
        Map<String, Object> legacy04 = DepinCore.buildBundle(
                DepinCore.FMT_V04, seed, syntheticObservations(4), 50, -1);
        check("parity2: v0.4 bundle verifies under the v0.4 profile",
                DepinCore.verifyBundleV04(legacy04, 50).isEmpty());
        check("parity2: v0.4 bundle refused by the current verifier",
                !DepinCore.verifyBundle(legacy04, 50).isEmpty());
        Map<String, Object> legacy03 = DepinCore.buildBundle(
                DepinCore.FMT_V03, seed, syntheticObservations(4), 50, -1);
        check("parity2: v0.3 bundle verifies under the v0.3 profile",
                DepinCore.verifyBundle(
                        DepinCore.FMT_V03, legacy03, 50, true).isEmpty());
        check("parity2: v0.3 bundle refused by the current verifier",
                !DepinCore.verifyBundle(legacy03, 50).isEmpty());
        check("parity2: v0.3 bundle refused by the v0.4 profile",
                !DepinCore.verifyBundleV04(legacy03, 50).isEmpty());
    }

    private static void testSeedBox() throws Exception {
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(256, new SecureRandom());
        SecretKey key = gen.generateKey();
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        AesGcmSeedBox.Wrapped wrapped = AesGcmSeedBox.wrap(key, seed);
        check("seed box roundtrip",
                Arrays.equals(AesGcmSeedBox.unwrap(key, wrapped), seed));
        byte[] badCt = wrapped.ciphertext.clone();
        badCt[0] ^= 1;
        boolean threw = false;
        try {
            AesGcmSeedBox.unwrap(key, new AesGcmSeedBox.Wrapped(wrapped.iv, badCt));
        } catch (Exception e) {
            threw = true;
        }
        check("seed box tamper rejected", threw);
    }

    private static void testSeedBoxKeystorePairing() throws Exception {
        // The v0.1.0 on-device crash, pinned as a regression test.
        // AesGcmSeedBox passes a caller-supplied IV to the Cipher on
        // both wrap and unwrap. Android KeyMint accepts a caller
        // nonce ONLY when the key was generated WITHOUT requiring
        // randomized encryption; v0.1.0's KeyGenParameterSpec set
        // that to true, so keystore2 rejected every wrap with
        // CALLER_NONCE_PROHIBITED and identity init always failed.
        // Plain JCE has no such flag, so the harness pins (a) the
        // parameter value itself (referenced by AndroidSeedVault)
        // and (b) the semantic half KeyMint enforces: every wrap
        // must carry a FRESH random IV — a reused caller IV under
        // one key would be a GCM nonce-reuse failure of its own.
        check("keystore pin: caller-IV design requires "
                        + "randomizedEncryptionRequired=false",
                !SeedVault.KEYSTORE_RANDOMIZED_ENCRYPTION_REQUIRED);

        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(256, new SecureRandom());
        SecretKey key = gen.generateKey();
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        AesGcmSeedBox.Wrapped w1 = AesGcmSeedBox.wrap(key, seed);
        AesGcmSeedBox.Wrapped w2 = AesGcmSeedBox.wrap(key, seed);
        check("seed box: fresh IV per wrap",
                !Arrays.equals(w1.iv, w2.iv)
                        && !Arrays.equals(w1.ciphertext, w2.ciphertext));
        check("seed box: both caller-IV wraps unwrap",
                Arrays.equals(AesGcmSeedBox.unwrap(key, w1), seed)
                        && Arrays.equals(AesGcmSeedBox.unwrap(key, w2), seed));
    }

    /**
     * A SeedVault with the production R-L01 semantics over an
     * in-memory wrapped store: it keeps ONLY the AES-GCM wrapped
     * form (never a plaintext field), unwraps on demand on every
     * loadOrCreateSeed() call, and publicKey() zeroes the seed
     * copy it obtained. This mirrors AndroidSeedVault's structure
     * (which the harness cannot compile — it is Android-bound);
     * the production class's no-cache shape itself is pinned by
     * inspection and stated in the v0.5 progress memo.
     */
    private static final class InMemorySeedVault implements SeedVault {
        private final SecretKey key;
        private AesGcmSeedBox.Wrapped stored;

        InMemorySeedVault(SecretKey key) {
            this.key = key;
        }

        @Override
        public byte[] loadOrCreateSeed() throws Exception {
            if (stored != null) {
                return AesGcmSeedBox.unwrap(key, stored);
            }
            byte[] seed = new byte[32];
            new SecureRandom().nextBytes(seed);
            stored = AesGcmSeedBox.wrap(key, seed);
            return seed;
        }

        @Override
        public byte[] publicKey() throws Exception {
            byte[] seed = loadOrCreateSeed();
            try {
                return Ed25519.publickeyFromSeed(seed);
            } finally {
                Arrays.fill(seed, (byte) 0);
            }
        }
    }

    private static void testSeedVaultNoCache() throws Exception {
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(256, new SecureRandom());
        InMemorySeedVault vault = new InMemorySeedVault(gen.generateKey());

        byte[] pk1 = vault.publicKey();
        check("vault: publicKey stable across calls (no cache)",
                Arrays.equals(pk1, vault.publicKey()));

        byte[] seedCopy = vault.loadOrCreateSeed();
        check("vault: loadSeed matches publicKey",
                Arrays.equals(Ed25519.publickeyFromSeed(seedCopy), pk1));

        // Mutating a returned copy must not affect later loads:
        // with no cache there is nothing shared to corrupt.
        Arrays.fill(seedCopy, (byte) 0xEE);
        byte[] seedAgain = vault.loadOrCreateSeed();
        check("vault: returned copies are independent (no cache)",
                !Arrays.equals(seedCopy, seedAgain)
                        && Arrays.equals(Ed25519.publickeyFromSeed(seedAgain), pk1));
        check("vault: publicKey still correct after copy mutation",
                Arrays.equals(vault.publicKey(), pk1));
    }

    private static void testCrashLog() throws Exception {
        File dir = new File(System.getProperty("java.io.tmpdir"),
                "depin-crashlog-test-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        check("crash log: empty reads null", CrashLog.readAll(dir) == null);

        CrashLog.record(dir, "service_init",
                new IllegalStateException("first failure",
                        new java.security.GeneralSecurityException("root cause")));
        CrashLog.recordMessage(dir, "note", "second entry");
        String all = CrashLog.readAll(dir);
        check("crash log: records class, message and cause",
                all != null
                        && all.contains("java.lang.IllegalStateException")
                        && all.contains("first failure")
                        && all.contains("root cause"));
        check("crash log: records stack frames",
                all != null && all.contains("    at "));
        String last = CrashLog.lastEntry(all);
        check("crash log: lastEntry isolates the latest entry",
                last != null && last.contains("second entry")
                        && !last.contains("first failure"));

        // Size cap: flood the log well past the cap; it must stay
        // bounded and the surviving text must start at an entry
        // boundary. (Each entry is only ~100 bytes on this shallow
        // harness stack, so a few hundred entries would not reach
        // the 64 KiB cap at all — hence the thousand.)
        for (int i = 0; i < 1000; i++) {
            CrashLog.record(dir, "flood",
                    new RuntimeException("entry number " + i));
        }
        File file = new File(dir, CrashLog.FILE_NAME);
        String capped = CrashLog.readAll(dir);
        check("crash log: size capped",
                file.length() <= 64 * 1024 && capped != null);
        check("crash log: cap keeps the newest entries",
                capped != null && capped.contains("entry number 999")
                        && !capped.contains("entry number 0\n"));
        check("crash log: capped text starts at an entry boundary",
                capped != null && capped.startsWith("=== "));

        CrashLog.clear(dir);
        check("crash log: clear removes the log",
                CrashLog.readAll(dir) == null);
    }

    private static JournalStore.EntrySigner testSigner(byte[] seed) {
        return (hash, seq) -> DepinCore.journalEntrySig(seed, hash, seq);
    }

    private static JournalStore.EntryVerifier testVerifier(byte[] pub) {
        return (hash, seq, sig) -> DepinCore.verifyJournalEntrySig(pub, hash, seq, sig);
    }

    private static byte[] testSeed() {
        byte[] seed = new byte[32];
        for (int i = 0; i < 32; i++) seed[i] = (byte) (i + 1);
        return seed;
    }

    private static void testJournal() throws Exception {
        File dir = new File(System.getProperty("java.io.tmpdir"),
                "depin-journal-test-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        File file = new File(dir, "journal.json");
        byte[] seed = testSeed();
        byte[] pub = Ed25519.publickeyFromSeed(seed);
        String deviceId = DepinCore.deviceIdFromPubkey(pub);

        JournalStore j = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        j.bindIdentity(deviceId, Hex.encode(pub));
        List<DepinCore.Observation> obs = syntheticObservations(3);
        for (int i = 0; i < 3; i++) {
            j.append(DepinCore.makeCheckpoint(i, obs.get(i),
                    j.nextPrevState(), j.nextPrevCheckpointHash(), 50, pub));
        }
        check("journal count", j.count() == 3);

        JournalStore reopened = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("journal survives reopen", reopened.count() == 3);
        check("journal: signed entries all verify on load",
                reopened.droppedOnLoad() == 0);
        check("journal chain head matches",
                Arrays.equals(reopened.nextPrevCheckpointHash(),
                        j.nextPrevCheckpointHash()));
        List<DepinCore.Checkpoint> cps = reopened.checkpoints();
        Map<String, Object> bundle = DepinCore.assembleBundle(seed, cps, 1762003600L, 50);
        check("journal -> bundle verifies",
                DepinCore.verifyBundle(bundle, 50).isEmpty());
    }

    private static void testJournalAuth() throws Exception {
        byte[] seed = testSeed();
        byte[] pub = Ed25519.publickeyFromSeed(seed);
        String deviceId = DepinCore.deviceIdFromPubkey(pub);

        // --- field tampering in a stored entry: the tampered entry
        // and its whole tail are dropped on load (H-04) ---
        File dir = new File(System.getProperty("java.io.tmpdir"),
                "depin-journal-auth-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        File file = new File(dir, "journal.json");
        JournalStore j = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        j.bindIdentity(deviceId, Hex.encode(pub));
        List<DepinCore.Observation> obs = syntheticObservations(3);
        for (int i = 0; i < 3; i++) {
            j.append(DepinCore.makeCheckpoint(i, obs.get(i),
                    j.nextPrevState(), j.nextPrevCheckpointHash(), 50, pub));
        }
        String content = new String(java.nio.file.Files.readAllBytes(file.toPath()),
                StandardCharsets.UTF_8);
        String[] lines = content.split("\n");
        // lines[0] = header, lines[1..3] = entries seq 0..2.
        // Entry seq 1 has observed_peers 9 in the synthetic data.
        // (The rewrites below re-add the trailing newline that
        // split() drops: since R-M04 a file NOT ending in '\n' is
        // by definition an interrupted write, and the store would
        // truncate its last line before judging anything else.)
        lines[2] = lines[2].replace("\"observed_peers\":9", "\"observed_peers\":8");
        java.nio.file.Files.write(file.toPath(),
                String.join("\n", lines).concat("\n").getBytes(StandardCharsets.UTF_8));
        JournalStore afterTamper = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("journal auth: tampered entry dropped with its tail",
                afterTamper.count() == 1 && afterTamper.droppedOnLoad() == 2);
        JournalStore afterRewrite = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("journal auth: accepted prefix persisted, no re-drop",
                afterRewrite.count() == 1 && afterRewrite.droppedOnLoad() == 0);

        // --- forged signature (signed by a DIFFERENT key): the
        // entry and its tail are dropped ---
        File file2 = new File(dir, "journal2.json");
        JournalStore j2 = JournalStore.forFile(file2, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        j2.bindIdentity(deviceId, Hex.encode(pub));
        for (int i = 0; i < 2; i++) {
            j2.append(DepinCore.makeCheckpoint(i, obs.get(i),
                    j2.nextPrevState(), j2.nextPrevCheckpointHash(), 50, pub));
        }
        byte[] otherSeed = new byte[32];
        Arrays.fill(otherSeed, (byte) 0x77);
        String content2 = new String(java.nio.file.Files.readAllBytes(file2.toPath()),
                StandardCharsets.UTF_8);
        String[] lines2 = content2.split("\n");
        String forged = Hex.encode(DepinCore.journalEntrySig(
                otherSeed, j2.checkpoints().get(0).checkpointHash, 0));
        lines2[1] = lines2[1].replaceAll(
                "\"entry_sig\":\"[0-9a-f]+\"", "\"entry_sig\":\"" + forged + "\"");
        java.nio.file.Files.write(file2.toPath(),
                String.join("\n", lines2).concat("\n").getBytes(StandardCharsets.UTF_8));
        JournalStore afterForge = JournalStore.forFile(file2, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("journal auth: forged signature entry dropped with its tail",
                afterForge.count() == 0 && afterForge.droppedOnLoad() == 2);

        // --- legacy migration: a v0.3-era pretty-printed journal
        // with internally consistent entries migrates to JSONL and
        // its entries are re-signed ---
        File legacyFile = new File(dir, "journal-legacy.json");
        List<DepinCore.Checkpoint> legacyCps = new ArrayList<>();
        byte[] prevState = DepinCore.ZERO32;
        byte[] prevHash = DepinCore.ZERO32;
        for (int i = 0; i < 3; i++) {
            DepinCore.Checkpoint c = DepinCore.makeCheckpoint(i, obs.get(i),
                    prevState, prevHash, 50, pub);
            // Pre-v0.4 entries carry v0.3-domain checkpoint hashes.
            c.checkpointHash = DepinCore.checkpointHashV03(c);
            legacyCps.add(c);
            prevState = c.chainState;
            prevHash = c.checkpointHash;
        }
        java.util.Map<String, Object> root = new java.util.LinkedHashMap<>();
        root.put("format", "quantus-depin-journal");
        root.put("version", "0.3");
        root.put("device_id", deviceId);
        root.put("pubkey", Hex.encode(pub));
        List<Object> rawCps = new ArrayList<>();
        for (DepinCore.Checkpoint c : legacyCps) rawCps.add(c.toMap());
        root.put("checkpoints", rawCps);
        java.nio.file.Files.write(legacyFile.toPath(),
                Json.pretty(root).getBytes(StandardCharsets.UTF_8));

        JournalStore migrated = JournalStore.forFile(legacyFile, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("journal migration: consistent legacy entries are archived, live is empty",
                migrated.count() == 0 && migrated.archivedCount() == 3
                        && migrated.archivedOnLoad() == 3
                        && migrated.droppedOnLoad() == 0);
        String migratedText = new String(
                java.nio.file.Files.readAllBytes(legacyFile.toPath()),
                StandardCharsets.UTF_8);
        check("journal migration: live file is now header-only JSONL",
                migratedText.startsWith("{\"checkpoints\"") == false
                        && migratedText.contains("\"type\":\"header\"")
                        && migratedText.contains("\"entry_sig\"") == false);
        File archiveFile = new File(dir, JournalStore.ARCHIVE_FILE_NAME);
        String archiveText = new String(
                java.nio.file.Files.readAllBytes(archiveFile.toPath()),
                StandardCharsets.UTF_8);
        check("journal migration: archive holds the signed legacy entries",
                archiveFile.exists()
                        && archiveText.contains("\"entry_sig\"")
                        && archiveText.contains("\"version\":\"0.3\""));
        JournalStore migratedReopen = JournalStore.forFile(legacyFile, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("journal migration: reopen keeps live empty, archive intact, no re-archive",
                migratedReopen.count() == 0 && migratedReopen.archivedCount() == 3
                        && migratedReopen.archivedOnLoad() == 0
                        && migratedReopen.droppedOnLoad() == 0);

        // --- legacy migration with a broken linkage: only the
        // consistent prefix migrates ---
        File brokenFile = new File(dir, "journal-legacy-broken.json");
        List<Object> rawBroken = new ArrayList<>();
        for (DepinCore.Checkpoint c : legacyCps) rawBroken.add(c.toMap());
        @SuppressWarnings("unchecked")
        Map<String, Object> brokenCp = (Map<String, Object>) rawBroken.get(1);
        brokenCp.put("prev_checkpoint_hash", Hex.encode(DepinCore.ZERO32));
        java.util.Map<String, Object> root2 = new java.util.LinkedHashMap<>(root);
        root2.put("checkpoints", rawBroken);
        java.nio.file.Files.write(brokenFile.toPath(),
                Json.pretty(root2).getBytes(StandardCharsets.UTF_8));
        JournalStore broken = JournalStore.forFile(brokenFile, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("journal migration: broken linkage archives only the prefix",
                broken.count() == 0 && broken.droppedOnLoad() == 2
                        && broken.archivedCount() >= 1);
    }

    /** Build the v0.3-domain legacy checkpoints used by the
     *  migration / archive tests: v0.4 chain states (as the harness
     *  synthetic data produces) but v0.3-domain checkpoint hashes,
     *  exactly the shape a pre-v0.4 journal holds. */
    private static List<DepinCore.Checkpoint> legacyCheckpoints(
            List<DepinCore.Observation> obs, int count, byte[] pub) {
        List<DepinCore.Checkpoint> cps = new ArrayList<>();
        byte[] prevState = DepinCore.ZERO32;
        byte[] prevHash = DepinCore.ZERO32;
        for (int i = 0; i < count; i++) {
            DepinCore.Checkpoint c = DepinCore.makeCheckpoint(i, obs.get(i),
                    prevState, prevHash, 50, pub);
            c.checkpointHash = DepinCore.checkpointHashV03(c);
            cps.add(c);
            prevState = c.chainState;
            prevHash = c.checkpointHash;
        }
        return cps;
    }

    private static void writeLegacyPrettyJournal(File file,
            List<DepinCore.Checkpoint> cps, String deviceId, byte[] pub)
            throws Exception {
        java.util.Map<String, Object> root = new java.util.LinkedHashMap<>();
        root.put("format", "quantus-depin-journal");
        root.put("version", "0.3");
        root.put("device_id", deviceId);
        root.put("pubkey", Hex.encode(pub));
        List<Object> rawCps = new ArrayList<>();
        for (DepinCore.Checkpoint c : cps) rawCps.add(c.toMap());
        root.put("checkpoints", rawCps);
        java.nio.file.Files.write(file.toPath(),
                Json.pretty(root).getBytes(StandardCharsets.UTF_8));
    }

    private static void testJournalArchive() throws Exception {
        byte[] seed = testSeed();
        byte[] pub = Ed25519.publickeyFromSeed(seed);
        String deviceId = DepinCore.deviceIdFromPubkey(pub);
        List<DepinCore.Observation> obs = syntheticObservations(6);

        // --- (a) legacy pretty-printed journal migrates: live
        // journal EMPTY, the consistent prefix lands in the
        // archive (v0.2.1 fix for the v0.2.0 defect that kept
        // v0.3-domain entries in the live journal, where they
        // poisoned every v0.4 bundle export) ---
        File dir = new File(System.getProperty("java.io.tmpdir"),
                "depin-journal-archive-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        File file = new File(dir, "journal.json");
        List<DepinCore.Checkpoint> legacyCps = legacyCheckpoints(obs, 3, pub);
        writeLegacyPrettyJournal(file, legacyCps, deviceId, pub);

        JournalStore store = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        File archiveFile = new File(dir, JournalStore.ARCHIVE_FILE_NAME);
        check("archive: migration leaves the live journal empty",
                store.count() == 0 && store.last() == null);
        check("archive: migration archives all consistent legacy entries",
                store.archivedCount() == 3 && store.archivedOnLoad() == 3
                        && archiveFile.exists());

        // --- (b) after migration the SAME store starts a fresh
        // v0.4 chain at seq 0 / zero prev, and a bundle built from
        // the reloaded journal passes full v0.4 verification ---
        store.bindIdentity(deviceId, Hex.encode(pub));
        check("archive: fresh chain starts from zero prev state",
                Arrays.equals(store.nextPrevCheckpointHash(), DepinCore.ZERO32)
                        && Arrays.equals(store.nextPrevState(), DepinCore.ZERO32));
        for (int i = 0; i < 2; i++) {
            // Observations continue after the legacy ones so the
            // timestamps keep increasing across the boundary.
            DepinCore.Observation o = obs.get(3 + i);
            store.append(DepinCore.makeCheckpoint(store.count(), o,
                    store.nextPrevState(), store.nextPrevCheckpointHash(), 50, pub));
        }
        check("archive: new checkpoints take seq 0.. with zero-based chain",
                store.count() == 2
                        && store.checkpoints().get(0).seq == 0
                        && Arrays.equals(store.checkpoints().get(0).prevCheckpointHash,
                                DepinCore.ZERO32));
        JournalStore reloaded = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("archive: post-migration journal reloads clean, archive untouched",
                reloaded.count() == 2 && reloaded.droppedOnLoad() == 0
                        && reloaded.archivedCount() == 3
                        && reloaded.archivedOnLoad() == 0);
        Map<String, Object> bundle = DepinCore.assembleBundle(
                seed, reloaded.checkpoints(), 1762003600L, 50);
        check("archive: bundle from post-migration journal verifies (current format)",
                DepinCore.verifyBundle(bundle, 50).isEmpty());

        // --- (c) the archive file itself verifies entry by entry:
        // header shape, v0.3-domain hash recomputation, prev
        // linkage from zero, and every entry_sig ---
        String archiveText = new String(
                java.nio.file.Files.readAllBytes(archiveFile.toPath()),
                StandardCharsets.UTF_8);
        String[] aLines = archiveText.split("\n");
        Map<String, Object> aHeader = Json.parseObject(aLines[0].trim());
        check("archive: header records the legacy format version",
                "header".equals(aHeader.get("type"))
                        && "0.3".equals(aHeader.get("version"))
                        && deviceId.equals(aHeader.get("device_id")));
        boolean archiveOk = aLines.length == 4; // header + 3 entries
        byte[] prev = DepinCore.ZERO32;
        for (int i = 1; i < aLines.length && archiveOk; i++) {
            Map<String, Object> e = Json.parseObject(aLines[i].trim());
            Object sigObj = e.remove("entry_sig");
            if (!(sigObj instanceof String)) { archiveOk = false; break; }
            byte[] sig = Hex.decodeCanonical((String) sigObj);
            DepinCore.Checkpoint cp = DepinCore.Checkpoint.fromMap(e);
            archiveOk = cp.seq == i - 1
                    && Arrays.equals(cp.prevCheckpointHash, prev)
                    && Arrays.equals(DepinCore.checkpointHashV03(cp), cp.checkpointHash)
                    && DepinCore.verifyJournalEntrySig(
                            pub, cp.checkpointHash, cp.seq, sig);
            prev = cp.checkpointHash;
        }
        check("archive: every archived entry verifies (v0.3 hash, linkage, entry_sig)",
                archiveOk);

        // --- load defence: a JSONL journal whose HEAD entries are
        // v0.3-domain (the shape the v0.2.0 migration produced in
        // the live file) gets them moved to the archive on load ---
        File dir2 = new File(System.getProperty("java.io.tmpdir"),
                "depin-journal-defence-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dir2.mkdirs();
        File mixed = new File(dir2, "journal.json");
        StringBuilder sb = new StringBuilder();
        Map<String, Object> hdr = new java.util.LinkedHashMap<>();
        hdr.put("type", "header");
        hdr.put("format", "quantus-depin-journal");
        hdr.put("version", "0.4");
        hdr.put("device_id", deviceId);
        hdr.put("pubkey", Hex.encode(pub));
        sb.append(Json.canonical(hdr)).append('\n');
        for (DepinCore.Checkpoint c : legacyCps) {
            Map<String, Object> m = c.toMap();
            m.put("entry_sig", Hex.encode(
                    DepinCore.journalEntrySig(seed, c.checkpointHash, c.seq)));
            sb.append(Json.canonical(m)).append('\n');
        }
        java.nio.file.Files.write(mixed.toPath(),
                sb.toString().getBytes(StandardCharsets.UTF_8));
        JournalStore defended = JournalStore.forFile(mixed, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("archive: JSONL legacy head is moved out of the live journal",
                defended.count() == 0 && defended.archivedCount() == 3
                        && defended.droppedOnLoad() == 0);
        JournalStore defendedReopen = JournalStore.forFile(mixed, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("archive: defended journal stays clean on reopen",
                defendedReopen.count() == 0 && defendedReopen.archivedCount() == 3
                        && defendedReopen.archivedOnLoad() == 0
                        && defendedReopen.droppedOnLoad() == 0);

        // --- a v0.4 entry chained ONTO the legacy prefix cannot
        // be re-based (its hashes bind the legacy anchor): with
        // the prefix archived, it falls under the drop rule ---
        File dir3 = new File(System.getProperty("java.io.tmpdir"),
                "depin-journal-anchored-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dir3.mkdirs();
        File anchored = new File(dir3, "journal.json");
        DepinCore.Checkpoint legacy0 = legacyCps.get(0);
        DepinCore.Checkpoint chained = DepinCore.makeCheckpoint(1, obs.get(1),
                legacy0.chainState, legacy0.checkpointHash, 50, pub);
        StringBuilder sb2 = new StringBuilder();
        sb2.append(Json.canonical(hdr)).append('\n');
        Map<String, Object> lm = legacy0.toMap();
        lm.put("entry_sig", Hex.encode(
                DepinCore.journalEntrySig(seed, legacy0.checkpointHash, 0)));
        sb2.append(Json.canonical(lm)).append('\n');
        Map<String, Object> cm = chained.toMap();
        cm.put("entry_sig", Hex.encode(
                DepinCore.journalEntrySig(seed, chained.checkpointHash, 1)));
        sb2.append(Json.canonical(cm)).append('\n');
        java.nio.file.Files.write(anchored.toPath(),
                sb2.toString().getBytes(StandardCharsets.UTF_8));
        JournalStore anchoredStore = JournalStore.forFile(anchored, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("archive: current entry anchored to the archived prefix is dropped, not re-based",
                anchoredStore.count() == 0 && anchoredStore.archivedCount() == 1
                        && anchoredStore.droppedOnLoad() == 1);
    }

    /** Build genuine checkpoints of a legacy profile (chain states
     *  AND checkpoint hashes under that profile), the shape a real
     *  journal of that app version held. */
    private static List<DepinCore.Checkpoint> profileCheckpoints(
            DepinCore.FormatProfile fmt, List<DepinCore.Observation> obs,
            int count, byte[] pub) {
        List<DepinCore.Checkpoint> cps = new ArrayList<>();
        byte[] prevState = DepinCore.ZERO32;
        byte[] prevHash = DepinCore.ZERO32;
        for (int i = 0; i < count; i++) {
            DepinCore.Checkpoint c = DepinCore.makeCheckpoint(fmt, i, obs.get(i),
                    prevState, prevHash, 50, pub);
            cps.add(c);
            prevState = c.chainState;
            prevHash = c.checkpointHash;
        }
        return cps;
    }

    private static void writeJsonlJournal(File file,
            List<DepinCore.Checkpoint> cps, String headerVersion,
            String deviceId, byte[] pub, byte[] seed) throws Exception {
        StringBuilder sb = new StringBuilder();
        Map<String, Object> hdr = new java.util.LinkedHashMap<>();
        hdr.put("type", "header");
        hdr.put("format", "quantus-depin-journal");
        hdr.put("version", headerVersion);
        hdr.put("device_id", deviceId);
        hdr.put("pubkey", Hex.encode(pub));
        sb.append(Json.canonical(hdr)).append('\n');
        for (DepinCore.Checkpoint c : cps) {
            Map<String, Object> m = c.toMap();
            m.put("entry_sig", Hex.encode(
                    DepinCore.journalEntrySig(seed, c.checkpointHash, c.seq)));
            sb.append(Json.canonical(m)).append('\n');
        }
        java.nio.file.Files.write(file.toPath(),
                sb.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static void testJournalMigrationV04() throws Exception {
        byte[] seed = testSeed();
        byte[] pub = Ed25519.publickeyFromSeed(seed);
        String deviceId = DepinCore.deviceIdFromPubkey(pub);
        List<DepinCore.Observation> obs = syntheticObservations(6);
        List<DepinCore.Checkpoint> v04Cps =
                profileCheckpoints(DepinCore.FMT_V04, obs, 3, pub);

        // --- a genuine v0.4 JSONL journal (the live format of app
        // v0.2.x): on first start under v0.3.0 the live journal
        // starts EMPTY for v0.5 and the whole prefix is preserved
        // in journal-archive-v0.4.jsonl with its entry_sigs ---
        File dir = new File(System.getProperty("java.io.tmpdir"),
                "depin-journal-mig04-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        File file = new File(dir, "journal.json");
        writeJsonlJournal(file, v04Cps, "0.4", deviceId, pub, seed);

        JournalStore store = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        File archiveV04 = new File(dir, JournalStore.ARCHIVE_V04_FILE_NAME);
        check("migration v0.4: live journal starts empty for v0.5",
                store.count() == 0 && store.last() == null);
        check("migration v0.4: prefix archived to the v0.4 archive",
                store.archivedV04Count() == 3 && store.archivedOnLoadV04() == 3
                        && store.archivedV03Count() == 0
                        && store.droppedOnLoad() == 0
                        && archiveV04.exists());

        // The archive itself verifies entry by entry (v0.4-domain
        // hash recomputation, linkage from zero, entry_sigs).
        String archiveText = new String(
                java.nio.file.Files.readAllBytes(archiveV04.toPath()),
                StandardCharsets.UTF_8);
        String[] aLines = archiveText.split("\n");
        Map<String, Object> aHeader = Json.parseObject(aLines[0].trim());
        boolean archiveOk = aLines.length == 4
                && "header".equals(aHeader.get("type"))
                && "0.4".equals(aHeader.get("version"));
        byte[] prev = DepinCore.ZERO32;
        for (int i = 1; i < aLines.length && archiveOk; i++) {
            Map<String, Object> e = Json.parseObject(aLines[i].trim());
            Object sigObj = e.remove("entry_sig");
            if (!(sigObj instanceof String)) { archiveOk = false; break; }
            byte[] sig = Hex.decodeCanonical((String) sigObj);
            DepinCore.Checkpoint cp = DepinCore.Checkpoint.fromMap(e);
            archiveOk = cp.seq == i - 1
                    && Arrays.equals(cp.prevCheckpointHash, prev)
                    && Arrays.equals(
                            DepinCore.checkpointHashV04(cp), cp.checkpointHash)
                    && DepinCore.verifyJournalEntrySig(
                            pub, cp.checkpointHash, cp.seq, sig);
            prev = cp.checkpointHash;
        }
        check("migration v0.4: every archived entry verifies", archiveOk);

        // New v0.5 checkpoints accumulate on the emptied journal
        // and export a bundle the current verifier accepts as 0.5.
        store.bindIdentity(deviceId, Hex.encode(pub));
        for (int i = 0; i < 2; i++) {
            store.append(DepinCore.makeCheckpoint(store.count(), obs.get(3 + i),
                    store.nextPrevState(), store.nextPrevCheckpointHash(), 50, pub));
        }
        JournalStore reloaded = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        Map<String, Object> bundle = DepinCore.assembleBundle(
                seed, reloaded.checkpoints(), 1762003600L, 50);
        check("migration v0.4: v0.5 history accumulates and exports as 0.5",
                reloaded.count() == 2 && reloaded.droppedOnLoad() == 0
                        && reloaded.archivedV04Count() == 3
                        && "0.5".equals(bundle.get("version"))
                        && DepinCore.verifyBundle(bundle, 50).isEmpty());

        // --- a v0.5 entry chained ONTO the v0.4 prefix cannot be
        // re-based: the prefix archives, the anchored entry drops ---
        File dir2 = new File(System.getProperty("java.io.tmpdir"),
                "depin-journal-mig04-anchor-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dir2.mkdirs();
        File anchored = new File(dir2, "journal.json");
        DepinCore.Checkpoint v04first = v04Cps.get(0);
        DepinCore.Checkpoint chained = DepinCore.makeCheckpoint(1, obs.get(1),
                v04first.chainState, v04first.checkpointHash, 50, pub);
        List<DepinCore.Checkpoint> mixed = Arrays.asList(v04first, chained);
        // Write manually: writeJsonlJournal would sign both lines
        // the same way, which is exactly the anchored shape.
        writeJsonlJournal(anchored, mixed, "0.4", deviceId, pub, seed);
        JournalStore anchoredStore = JournalStore.forFile(anchored, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("migration v0.4: entry anchored to the v0.4 prefix is dropped, not re-based",
                anchoredStore.count() == 0
                        && anchoredStore.archivedV04Count() == 1
                        && anchoredStore.droppedOnLoad() == 1);
    }

    private static void testJournalPartialTail() throws Exception {
        byte[] seed = testSeed();
        byte[] pub = Ed25519.publickeyFromSeed(seed);
        String deviceId = DepinCore.deviceIdFromPubkey(pub);
        List<DepinCore.Observation> obs = syntheticObservations(6);

        // --- live journal: two complete entries, then a crash
        // mid-append leaves a partial third line (no newline) ---
        File dir = new File(System.getProperty("java.io.tmpdir"),
                "depin-journal-partial-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        File file = new File(dir, "journal.json");
        JournalStore j = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        j.bindIdentity(deviceId, Hex.encode(pub));
        for (int i = 0; i < 2; i++) {
            j.append(DepinCore.makeCheckpoint(i, obs.get(i),
                    j.nextPrevState(), j.nextPrevCheckpointHash(), 50, pub));
        }
        try (java.io.FileOutputStream out = new java.io.FileOutputStream(file, true)) {
            out.write("{\"best_block_hash\":\"ab12".getBytes(StandardCharsets.UTF_8));
        }
        JournalStore reopened = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("partial tail: truncation reported, complete entries survive",
                reopened.partialTailDropped() == 1
                        && reopened.count() == 2
                        && reopened.droppedOnLoad() == 0);
        // Appending after the repair must not glue onto the
        // partial line (the R-M04 "}{" corruption).
        reopened.append(DepinCore.makeCheckpoint(2, obs.get(2),
                reopened.nextPrevState(), reopened.nextPrevCheckpointHash(), 50, pub));
        String raw = new String(java.nio.file.Files.readAllBytes(file.toPath()),
                StandardCharsets.UTF_8);
        boolean allLinesParse = raw.endsWith("\n") && !raw.contains("}{");
        if (allLinesParse) {
            for (String line : raw.split("\n")) {
                if (line.trim().isEmpty()) continue;
                try {
                    Json.parseObject(line.trim());
                } catch (RuntimeException e) {
                    allLinesParse = false;
                    break;
                }
            }
        }
        check("partial tail: append after repair stays line-clean", allLinesParse);
        JournalStore again = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("partial tail: repaired journal reloads fully, no re-truncation",
                again.count() == 3 && again.droppedOnLoad() == 0
                        && again.partialTailDropped() == 0);

        // --- archive file with a partial tail: the next migration
        // append truncates it first, then appends cleanly ---
        File dir2 = new File(System.getProperty("java.io.tmpdir"),
                "depin-journal-partial-arc-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dir2.mkdirs();
        List<DepinCore.Checkpoint> v04a =
                profileCheckpoints(DepinCore.FMT_V04, obs, 2, pub);
        File liveA = new File(dir2, "journal.json");
        writeJsonlJournal(liveA, v04a, "0.4", deviceId, pub, seed);
        JournalStore storeA = JournalStore.forFile(liveA, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("partial tail: first migration archived",
                storeA.archivedV04Count() == 2);
        File archive = new File(dir2, JournalStore.ARCHIVE_V04_FILE_NAME);
        try (java.io.FileOutputStream out = new java.io.FileOutputStream(archive, true)) {
            out.write("{\"best_block_number\":".getBytes(StandardCharsets.UTF_8));
        }
        // A second journal in the same directory migrates one more
        // v0.4 entry (a distinct observation, hence a new hash —
        // re-using an already-archived checkpoint would be skipped
        // by the archive's dedup, by design).
        List<DepinCore.Observation> otherObs = new ArrayList<>();
        DepinCore.Observation oo = new DepinCore.Observation();
        oo.timestampUnix = 1762999999L;
        oo.bestBlockNumber = 999999;
        oo.bestBlockHash = DepinCore.sha256(
                "partial-archive-other".getBytes(StandardCharsets.US_ASCII));
        oo.observedPeers = 3;
        oo.finalizedBlockNumber = 999990L;
        otherObs.add(oo);
        List<DepinCore.Checkpoint> v04b =
                profileCheckpoints(DepinCore.FMT_V04, otherObs, 1, pub);
        File liveB = new File(dir2, "journal-b.json");
        writeJsonlJournal(liveB, v04b, "0.4", deviceId, pub, seed);
        JournalStore storeB = JournalStore.forFile(liveB, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("partial tail: archive truncated before migration append",
                storeB.archivedV04Count() == 3);
        String arcRaw = new String(java.nio.file.Files.readAllBytes(archive.toPath()),
                StandardCharsets.UTF_8);
        boolean arcClean = arcRaw.endsWith("\n") && !arcRaw.contains("}{");
        int arcLines = 0;
        if (arcClean) {
            for (String line : arcRaw.split("\n")) {
                if (line.trim().isEmpty()) continue;
                arcLines++;
                try {
                    Json.parseObject(line.trim());
                } catch (RuntimeException e) {
                    arcClean = false;
                    break;
                }
            }
        }
        check("partial tail: archive lines all parse after repair",
                arcClean && arcLines == 4); // header + 3 entries
    }

    /** Build a valid current-format journal with `entries`
     *  checkpoints over `file` and return its exact bytes. */
    private static byte[] buildValidJournal(File file, int entries,
            byte[] seed, byte[] pub, String deviceId,
            List<DepinCore.Observation> obs) throws Exception {
        JournalStore j = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        for (int i = 0; i < entries; i++) {
            j.append(DepinCore.makeCheckpoint(i, obs.get(i),
                    j.nextPrevState(), j.nextPrevCheckpointHash(), 50, pub));
        }
        return java.nio.file.Files.readAllBytes(file.toPath());
    }

    /** Open a journal whose header is damaged and assert the B4
     *  recovery contract: load does not throw, the damaged file is
     *  quarantined with its EXACT bytes, the store is a fresh
     *  journal under the expected identity, and append + export
     *  work afterwards. Returns nothing; assertions are via
     *  check(). */
    private static void assertHeaderQuarantine(String label, File file,
            byte[] damagedBytes, byte[] seed, byte[] pub, String deviceId,
            List<DepinCore.Observation> obs) throws Exception {
        JournalStore s = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        File q = s.quarantinedFile();
        check(label + ": recovery flagged, quarantine file recorded",
                s.recoveryOccurred() && q != null && s.quarantinedFiles().size() == 1);
        check(label + ": quarantine name and existence",
                q != null && q.getName().startsWith("journal-corrupt-")
                        && q.getName().endsWith(".jsonl") && q.exists());
        check(label + ": quarantined bytes are the exact damaged file",
                q != null && Arrays.equals(
                        java.nio.file.Files.readAllBytes(q.toPath()), damagedBytes));
        check(label + ": fresh journal starts empty", s.count() == 0);
        s.append(DepinCore.makeCheckpoint(0, obs.get(0),
                s.nextPrevState(), s.nextPrevCheckpointHash(), 50, pub));
        JournalStore reopened = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        Map<String, Object> bundle = DepinCore.assembleBundle(
                seed, reopened.checkpoints(), 1762003600L, 50);
        check(label + ": append + export work after recovery",
                reopened.count() == 1 && !reopened.recoveryOccurred()
                        && DepinCore.verifyBundle(bundle, 50).isEmpty());
    }

    private static void testJournalHeaderRecovery() throws Exception {
        byte[] seed = testSeed();
        byte[] pub = Ed25519.publickeyFromSeed(seed);
        String deviceId = DepinCore.deviceIdFromPubkey(pub);
        byte[] seed2 = new byte[32];
        Arrays.fill(seed2, (byte) 0x5A);
        byte[] pub2 = Ed25519.publickeyFromSeed(seed2);
        String deviceId2 = DepinCore.deviceIdFromPubkey(pub2);
        List<DepinCore.Observation> obs = syntheticObservations(6);

        // --- the damage matrix on a valid 3-entry journal ---
        String[] caseNames = {
                "header recovery: line 0 deleted",
                "header recovery: lines 0/1 swapped",
                "header recovery: device_id byte flipped",
                "header recovery: truncated mid-header",
                "header recovery: header replaced with garbage",
                "header recovery: foreign journal",
        };
        for (int c = 0; c < caseNames.length; c++) {
            File dir = new File(System.getProperty("java.io.tmpdir"),
                    "depin-journal-hdr-" + c + "-" + System.nanoTime());
            //noinspection ResultOfMethodCallIgnored
            dir.mkdirs();
            File file = new File(dir, "journal.json");
            byte[] seedC = (c == 5) ? seed2 : seed;
            byte[] pubC = (c == 5) ? pub2 : pub;
            String idC = (c == 5) ? deviceId2 : deviceId;
            byte[] valid = buildValidJournal(file, 3, seedC, pubC, idC, obs);
            String text = new String(valid, StandardCharsets.UTF_8);
            String[] lines = text.split("\n");
            byte[] damaged;
            switch (c) {
                case 0: {
                    String joined = String.join("\n",
                            Arrays.copyOfRange(lines, 1, lines.length)) + "\n";
                    damaged = joined.getBytes(StandardCharsets.UTF_8);
                    break;
                }
                case 1: {
                    String[] swapped = lines.clone();
                    swapped[0] = lines[1];
                    swapped[1] = lines[0];
                    damaged = (String.join("\n", swapped) + "\n")
                            .getBytes(StandardCharsets.UTF_8);
                    break;
                }
                case 2: {
                    String[] mutated = lines.clone();
                    int at = mutated[0].indexOf(idC);
                    char orig = mutated[0].charAt(at);
                    mutated[0] = mutated[0].substring(0, at)
                            + (orig == 'a' ? 'b' : 'a')
                            + mutated[0].substring(at + 1);
                    damaged = (String.join("\n", mutated) + "\n")
                            .getBytes(StandardCharsets.UTF_8);
                    break;
                }
                case 3: {
                    int headerLen = text.indexOf('\n');
                    damaged = Arrays.copyOf(valid, Math.max(1, headerLen * 2 / 5));
                    break;
                }
                case 4: {
                    String[] mutated = lines.clone();
                    mutated[0] = "this is not a json header {{{";
                    damaged = (String.join("\n", mutated) + "\n")
                            .getBytes(StandardCharsets.UTF_8);
                    break;
                }
                default: {
                    damaged = valid; // foreign journal: intact bytes,
                                     // wrong identity for this store
                    break;
                }
            }
            java.nio.file.Files.write(file.toPath(), damaged);
            assertHeaderQuarantine(caseNames[c], file, damaged,
                    seed, pub, deviceId, obs);
        }

        // --- 0-byte file: fresh journal, NOT a recovery event ---
        File dirZ = new File(System.getProperty("java.io.tmpdir"),
                "depin-journal-hdr-zero-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dirZ.mkdirs();
        File emptyFile = new File(dirZ, "journal.json");
        //noinspection ResultOfMethodCallIgnored
        emptyFile.createNewFile();
        JournalStore zero = JournalStore.forFile(emptyFile, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        boolean anyQuarantineFile = false;
        String[] zeroDirFiles = dirZ.list();
        if (zeroDirFiles != null) {
            for (String n : zeroDirFiles) {
                if (n.startsWith("journal-corrupt-")) anyQuarantineFile = true;
            }
        }
        check("header recovery: 0-byte file is a fresh journal, no quarantine",
                zero.count() == 0 && !zero.recoveryOccurred()
                        && zero.quarantinedFiles().isEmpty()
                        && !anyQuarantineFile);
        zero.append(DepinCore.makeCheckpoint(0, obs.get(0),
                zero.nextPrevState(), zero.nextPrevCheckpointHash(), 50, pub));
        check("header recovery: 0-byte journal accepts appends",
                zero.count() == 1);

        // --- healthy journal: zero recovery events, entries and
        // file bytes carried over identical (the v0.3.1 upgrade
        // must NOT migrate or rewrite a healthy v0.5 journal) ---
        File dirH = new File(System.getProperty("java.io.tmpdir"),
                "depin-journal-hdr-healthy-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dirH.mkdirs();
        File healthyFile = new File(dirH, "journal.json");
        byte[] healthyBytes = buildValidJournal(
                healthyFile, 3, seed, pub, deviceId, obs);
        JournalStore healthy = JournalStore.forFile(healthyFile, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("header recovery: healthy journal loads with no recovery",
                healthy.count() == 3 && !healthy.recoveryOccurred()
                        && healthy.droppedOnLoad() == 0
                        && healthy.quarantinedFiles().isEmpty());
        check("header recovery: healthy journal file is byte-identical after load",
                Arrays.equals(healthyBytes,
                        java.nio.file.Files.readAllBytes(healthyFile.toPath())));

        // --- archive with a damaged header: the count path does
        // not throw, the archive is quarantined, the live journal
        // is untouched ---
        for (int c = 0; c < 2; c++) {
            String label = (c == 0)
                    ? "header recovery: archive header garbage"
                    : "header recovery: archive header foreign identity";
            File dir = new File(System.getProperty("java.io.tmpdir"),
                    "depin-journal-hdr-arc-" + c + "-" + System.nanoTime());
            //noinspection ResultOfMethodCallIgnored
            dir.mkdirs();
            File live = new File(dir, "journal.json");
            List<DepinCore.Checkpoint> v04 =
                    profileCheckpoints(DepinCore.FMT_V04, obs, 2, pub);
            writeJsonlJournal(live, v04, "0.4", deviceId, pub, seed);
            JournalStore first = JournalStore.forFile(live, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
            first.append(DepinCore.makeCheckpoint(0, obs.get(2),
                    first.nextPrevState(), first.nextPrevCheckpointHash(), 50, pub));
            File archive = new File(dir, JournalStore.ARCHIVE_V04_FILE_NAME);
            String arcText = new String(
                    java.nio.file.Files.readAllBytes(archive.toPath()),
                    StandardCharsets.UTF_8);
            String[] aLines = arcText.split("\n");
            if (c == 0) {
                aLines[0] = "garbage, not a header";
            } else {
                aLines[0] = aLines[0].replace(deviceId, deviceId2);
            }
            byte[] damagedArc = (String.join("\n", aLines) + "\n")
                    .getBytes(StandardCharsets.UTF_8);
            java.nio.file.Files.write(archive.toPath(), damagedArc);
            JournalStore second = JournalStore.forFile(live, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
            File qArc = null;
            for (File q : second.quarantinedFiles()) {
                if (q.getName().startsWith(
                        JournalStore.ARCHIVE_V04_FILE_NAME + ".corrupt-")) {
                    qArc = q;
                }
            }
            check(label + ": archive quarantined, count reads 0, notice set",
                    second.archiveRecoveryOccurred()
                            && second.archivedV04Count() == 0 && qArc != null);
            check(label + ": quarantined archive bytes are exact",
                    qArc != null && Arrays.equals(
                            java.nio.file.Files.readAllBytes(qArc.toPath()),
                            damagedArc));
            check(label + ": live journal untouched by archive recovery",
                    second.count() == 1 && second.droppedOnLoad() == 0);
        }

        // --- foreign LEGACY document: quarantined whole, nothing
        // archived under this device's identity ---
        File dirL = new File(System.getProperty("java.io.tmpdir"),
                "depin-journal-hdr-legacy-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dirL.mkdirs();
        File legacyFile = new File(dirL, "journal.json");
        List<DepinCore.Checkpoint> foreignCps =
                legacyCheckpoints(obs, 2, pub2);
        writeLegacyPrettyJournal(legacyFile, foreignCps, deviceId2, pub2);
        byte[] foreignBytes = java.nio.file.Files.readAllBytes(legacyFile.toPath());
        JournalStore foreign = JournalStore.forFile(legacyFile, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("header recovery: foreign legacy document quarantined, nothing archived",
                foreign.recoveryOccurred() && foreign.count() == 0
                        && foreign.archivedCount() == 0
                        && foreign.quarantinedFile() != null
                        && Arrays.equals(java.nio.file.Files.readAllBytes(
                                foreign.quarantinedFile().toPath()), foreignBytes));
    }

    private static void testJson() {
        Map<String, Object> sync = Json.parseObject(
                "{\"currentBlock\":350123,\"highestBlock\":350130,"
                        + "\"startingBlock\":340000}");
        check("json: syncState currentBlock", Json.asLong(sync.get("currentBlock")) == 350123L);
        Map<String, Object> header = Json.parseObject(
                "{\"number\":\"0x55d3\",\"parentHash\":\"0x00\"}");
        check("json: header hex number",
                Long.parseLong(Hex.strip0x(Json.asString(header.get("number"))), 16)
                        == 0x55d3L);
        Map<String, Object> nested = Json.parseObject(
                "{\"b\":1,\"a\":{\"z\":[1,2,{\"k\":\"v\"}]}}");
        check("json: canonical key order",
                Json.canonical(nested).equals("{\"a\":{\"z\":[1,2,{\"k\":\"v\"}]},\"b\":1}"));

        // Strict number grammar (R-M01): the reference parser
        // rejects every one of these; the old reader accepted
        // several (it skipped digits without checking the shape).
        String[] badNumbers = {
                "{\"a\":00}", "{\"a\":01}", "{\"a\":-01}", "{\"a\":+1}",
                "{\"a\":1.}", "{\"a\":.5}", "{\"a\":1e}", "{\"a\":1e+}",
                "{\"a\":NaN}", "{\"a\":Infinity}", "{\"a\":-Infinity}",
                "[00]", "{\"a\":1.e3}",
        };
        boolean allRejected = true;
        for (String bad : badNumbers) {
            try {
                Json.parse(bad);
                allRejected = false;
                System.out.println("  (accepted but must reject: " + bad + ")");
            } catch (IllegalArgumentException expected) {
                // rejected, as required
            }
        }
        check("json: non-canonical numbers rejected", allRejected);

        // ...while canonical numbers keep their established types:
        // integers are Long, fractions/exponents are Double.
        Map<String, Object> nums = Json.parseObject(
                "{\"zero\":0,\"negzero\":-0,\"exp\":1e2,\"frac\":-12.5e-1,"
                        + "\"big\":1762000000}");
        check("json: canonical numbers parse with the right types",
                Json.asLong(nums.get("zero")) == 0L
                        && Json.asLong(nums.get("negzero")) == 0L
                        && nums.get("exp") instanceof Double
                        && nums.get("frac") instanceof Double
                        && Json.asLong(nums.get("big")) == 1762000000L);
    }

    // ---------------- RPC (injected transport) ----------------
    //
    // This build VM intercepts direct TCP from spawned processes, so
    // the harness cannot open real sockets here. It injects a canned
    // transport instead and exercises everything above the socket:
    // request encoding, response parsing, the observation sequence,
    // consistency re-check, and error surfacing. The on-device HTTP
    // transport itself is thin and mirrors the Node app's poller.

    private static RpcClient.Transport cannedTransport(
            java.util.function.Function<String, String> responder) {
        return body -> {
            String request = new String(body, StandardCharsets.UTF_8);
            String response = responder.apply(request);
            return response.getBytes(StandardCharsets.UTF_8);
        };
    }

    private static String resultJson(String result) {
        return "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":" + result + "}";
    }

    private static void testRpcAgainstStub() throws Exception {
        String bestHash = "0x" + "ab".repeat(32);
        String finHash = "0x" + "cd".repeat(32);
        RpcClient client = new RpcClient(cannedTransport(request -> {
            if (request.contains("system_syncState")) {
                return resultJson("{\"currentBlock\":1000,\"highestBlock\":1000,"
                        + "\"startingBlock\":900}");
            }
            if (request.contains("chain_getBlockHash")) {
                return resultJson("\"" + bestHash + "\"");
            }
            if (request.contains("chain_getFinalizedHead")) {
                return resultJson("\"" + finHash + "\"");
            }
            if (request.contains("chain_getHeader")) {
                return resultJson("{\"number\":\"0x3e0\",\"parentHash\":\"0x00\"}");
            }
            if (request.contains("system_health")) {
                return resultJson("{\"peers\":7,\"isSyncing\":false,"
                        + "\"shouldHavePeers\":true}");
            }
            if (request.contains("system_localPeerId")) {
                return resultJson("\"12D3KooWTestPeerId\"");
            }
            return resultJson("null");
        }));
        RpcClient.NodeObservation round = client.fetchObservation();
        check("rpc stub: best number", round.observation.bestBlockNumber == 1000L);
        check("rpc stub: best hash",
                Hex.encode(round.observation.bestBlockHash).equals("ab".repeat(32)));
        check("rpc stub: finalized number",
                round.observation.finalizedBlockNumber == 0x3e0L);
        check("rpc stub: peers", round.observation.observedPeers == 7);
        check("rpc stub: peer id",
                "12D3KooWTestPeerId".equals(client.fetchLocalPeerId()));

        // The request the client emits must be well-formed JSON-RPC
        // naming the method it means to call.
        StringBuilder seen = new StringBuilder();
        RpcClient probe = new RpcClient(body -> {
            seen.append(new String(body, StandardCharsets.UTF_8));
            return resultJson("\"ok\"").getBytes(StandardCharsets.UTF_8);
        });
        probe.call("system_health", java.util.Collections.emptyList());
        Map<String, Object> emitted = Json.parseObject(seen.toString());
        check("rpc stub: request shape",
                "2.0".equals(emitted.get("jsonrpc"))
                        && "system_health".equals(emitted.get("method")));

        // Inconsistent round: best moves between the two syncState
        // reads -> InconsistentObservation (treated as a gap).
        AtomicInteger syncCalls = new AtomicInteger();
        RpcClient moving = new RpcClient(cannedTransport(request -> {
            if (request.contains("system_syncState")) {
                int n = syncCalls.incrementAndGet();
                return resultJson("{\"currentBlock\":" + (1000 + n)
                        + ",\"highestBlock\":1001,\"startingBlock\":900}");
            }
            if (request.contains("chain_getBlockHash")) {
                return resultJson("\"" + bestHash + "\"");
            }
            if (request.contains("chain_getFinalizedHead")) {
                return resultJson("\"" + finHash + "\"");
            }
            if (request.contains("chain_getHeader")) {
                return resultJson("{\"number\":\"0x3e0\"}");
            }
            if (request.contains("system_health")) {
                return resultJson("{\"peers\":1,\"isSyncing\":false}");
            }
            return resultJson("null");
        }));
        boolean inconsistent = false;
        try {
            moving.fetchObservation();
        } catch (RpcClient.InconsistentObservation e) {
            inconsistent = true;
        }
        check("rpc stub: moving best is a gap, not a checkpoint", inconsistent);

        // Error object (the unsafe-gate shape) -> RpcException.
        RpcClient errClient = new RpcClient(cannedTransport(request ->
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":"
                        + "{\"code\":-32601,\"message\":\"RPC call is unsafe\"}}"));
        boolean threw = false;
        try {
            errClient.fetchObservation();
        } catch (RpcClient.RpcException e) {
            threw = e.getMessage().contains("unsafe");
        }
        check("rpc stub: RPC error surfaces", threw);

        // Transport-level failure (the "node is down" path).
        RpcClient dead = new RpcClient(body -> {
            throw new RpcClient.RpcException("connection refused");
        });
        threw = false;
        try {
            dead.fetchObservation();
        } catch (RpcClient.RpcException e) {
            threw = true;
        }
        check("rpc stub: unreachable node is a clean failure", threw);
    }

    private static void testRpcValidation() throws Exception {
        String bestHash = "0x" + "ab".repeat(32);
        String finHash = "0x" + "cd".repeat(32);

        // finalized ahead of best is impossible on a real chain:
        // the round is treated as a gap, never stored (M-02).
        RpcClient finAhead = new RpcClient(cannedTransport(request -> {
            if (request.contains("system_syncState")) {
                return resultJson("{\"currentBlock\":1000,\"highestBlock\":1000,"
                        + "\"startingBlock\":900}");
            }
            if (request.contains("chain_getBlockHash")) {
                return resultJson("\"" + bestHash + "\"");
            }
            if (request.contains("chain_getFinalizedHead")) {
                return resultJson("\"" + finHash + "\"");
            }
            if (request.contains("chain_getHeader")) {
                return resultJson("{\"number\":\"0x7d0\",\"parentHash\":\"0x00\"}");
            }
            if (request.contains("system_health")) {
                return resultJson("{\"peers\":7,\"isSyncing\":false}");
            }
            return resultJson("null");
        }));
        boolean gap = false;
        try {
            finAhead.fetchObservation();
        } catch (RpcClient.InconsistentObservation e) {
            gap = e.getMessage().contains("finalized");
        }
        check("rpc validation: finalized > best is a gap", gap);

        // Whole-round deadline: a slow-drip transport must not
        // stretch one observation round without bound.
        RpcClient slow = new RpcClient(body -> {
            try {
                Thread.sleep(150);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            return resultJson("{\"currentBlock\":1000,\"highestBlock\":1000,"
                    + "\"startingBlock\":900}").getBytes(StandardCharsets.UTF_8);
        }, 100);
        boolean deadlineHit = false;
        try {
            slow.fetchObservation();
        } catch (RpcClient.RpcException e) {
            deadlineHit = e.getMessage().contains("deadline");
        }
        check("rpc validation: round deadline enforced", deadlineHit);

        // Deadline-derived per-call timeouts (R-M02): the pure
        // budget function the HTTP transport uses. This is what
        // makes the deadline interrupt real I/O on device; the
        // socket behaviour itself cannot run in this VM (direct
        // TCP is intercepted), so the harness pins the arithmetic
        // and the post-hoc enforcement above.
        check("rpc deadline: full budget at round start",
                RpcClient.timeoutFor(0, 20_000) == 20_000);
        check("rpc deadline: remaining budget mid-round",
                RpcClient.timeoutFor(7_500, 20_000) == 12_500);
        check("rpc deadline: small remainder floored at the minimum",
                RpcClient.timeoutFor(19_900, 20_000)
                        == RpcClient.MIN_CALL_TIMEOUT_MS);
        check("rpc deadline: exhausted budget aborts",
                RpcClient.timeoutFor(20_000, 20_000) == 0
                        && RpcClient.timeoutFor(25_000, 20_000) == 0);
    }

    private static DepinCore.Observation obs(long ts, long best, Long fin) {
        DepinCore.Observation o = new DepinCore.Observation();
        o.timestampUnix = ts;
        o.bestBlockNumber = best;
        o.bestBlockHash = DepinCore.sha256(
                ("obs-" + best).getBytes(StandardCharsets.US_ASCII));
        o.observedPeers = 5;
        o.finalizedBlockNumber = fin;
        return o;
    }

    private static void testPlausibility() {
        // The R-M03 state machine, transition by transition.
        long t0 = 1762000000L;

        // First observation on an empty journal: accepted AND
        // flagged as baseline-initializing (never silent).
        ObservationPlausibility p = new ObservationPlausibility();
        ObservationPlausibility.Decision d = p.evaluate(obs(t0, 1000, 990L));
        check("plausibility: first observation accepted + flagged",
                d.accepted && d.baselineInitializing && !d.baselineReset
                        && p.hasBaseline() && p.baselineBest() == 1000);

        // Ordinary forward progress.
        d = p.evaluate(obs(t0 + 600, 1100, 1090L));
        check("plausibility: forward progress accepted",
                d.accepted && !d.baselineInitializing && !d.baselineReset);

        // Forward jump: at the per-slot limit passes, beyond fails
        // (baseline unchanged by the rejection).
        d = p.evaluate(obs(t0 + 600, 1100 + 6001, 1090L));
        check("plausibility: jump beyond the per-slot limit rejected",
                !d.accepted && p.baselineBest() == 1100);
        d = p.evaluate(obs(t0 + 600, 1100 + 6000, 1090L));
        check("plausibility: jump at the per-slot limit accepted",
                d.accepted && p.baselineBest() == 7100);

        // The limit grows with elapsed slots from the baseline.
        d = p.evaluate(obs(t0 + 600 + 1200, 7100 + 12001, 7000L));
        check("plausibility: beyond the grown limit rejected", !d.accepted);
        d = p.evaluate(obs(t0 + 600 + 1200, 7100 + 12000, 7000L));
        check("plausibility: limit grows with elapsed slots",
                d.accepted && p.baselineBest() == 19100);

        // finalized > best: rejected WITHOUT consuming the
        // regression budget.
        d = p.evaluate(obs(t0 + 2400, 19000, 19500L));
        check("plausibility: finalized > best rejected, no regression counted",
                !d.accepted && p.consecutiveRegressions() == 0
                        && p.baselineBest() == 19100);

        // Regressions: 1st and 2nd rejected, 3rd adopts the new
        // baseline (self-healing — no permanent wedge).
        d = p.evaluate(obs(t0 + 3000, 18000, 17900L));
        check("plausibility: regression 1 rejected",
                !d.accepted && p.consecutiveRegressions() == 1);
        d = p.evaluate(obs(t0 + 3600, 18000, 17900L));
        check("plausibility: regression 2 rejected",
                !d.accepted && p.consecutiveRegressions() == 2);
        d = p.evaluate(obs(t0 + 4200, 18000, 17900L));
        check("plausibility: regression 3 adopts the new baseline",
                d.accepted && d.baselineReset
                        && p.baselineBest() == 18000
                        && p.consecutiveRegressions() == 0);

        // Recovery: forward from the adopted baseline is normal,
        // and the regression counter starts over afterwards.
        d = p.evaluate(obs(t0 + 4800, 18500, 18400L));
        check("plausibility: recovery after baseline reset",
                d.accepted && !d.baselineReset && p.baselineBest() == 18500);
        d = p.evaluate(obs(t0 + 5400, 18000, 17900L));
        check("plausibility: regression counting restarts after an accept",
                !d.accepted && p.consecutiveRegressions() == 1);

        // A tracker seeded from the journal tail (R-M03 extension
        // a) applies the rules from the first round: no silent
        // baseline-initializing acceptance, jumps measured from
        // the persisted baseline.
        ObservationPlausibility seeded =
                ObservationPlausibility.seededWith(5000, t0);
        d = seeded.evaluate(obs(t0, 5000, 4990L));
        check("plausibility: seeded baseline, steady best accepted unflagged",
                d.accepted && !d.baselineInitializing);
        d = seeded.evaluate(obs(t0, 5000 + 6001, 4990L));
        check("plausibility: seeded baseline enforces the jump bound",
                !d.accepted && seeded.baselineBest() == 5000);
    }

    private static boolean hexNumberRejected(String s) {
        try {
            RpcClient.parseHexBlockNumber(s);
            return false;
        } catch (RpcClient.RpcException e) {
            return true;
        }
    }

    private static void testRpcStrictParsing() throws Exception {
        // R-M03 intake grammar, pinned at the pure-function level.
        check("rpc intake: canonical hex numbers accepted",
                RpcClient.parseHexBlockNumber("0x0") == 0L
                        && RpcClient.parseHexBlockNumber("0xff") == 255L
                        && RpcClient.parseHexBlockNumber("0xFF") == 255L
                        && RpcClient.parseHexBlockNumber("0xAb") == 171L
                        && RpcClient.parseHexBlockNumber("0x00010") == 16L
                        && RpcClient.parseHexBlockNumber("0xffffffffffff")
                                == (1L << 48) - 1);
        String[] bad = {
                "0x-1",           // the R-M03 wedge value
                "0x",             // no digits
                " 0x10", "0x10 ", // whitespace
                "0x1000000000000",// exactly 2^48
                "0xg1", "10", "", "0X10", "-0x10",
        };
        boolean allBad = true;
        for (String s : bad) {
            if (!hexNumberRejected(s)) {
                allBad = false;
                System.out.println("  (accepted but must reject: '" + s + "')");
            }
        }
        check("rpc intake: non-canonical hex numbers rejected",
                allBad && hexNumberRejected(null));

        String bestHash = "0x" + "ab".repeat(32);
        String finHash = "0x" + "cd".repeat(32);

        // "0x-1" as the finalized header number: the round fails
        // cleanly as an RpcException (nothing is stored — the
        // failure happens inside fetchObservation, before any
        // observation exists).
        RpcClient negFin = new RpcClient(cannedTransport(request -> {
            if (request.contains("system_syncState")) {
                return resultJson("{\"currentBlock\":1000,\"highestBlock\":1000,"
                        + "\"startingBlock\":900}");
            }
            if (request.contains("chain_getBlockHash")) {
                return resultJson("\"" + bestHash + "\"");
            }
            if (request.contains("chain_getFinalizedHead")) {
                return resultJson("\"" + finHash + "\"");
            }
            if (request.contains("chain_getHeader")) {
                return resultJson("{\"number\":\"0x-1\",\"parentHash\":\"0x00\"}");
            }
            if (request.contains("system_health")) {
                return resultJson("{\"peers\":7,\"isSyncing\":false}");
            }
            return resultJson("null");
        }));
        boolean cleanFailure = false;
        try {
            negFin.fetchObservation();
        } catch (RpcClient.InconsistentObservation e) {
            cleanFailure = false;
        } catch (RpcClient.RpcException e) {
            cleanFailure = true;
        }
        check("rpc intake: '0x-1' finalized fails the round cleanly", cleanFailure);

        // Peer count out of range and non-integer values fail the
        // round the same way.
        check("rpc intake: peers above the sanity bound rejected",
                roundFailsWithHealth("{\"peers\":100001,\"isSyncing\":false}",
                        bestHash, finHash));
        check("rpc intake: fractional peers rejected",
                roundFailsWithHealth("{\"peers\":7.5,\"isSyncing\":false}",
                        bestHash, finHash));
        check("rpc intake: peers at the bound accepted",
                !roundFailsWithHealth("{\"peers\":100000,\"isSyncing\":false}",
                        bestHash, finHash));

        // A JSON block number at/above 2^48 in syncState fails.
        RpcClient hugeBest = new RpcClient(cannedTransport(request -> {
            if (request.contains("system_syncState")) {
                return resultJson("{\"currentBlock\":281474976710656,"
                        + "\"highestBlock\":281474976710656,\"startingBlock\":900}");
            }
            return resultJson("null");
        }));
        boolean hugeFailed = false;
        try {
            hugeBest.fetchObservation();
        } catch (RpcClient.RpcException e) {
            hugeFailed = true;
        } catch (RpcClient.InconsistentObservation e) {
            hugeFailed = false;
        }
        check("rpc intake: best at 2^48 rejected", hugeFailed);
    }

    /** One observation round against a canned node whose
     *  system_health result is the given JSON; true when the round
     *  fails with RpcException. */
    private static boolean roundFailsWithHealth(String healthJson,
                                                String bestHash, String finHash) {
        RpcClient client = new RpcClient(cannedTransport(request -> {
            if (request.contains("system_syncState")) {
                return resultJson("{\"currentBlock\":1000,\"highestBlock\":1000,"
                        + "\"startingBlock\":900}");
            }
            if (request.contains("chain_getBlockHash")) {
                return resultJson("\"" + bestHash + "\"");
            }
            if (request.contains("chain_getFinalizedHead")) {
                return resultJson("\"" + finHash + "\"");
            }
            if (request.contains("chain_getHeader")) {
                return resultJson("{\"number\":\"0x3e0\",\"parentHash\":\"0x00\"}");
            }
            if (request.contains("system_health")) {
                return resultJson(healthJson);
            }
            return resultJson("null");
        }));
        try {
            client.fetchObservation();
            return false;
        } catch (RpcClient.RpcException e) {
            return true;
        } catch (RpcClient.InconsistentObservation e) {
            return false;
        }
    }

    // ---------------- v0.7 suites (re-audit of v0.6) ----------------

    private static boolean jsonRejected(String text) {
        try {
            Json.parse(text);
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        }
    }

    private static void testJsonStrictRaw() {
        // M-03: verdicts are made on the RAW TEXT, exactly as the
        // Python reference makes them. A parse-then-inspect test
        // cannot see these mutations — the whole point is that the
        // previous reader normalized them away.
        byte[] seed = testSeed();
        Map<String, Object> bundle = DepinCore.buildBundle(
                seed, syntheticObservations(4), 50, -1);
        String pretty = Json.pretty(bundle);

        // (1) "seq": 0 with the 0 written as U+0660 (Arabic-Indic
        // digit zero). Character.isDigit + Long.parseLong used to
        // read this as the integer 0, signature and all.
        int at = pretty.indexOf("\"seq\": 0");
        check("json strict: bundle text contains a seq field", at >= 0);
        String arabicSeq = pretty.substring(0, at) + "\"seq\": \u0660"
                + pretty.substring(at + "\"seq\": 0".length());
        check("json strict: Arabic-Indic digit in seq rejected (raw)",
                jsonRejected(arabicSeq));
        check("json strict: Arabic-Indic number rejected (direct)",
                jsonRejected("{\"seq\":\u0660}")
                        && jsonRejected("{\"a\":\u0661\u0662}"));

        // (2) A key written with a signed unicode escape: the old
        // reader's Integer.parseInt("+066", 16) decoded it to 'f'
        // and silently produced the key "format".
        check("json strict: signed unicode escape in key rejected",
                jsonRejected("{\"\\u+066ormat\":1}"));
        Map<String, Object> okKey = Json.parseObject("{\"\\u0066ormat\":1}");
        check("json strict: canonical unicode escape still parses",
                okKey.containsKey("format"));

        // (3) A raw (unescaped) control character inside a string.
        check("json strict: raw control character in string rejected",
                jsonRejected("{\"a\":\"x\ny\"}")
                        && jsonRejected("{\"a\":\"x\ty\"}"));
        check("json strict: escaped control characters still parse",
                "x\ny".equals(Json.parseObject("{\"a\":\"x\\ny\"}").get("a")));

        // (4) The untouched bundle text still parses (sanity: the
        // strictness did not reject the system's own output).
        check("json strict: own bundle text parses",
                !jsonRejected(pretty));
    }

    /** A drip-feed stream: one byte per read, a fixed delay per
     *  byte, far more bytes than any deadline could consume. */
    private static final class DripStream extends java.io.InputStream {
        private final long delayMs;
        private long remaining;
        long served = 0;

        DripStream(long totalBytes, long delayMs) {
            this.remaining = totalBytes;
            this.delayMs = delayMs;
        }

        @Override
        public int read() {
            byte[] one = new byte[1];
            int n = read(one, 0, 1);
            return n < 0 ? -1 : (one[0] & 0xFF);
        }

        @Override
        public int read(byte[] b, int off, int len) {
            if (remaining <= 0) {
                return -1;
            }
            try {
                Thread.sleep(delayMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return -1;
            }
            b[off] = 'x';
            remaining--;
            served++;
            return 1;
        }
    }

    private static void testRpcAbsoluteDeadline() throws Exception {
        // M-01: the body read must abort AT the absolute deadline
        // instead of following a drip-feed stream. (Sockets cannot
        // run in this VM; readCapped is the deadline-enforcing
        // loop the HTTP transport uses, driven here directly.)
        DripStream drip = new DripStream(100_000, 25);
        long deadline = System.nanoTime() + 400L * 1_000_000L;
        long t0 = System.nanoTime();
        boolean deadlineThrown = false;
        try {
            RpcClient.readCapped(drip, deadline, null);
        } catch (RpcClient.RpcException e) {
            deadlineThrown = e.getMessage().contains("deadline");
        }
        long elapsedMs = (System.nanoTime() - t0) / 1_000_000L;
        check("rpc deadline: drip-feed read aborts on the deadline",
                deadlineThrown);
        check("rpc deadline: abort is timely, stream not followed",
                elapsedMs < 3_000 && drip.served < 100);

        // A complete body arriving well inside the deadline is
        // returned whole.
        byte[] payload = resultJson("{\"ok\":true}")
                .getBytes(StandardCharsets.UTF_8);
        byte[] got = RpcClient.readCapped(
                new java.io.ByteArrayInputStream(payload),
                System.nanoTime() + 5_000L * 1_000_000L, null);
        check("rpc deadline: timely body returned whole",
                Arrays.equals(got, payload));

        // The size cap still applies under the deadline logic.
        byte[] big = new byte[300 * 1024];
        boolean capThrown = false;
        try {
            RpcClient.readCapped(new java.io.ByteArrayInputStream(big),
                    System.nanoTime() + 60_000L * 1_000_000L, null);
        } catch (RpcClient.RpcException e) {
            capThrown = e.getMessage().contains("exceeds");
        }
        check("rpc deadline: response size cap still enforced", capThrown);

        // A deadline already in the past aborts before any read.
        DripStream drip2 = new DripStream(10, 1);
        boolean pastThrown = false;
        try {
            RpcClient.readCapped(drip2, System.nanoTime() - 1_000_000L, null);
        } catch (RpcClient.RpcException e) {
            pastThrown = e.getMessage().contains("deadline");
        }
        check("rpc deadline: expired deadline aborts immediately",
                pastThrown && drip2.served == 0);
    }

    private static void testSegmentPolicyV08() throws Exception {
        // Advance-cap arithmetic (M-02(b), v0.8): a candidate may
        // run ahead of the RECORDED tail by at most the elapsed
        // slots × MAX_TAIL_ADVANCE_BLOCKS_PER_SLOT, with a
        // one-slot minimum allowance. Candidates at or below the
        // tail are not advances at all (the service holds
        // regressions separately).
        long cap = SegmentPolicy.MAX_TAIL_ADVANCE_BLOCKS_PER_SLOT;
        long t0 = 1762000000L;
        check("segment cap: candidate at the tail allowed",
                SegmentPolicy.tailAdvanceAllowed(350000, t0, 350000, t0));
        check("segment cap: candidate below the tail is not an advance",
                SegmentPolicy.tailAdvanceAllowed(350000, t0, 349000, t0));
        check("segment cap: one-slot advance at the bound allowed",
                SegmentPolicy.tailAdvanceAllowed(350000, t0, 350000 + cap, t0));
        check("segment cap: one-slot advance beyond the bound held",
                !SegmentPolicy.tailAdvanceAllowed(
                        350000, t0, 350000 + cap + 1, t0));
        // A4 catch-up shape: the elapsed time is measured from
        // the tail's OWN recorded timestamp, so at T + n
        // intervals a reading of H + n×A is admissible (the node
        // catching up after downtime), while H + n×A + (A+1) is
        // still held. (Allowance = n×A + A under the formula.)
        check("segment cap: at T+n intervals, H + nA is admissible (A4)",
                SegmentPolicy.tailAdvanceAllowed(
                        350000, t0, 350000 + 2 * cap, t0 + 1200));
        check("segment cap: at T+n intervals, H + nA + (A+1) is still held (A4)",
                !SegmentPolicy.tailAdvanceAllowed(
                        350000, t0, 350000 + 2 * cap + cap + 1, t0 + 1200));
        check("segment cap: spoofed 2^48 jump held at any realistic gap",
                !SegmentPolicy.tailAdvanceAllowed(
                        350000, t0, (1L << 48) - 1, t0 + 86400));

        // M-02(a) streak (unchanged in v0.8): 2 CONSECUTIVE
        // accepted readings open a fresh segment; a rejection
        // breaks the streak; reset starts it over.
        SegmentPolicy sp = new SegmentPolicy();
        check("segment: first reading does not open a segment",
                !sp.noteAcceptedWhileSegmentEmpty());
        check("segment: second consecutive reading opens it",
                sp.noteAcceptedWhileSegmentEmpty());
        check("segment: further readings keep it open",
                sp.noteAcceptedWhileSegmentEmpty());
        sp.noteRejected();
        check("segment: rejection breaks the streak",
                !sp.noteAcceptedWhileSegmentEmpty()
                        && sp.plausibleStreak() == 1);
        sp.reset();
        check("segment: reset restarts the streak",
                sp.plausibleStreak() == 0
                        && !sp.noteAcceptedWhileSegmentEmpty());

        byte[] seed = testSeed();
        byte[] pub = Ed25519.publickeyFromSeed(seed);
        String deviceId = DepinCore.deviceIdFromPubkey(pub);

        // Fake-low RPC against a GENUINE recorded tail — the
        // v0.7 re-audit's M-02 attack, inverted: best=1 three
        // times heals the baseline down to 1. Under v0.7 the
        // service then PRESERVED the genuine segment out of the
        // live journal. Under v0.8 nothing destructive may
        // happen: the tail stays byte-exact, no segment or
        // quarantine file appears, appends are held, and the
        // hold persists across a store reopen (a restart).
        File dir = new File(System.getProperty("java.io.tmpdir"),
                "depin-segment-fakelow-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        File file = new File(dir, "journal.json");
        JournalStore j = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        List<DepinCore.Observation> genuine = syntheticObservations(3);
        for (int i = 0; i < 3; i++) {
            j.append(DepinCore.makeCheckpoint(i, genuine.get(i),
                    j.nextPrevState(), j.nextPrevCheckpointHash(), 50, pub));
        }
        // Genuine recorded tail: best 350200 at t0+1200.
        byte[] genuineBytes = java.nio.file.Files.readAllBytes(file.toPath());
        ObservationPlausibility healed =
                ObservationPlausibility.seededWith(350200, t0 + 1200L);
        healed.evaluate(obs(t0 + 1800L, 1, null));
        healed.evaluate(obs(t0 + 2400L, 1, null));
        ObservationPlausibility.Decision third =
                healed.evaluate(obs(t0 + 3000L, 1, null));
        check("segment v0.8: fake-low view heals the baseline (precondition)",
                third.accepted && third.baselineReset
                        && healed.baselineBest() == 1);
        // The service's v0.8 response to the disagreement: hold
        // and persist — touch nothing else.
        j.setHold(1, t0 + 3000L);
        check("segment v0.8: fake-low view leaves the recorded tail untouched",
                j.count() == 3 && j.last().bestBlockNumber == 350200
                        && Arrays.equals(
                                java.nio.file.Files.readAllBytes(file.toPath()),
                                genuineBytes));
        boolean anySegmentOrQuarantine = false;
        String[] dirNames = dir.list();
        if (dirNames != null) {
            for (String n : dirNames) {
                if (n.startsWith("journal-segment-")
                        || n.startsWith("journal-corrupt-")) {
                    anySegmentOrQuarantine = true;
                }
            }
        }
        check("segment v0.8: no segment preserved, nothing quarantined",
                !anySegmentOrQuarantine && !j.recoveryOccurred());
        JournalStore.HoldInfo hold = j.holdInfo();
        check("segment v0.8: hold recorded against the genuine tail",
                hold != null && hold.tailBest == 350200
                        && hold.liveBest == 1
                        && hold.sinceUnix == t0 + 3000L);
        JournalStore reopened = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("segment v0.8: hold survives a store reopen (restart)",
                reopened.holdInfo() != null
                        && reopened.holdInfo().tailBest == 350200
                        && reopened.holdInfo().liveBest == 1
                        && reopened.count() == 3
                        && reopened.droppedOnLoad() == 0);

        // The real view returns: a reading back at the tail is
        // inside the advance cap, the append lands, and clearing
        // the hold removes the persisted notice.
        DepinCore.Observation back = obs(t0 + 3600L, 350250, 350240L);
        check("segment v0.8: returning view is inside the advance cap",
                SegmentPolicy.tailAdvanceAllowed(
                        350200, t0 + 1200L, 350250, t0 + 3600L));
        reopened.append(DepinCore.makeCheckpoint(3, back,
                reopened.nextPrevState(), reopened.nextPrevCheckpointHash(), 50, pub));
        reopened.clearHold();
        JournalStore resumed = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("segment v0.8: accumulation resumes and the hold is gone",
                resumed.count() == 4 && resumed.holdInfo() == null
                        && resumed.droppedOnLoad() == 0);

        // Fake-high jump mid-segment: a reading that runs past
        // the advance cap is held at the tail, not recorded —
        // while honest next-slot progress stays inside the cap.
        check("segment v0.8: fake-high jump mid-segment exceeds the cap",
                !SegmentPolicy.tailAdvanceAllowed(
                        350250, t0 + 3600L, (1L << 48) - 1, t0 + 4200L));
        check("segment v0.8: honest next-slot progress stays inside the cap",
                SegmentPolicy.tailAdvanceAllowed(
                        350250, t0 + 3600L, 350250 + 100, t0 + 4200L));

        // Small regression (100 blocks): the baseline heals and
        // the journal simply stays put — under v0.8 there is no
        // destructive trigger at ANY gap size; the ordinary hold
        // is the whole response (its wiring is the service's).
        File dir2 = new File(System.getProperty("java.io.tmpdir"),
                "depin-segment-small-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dir2.mkdirs();
        File file2 = new File(dir2, "journal.json");
        JournalStore j2 = JournalStore.forFile(file2, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        for (int i = 0; i < 2; i++) {
            DepinCore.Observation o = obs(t0 + i * 600L, 5000 + i * 100,
                    4990L + i * 100);
            j2.append(DepinCore.makeCheckpoint(i, o,
                    j2.nextPrevState(), j2.nextPrevCheckpointHash(), 50, pub));
        }
        ObservationPlausibility healed2 =
                ObservationPlausibility.seededWith(5100, t0 + 600L);
        healed2.evaluate(obs(t0 + 1200L, 5000, 4990L));
        healed2.evaluate(obs(t0 + 1800L, 5000, 4990L));
        ObservationPlausibility.Decision third2 =
                healed2.evaluate(obs(t0 + 2400L, 5000, 4990L));
        check("segment: small regression heals the baseline",
                third2.accepted && third2.baselineReset
                        && healed2.baselineBest() == 5000);
        check("segment v0.8: small regression leaves the journal in place",
                j2.count() == 2 && !j2.recoveryOccurred());
    }

    private static void testRpcHeaderDeadline() throws Exception {
        // M-01 header phase (v0.8, design review amendment): the
        // response-code wait itself is under the absolute
        // deadline, enforced DURING the read — not merely checked
        // after the headers complete. Sockets cannot run in this
        // VM, so the header wait is modelled the way the
        // transport performs it: a blocking read of header bytes
        // from a drip-feed stream (which never produces a header
        // terminator), run through RpcClient.runWithDeadline
        // with the abort action standing in for disconnect().
        // The drip interval (300 ms) sits just UNDER the 400 ms
        // deadline: every individual read completes comfortably
        // inside any per-read wait, so a design that only
        // re-arms a gap timeout per read — or checks the deadline
        // after completion — would follow the drip indefinitely.
        // The cut must come from the deadline itself, mid-read
        // (the 19-seconds-against-20 case, scaled down).
        DripStream drip = new DripStream(100_000, 300);
        java.util.concurrent.atomic.AtomicBoolean aborted =
                new java.util.concurrent.atomic.AtomicBoolean(false);
        long deadline = System.nanoTime() + 400L * 1_000_000L;
        long t0 = System.nanoTime();
        boolean deadlineThrown = false;
        try {
            Integer ignored = RpcClient.runWithDeadline(() -> {
                int b;
                int seen = 0;
                while ((b = drip.read()) >= 0) {
                    if (++seen > 8192) {
                        return 200; // headers complete (never happens)
                    }
                }
                throw new java.io.IOException("eof before headers complete");
            }, deadline, () -> aborted.set(true), "testHeader");
        } catch (RpcClient.RpcException e) {
            deadlineThrown = e.getMessage() != null
                    && e.getMessage().contains("deadline");
        }
        long elapsedMs = (System.nanoTime() - t0) / 1_000_000L;
        check("rpc header deadline: dripping headers abort at the deadline",
                deadlineThrown && aborted.get());
        check("rpc header deadline: abort is timely, stream not followed",
                elapsedMs < 3_000 && drip.served <= 2);

        // A call completing inside the deadline returns its value
        // and never touches the abort action.
        java.util.concurrent.atomic.AtomicBoolean aborted2 =
                new java.util.concurrent.atomic.AtomicBoolean(false);
        Integer code = RpcClient.runWithDeadline(() -> 200,
                System.nanoTime() + 5_000L * 1_000_000L,
                () -> aborted2.set(true), "testHeader");
        check("rpc header deadline: timely call returns its value",
                code == 200 && !aborted2.get());
    }

    private static void testJournalAppendRetry() throws Exception {
        // M-03: appends write from a known-good tail offset.
        byte[] seed = testSeed();
        byte[] pub = Ed25519.publickeyFromSeed(seed);
        String deviceId = DepinCore.deviceIdFromPubkey(pub);
        List<DepinCore.Observation> obs = syntheticObservations(6);
        long t0 = 1762000000L;

        // (a) Partial remnant past the synced tail: bytes of an
        // append that died between write and sync sit at the end
        // of the file while the entry never entered the chain.
        // The SAME store instance must cut them back before its
        // next append — not glue onto them — and every valid
        // entry must survive, with the load-time repair never
        // even seeing the remnant.
        File dir = new File(System.getProperty("java.io.tmpdir"),
                "depin-append-retry-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        File file = new File(dir, "journal.json");
        JournalStore j = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        for (int i = 0; i < 2; i++) {
            j.append(DepinCore.makeCheckpoint(i, obs.get(i),
                    j.nextPrevState(), j.nextPrevCheckpointHash(), 50, pub));
        }
        long goodLen = file.length();
        try (java.io.FileOutputStream raw =
                     new java.io.FileOutputStream(file, true)) {
            raw.write("{\"seq\":2,\"checkpoint_ha"
                    .getBytes(StandardCharsets.UTF_8));
            raw.getFD().sync();
        }
        check("journal retry: remnant present past the synced tail",
                file.length() > goodLen);
        j.append(DepinCore.makeCheckpoint(2, obs.get(2),
                j.nextPrevState(), j.nextPrevCheckpointHash(), 50, pub));
        JournalStore reloaded = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("journal retry: remnant cut in-process, all valid entries survive",
                reloaded.count() == 3 && reloaded.droppedOnLoad() == 0
                        && reloaded.partialTailDropped() == 0
                        && reloaded.last().bestBlockNumber
                                == obs.get(2).bestBlockNumber);

        // (b) Sync failure: the line is fully written but fsync
        // throws. The append fails loudly, the in-memory state is
        // rebuilt from the disk truth (the entry IS on disk, so
        // it stays — exactly once), and the chain continues with
        // no duplicate and no drop.
        File dir2 = new File(System.getProperty("java.io.tmpdir"),
                "depin-append-syncfail-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dir2.mkdirs();
        File file2 = new File(dir2, "journal.json");
        JournalStore j2 = JournalStore.forFile(file2, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        j2.append(DepinCore.makeCheckpoint(0, obs.get(0),
                j2.nextPrevState(), j2.nextPrevCheckpointHash(), 50, pub));
        java.util.concurrent.atomic.AtomicInteger syncCalls =
                new java.util.concurrent.atomic.AtomicInteger(0);
        j2.setFsyncForTest(out -> {
            if (syncCalls.incrementAndGet() == 1) {
                throw new java.io.IOException("simulated fsync failure");
            }
            out.getFD().sync();
        });
        boolean appendThrew = false;
        try {
            j2.append(DepinCore.makeCheckpoint(1, obs.get(1),
                    j2.nextPrevState(), j2.nextPrevCheckpointHash(), 50, pub));
        } catch (IllegalStateException e) {
            appendThrew = true;
        }
        check("journal sync failure: the append fails loudly", appendThrew);
        check("journal sync failure: state rebuilt from disk, entry kept once",
                j2.count() == 2
                        && j2.last().bestBlockNumber
                                == obs.get(1).bestBlockNumber);
        j2.append(DepinCore.makeCheckpoint(2, obs.get(2),
                j2.nextPrevState(), j2.nextPrevCheckpointHash(), 50, pub));
        JournalStore reloaded2 = JournalStore.forFile(file2, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("journal sync failure: chain continues cleanly afterwards",
                reloaded2.count() == 3 && reloaded2.droppedOnLoad() == 0);
        j2.setFsyncForTest(null);

        // (c) M-04 store-level defence: a checkpoint whose best
        // is below the recorded tail is refused even when its
        // chain link and timestamp are well-formed.
        DepinCore.Observation low = obs(t0 + 5400L,
                obs.get(2).bestBlockNumber - 1, 350190L);
        boolean refused = false;
        try {
            reloaded2.append(DepinCore.makeCheckpoint(3, low,
                    reloaded2.nextPrevState(),
                    reloaded2.nextPrevCheckpointHash(), 50, pub));
        } catch (IllegalStateException e) {
            refused = e.getMessage() != null
                    && e.getMessage().contains("regresses");
        }
        check("journal monotonicity: best below the recorded tail refused",
                refused && reloaded2.count() == 3);
    }

    private static void testServiceGeneration() {
        // M-04 logic: a captured generation is current until a
        // stop is requested or a new generation begins; both
        // retire every previously captured generation, and the
        // stop flag latches until the next begin.
        ServiceGeneration g = new ServiceGeneration();
        long gen = g.capture();
        check("generation: captured generation is current",
                g.isCurrent(gen));
        g.requestStop();
        check("generation: stop request retires the captured generation",
                !g.isCurrent(gen));
        check("generation: stop latches — post-stop captures are not current",
                !g.isCurrent(g.capture()));
        g.beginNewGeneration();
        long gen2 = g.capture();
        check("generation: restarted generation is current, old stays stale",
                g.isCurrent(gen2) && !g.isCurrent(gen));
        g.beginNewGeneration();
        check("generation: a further restart retires the previous generation",
                !g.isCurrent(gen2) && g.isCurrent(g.capture()));
    }

    private static void testJournalArchiveHeaderL03() throws Exception {
        // L-03: an archive whose header names the right device
        // but carries NO pubkey. Before v0.8 the header was never
        // verified on the write path and migration appended
        // genuine entries under it. Now the archive is
        // quarantined FIRST — the genuine entries never touch
        // it — and the migration proceeds into a fresh archive
        // under a verified header.
        byte[] seed = testSeed();
        byte[] pub = Ed25519.publickeyFromSeed(seed);
        String deviceId = DepinCore.deviceIdFromPubkey(pub);
        List<DepinCore.Observation> obs = syntheticObservations(6);

        File dir = new File(System.getProperty("java.io.tmpdir"),
                "depin-archive-l03-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        File archive = new File(dir, JournalStore.ARCHIVE_V04_FILE_NAME);
        String badHeader = "{\"type\":\"header\",\"format\":\"quantus-depin-journal\","
                + "\"version\":\"0.4\",\"device_id\":\"" + deviceId + "\"}";
        byte[] badBytes = (badHeader + "\n").getBytes(StandardCharsets.UTF_8);
        java.nio.file.Files.write(archive.toPath(), badBytes);
        File live = new File(dir, "journal.json");
        List<DepinCore.Checkpoint> v04 =
                profileCheckpoints(DepinCore.FMT_V04, obs, 2, pub);
        writeJsonlJournal(live, v04, "0.4", deviceId, pub, seed);
        JournalStore store = JournalStore.forFile(live, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        File quarantined = null;
        for (File q : store.quarantinedFiles()) {
            if (q.getName().startsWith(
                    JournalStore.ARCHIVE_V04_FILE_NAME + ".corrupt-")) {
                quarantined = q;
            }
        }
        check("archive L-03: pubkey-less header archive is quarantined",
                quarantined != null && store.archiveRecoveryOccurred());
        check("archive L-03: quarantined bytes exact — nothing migrated into it",
                quarantined != null && Arrays.equals(
                        java.nio.file.Files.readAllBytes(quarantined.toPath()),
                        badBytes));
        check("archive L-03: migration proceeds into a fresh archive",
                store.archivedV04Count() == 2);
        String freshText = new String(
                java.nio.file.Files.readAllBytes(archive.toPath()),
                StandardCharsets.UTF_8);
        check("archive L-03: fresh archive header carries device_id and pubkey",
                freshText.contains("\"device_id\":\"" + deviceId + "\"")
                        && freshText.contains(
                                "\"pubkey\":\"" + Hex.encode(pub) + "\""));

        // Variant: a header with a WRONG pubkey gets the same
        // treatment (this one exercises the write-path gate in
        // appendToArchive when the damage appears after the
        // construction sweep would have run — same dir, second
        // store, archive re-damaged between the two).
        byte[] seed2 = new byte[32];
        Arrays.fill(seed2, (byte) 0x5A);
        byte[] pub2 = Ed25519.publickeyFromSeed(seed2);
        String wrongHeader = "{\"type\":\"header\",\"format\":\"quantus-depin-journal\","
                + "\"version\":\"0.4\",\"device_id\":\"" + deviceId
                + "\",\"pubkey\":\"" + Hex.encode(pub2) + "\"}";
        byte[] wrongBytes = (wrongHeader + "\n").getBytes(StandardCharsets.UTF_8);
        java.nio.file.Files.write(archive.toPath(), wrongBytes);
        File live2 = new File(dir, "journal-b.json");
        writeJsonlJournal(live2, v04, "0.4", deviceId, pub, seed);
        JournalStore store2 = JournalStore.forFile(live2, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        File quarantined2 = null;
        for (File q : store2.quarantinedFiles()) {
            if (q.getName().startsWith(
                    JournalStore.ARCHIVE_V04_FILE_NAME + ".corrupt-")) {
                quarantined2 = q;
            }
        }
        check("archive L-03: wrong-pubkey header archive is quarantined",
                quarantined2 != null && Arrays.equals(
                        java.nio.file.Files.readAllBytes(quarantined2.toPath()),
                        wrongBytes));
        check("archive L-03: second migration also lands in a verified archive",
                store2.archivedV04Count() == 2);
    }

    private static void testJournalHeaderNoNewline() throws Exception {
        // M-04 regression: a file containing EXACTLY one complete
        // valid header JSON with no trailing newline. The old load
        // validated the header (headerWritten=true) and then let
        // the partial-tail truncation empty the file; the next
        // append glued entries onto the headerless file and the
        // load after that quarantined the whole, valid, history.
        byte[] seed = testSeed();
        byte[] pub = Ed25519.publickeyFromSeed(seed);
        String deviceId = DepinCore.deviceIdFromPubkey(pub);
        List<DepinCore.Observation> obs = syntheticObservations(3);
        File dir = new File(System.getProperty("java.io.tmpdir"),
                "depin-journal-m04-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        File file = new File(dir, "journal.json");
        JournalStore j = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        j.bindIdentity(deviceId, Hex.encode(pub)); // writes header + newline
        byte[] withNewline = java.nio.file.Files.readAllBytes(file.toPath());
        check("m04: setup wrote a newline-terminated header",
                withNewline.length > 1
                        && withNewline[withNewline.length - 1] == (byte) '\n');
        java.nio.file.Files.write(file.toPath(),
                Arrays.copyOf(withNewline, withNewline.length - 1));

        JournalStore loaded = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("m04: header-only file without newline loads fresh, no quarantine",
                loaded.count() == 0 && !loaded.recoveryOccurred()
                        && loaded.quarantinedFile() == null);
        loaded.append(DepinCore.makeCheckpoint(0, obs.get(0),
                loaded.nextPrevState(), loaded.nextPrevCheckpointHash(), 50, pub));
        JournalStore reloaded = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("m04: checkpoint appended after recovery survives reload",
                reloaded.count() == 1 && reloaded.droppedOnLoad() == 0
                        && !reloaded.recoveryOccurred());
        boolean anyQuarantine = false;
        String[] names = dir.list();
        if (names != null) {
            for (String n : names) {
                if (n.startsWith("journal-corrupt-")) anyQuarantine = true;
            }
        }
        check("m04: nothing was ever quarantined", !anyQuarantine);
    }

    private static void testJournalVerifiedArchive() throws Exception {
        // M-05: a fake archive — a proper header line plus a bare
        // {"checkpoint_hash": H} line — must NOT make migration
        // skip the genuine record H. Only fully verifying archive
        // entries count as preserved.
        byte[] seed = testSeed();
        byte[] pub = Ed25519.publickeyFromSeed(seed);
        String deviceId = DepinCore.deviceIdFromPubkey(pub);
        List<DepinCore.Observation> obs = syntheticObservations(6);
        List<DepinCore.Checkpoint> v04Cps =
                profileCheckpoints(DepinCore.FMT_V04, obs, 1, pub);
        DepinCore.Checkpoint genuine = v04Cps.get(0);
        String hashH = Hex.encode(genuine.checkpointHash);

        File dir = new File(System.getProperty("java.io.tmpdir"),
                "depin-journal-m05-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        // The fake archive, in place BEFORE the store opens (so
        // the constructor's archive-header check sees it too: its
        // header is well-formed and names this device, so it is
        // NOT quarantined — only its claim is worthless).
        File archive = new File(dir, JournalStore.ARCHIVE_V04_FILE_NAME);
        Map<String, Object> fakeHeader = new java.util.LinkedHashMap<>();
        fakeHeader.put("type", "header");
        fakeHeader.put("format", "quantus-depin-journal");
        fakeHeader.put("version", "0.4");
        fakeHeader.put("device_id", deviceId);
        fakeHeader.put("pubkey", Hex.encode(pub));
        String fakeText = Json.canonical(fakeHeader) + "\n"
                + "{\"checkpoint_hash\":\"" + hashH + "\"}\n";
        java.nio.file.Files.write(archive.toPath(),
                fakeText.getBytes(StandardCharsets.UTF_8));

        File live = new File(dir, "journal.json");
        writeJsonlJournal(live, v04Cps, "0.4", deviceId, pub, seed);
        JournalStore store = JournalStore.forFile(live, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("m05: live v0.4 journal migrated (live empty)",
                store.count() == 0 && store.archivedOnLoadV04() == 1);

        // The genuine record must SURVIVE in the archive as a
        // fully verifying entry — not be skipped on the bare
        // hash line's say-so.
        String archiveText = new String(
                java.nio.file.Files.readAllBytes(archive.toPath()),
                StandardCharsets.UTF_8);
        int fullEntriesForH = 0;
        boolean bareLineStillThere = false;
        for (String line : archiveText.split("\n")) {
            line = line.trim();
            if (line.isEmpty()) continue;
            if (line.equals("{\"checkpoint_hash\":\"" + hashH + "\"}")) {
                bareLineStillThere = true;
                continue;
            }
            Map<String, Object> e;
            try {
                e = Json.parseObject(line);
            } catch (RuntimeException ex) {
                continue;
            }
            Object sigObj = e.remove("entry_sig");
            if (!(sigObj instanceof String)) continue;
            DepinCore.Checkpoint cp;
            try {
                cp = DepinCore.Checkpoint.fromMap(e);
            } catch (RuntimeException ex) {
                continue;
            }
            if (!hashH.equals(Hex.encode(cp.checkpointHash))) continue;
            byte[] sig = Hex.decodeCanonical((String) sigObj);
            if (Arrays.equals(DepinCore.checkpointHashV04(cp), cp.checkpointHash)
                    && DepinCore.verifyJournalEntrySig(
                            pub, cp.checkpointHash, cp.seq, sig)) {
                fullEntriesForH++;
            }
        }
        check("m05: fake archive did not suppress the genuine record",
                fullEntriesForH == 1);
        check("m05: the bare fake line was left untouched (append-only)",
                bareLineStillThere);

        // And the verified-presence path still dedups: migrating
        // the same checkpoint again (a second live journal in the
        // same directory) must NOT duplicate the now-genuine
        // archive entry.
        File live2 = new File(dir, "journal-b.json");
        writeJsonlJournal(live2, v04Cps, "0.4", deviceId, pub, seed);
        JournalStore store2 = JournalStore.forFile(live2, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        String archiveText2 = new String(
                java.nio.file.Files.readAllBytes(archive.toPath()),
                StandardCharsets.UTF_8);
        int fullEntriesAfter = 0;
        for (String line : archiveText2.split("\n")) {
            if (line.contains("\"entry_sig\"")
                    && line.contains("\"checkpoint_hash\":\"" + hashH + "\"")) {
                fullEntriesAfter++;
            }
        }
        check("m05: verified presence still dedups genuine archives",
                store2.archivedOnLoadV04() == 1 && fullEntriesAfter == 1);
    }

    private static void testJournalDeepNesting() throws Exception {
        // M-06: a header carrying a 10,000-deep nested array in
        // an unknown field must be quarantined — not drive the
        // recursive parser into a StackOverflowError that escapes
        // load() and wedges every future launch.
        check("json depth: nesting beyond the cap is a parse failure",
                jsonRejected("[".repeat(100) + "]".repeat(100)));
        check("json depth: ordinary nesting still parses",
                !jsonRejected("{\"a\":{\"z\":[1,2,{\"k\":\"v\"}]}}"));

        byte[] seed = testSeed();
        byte[] pub = Ed25519.publickeyFromSeed(seed);
        String deviceId = DepinCore.deviceIdFromPubkey(pub);
        List<DepinCore.Observation> obs = syntheticObservations(3);
        File dir = new File(System.getProperty("java.io.tmpdir"),
                "depin-journal-m06-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        File file = new File(dir, "journal.json");
        byte[] valid = buildValidJournal(file, 1, seed, pub, deviceId, obs);
        String text = new String(valid, StandardCharsets.UTF_8);
        int nl = text.indexOf('\n');
        String headerLine = text.substring(0, nl);
        String rest = text.substring(nl);
        String deepHeader = headerLine.substring(0, headerLine.length() - 1)
                + ",\"x\":" + "[".repeat(10_000) + "]".repeat(10_000) + "}";
        byte[] damaged = (deepHeader + rest).getBytes(StandardCharsets.UTF_8);
        java.nio.file.Files.write(file.toPath(), damaged);

        JournalStore s = null;
        Throwable escaped = null;
        try {
            s = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        } catch (Throwable t) {
            escaped = t;
        }
        check("m06: deep-nested header does not escape load",
                escaped == null && s != null);
        check("m06: deep-nested header is quarantined, fresh journal starts",
                s != null && s.recoveryOccurred() && s.count() == 0
                        && s.quarantinedFile() != null
                        && Arrays.equals(java.nio.file.Files.readAllBytes(
                                s.quarantinedFile().toPath()), damaged));
        if (s != null) {
            s.append(DepinCore.makeCheckpoint(0, obs.get(0),
                    s.nextPrevState(), s.nextPrevCheckpointHash(), 50, pub));
            JournalStore reopened = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
            check("m06: journal usable after deep-nesting recovery",
                    reopened.count() == 1 && !reopened.recoveryOccurred());
        }
    }

    // ---------------- v0.9 suites (fifth review of v0.8) ----------------

    private static void testJsonDuplicateKeys() {
        // F-06: the Java parser accepted duplicate keys in one
        // object (last value wins) where the Python reference
        // rejects the text outright, so the two implementations
        // disagreed on the same signed bytes. SPEC section 8 and
        // the v0.8 round's own account both say the Android-side
        // parser rejects duplicates; now it does.
        check("dup keys: plain duplicate rejected",
                jsonRejected("{\"a\":1,\"a\":2}"));
        check("dup keys: duplicate via unicode escape rejected",
                jsonRejected("{\"a\":1,\"\\u0061\":2}"));
        check("dup keys: nested duplicate rejected",
                jsonRejected("{\"outer\":{\"x\":1,\"x\":2}}"));
        check("dup keys: duplicate inside an array element rejected",
                jsonRejected("[{\"k\":1,\"k\":1}]"));
        check("dup keys: distinct keys still parse",
                Json.parseObject("{\"a\":1,\"b\":2}").size() == 2);

        // The audit's exact mutation: a signed bundle whose first
        // checkpoint gains a shadowing "seq": 99 in front of the
        // genuine "seq": 0. Last-wins parsing read it as seq 0
        // and Java verified the bundle; Python rejected the text.
        byte[] seed = testSeed();
        Map<String, Object> bundle = DepinCore.buildBundle(
                seed, syntheticObservations(4), 50, -1);
        String pretty = Json.pretty(bundle);
        int at = pretty.indexOf("\"seq\": 0");
        check("dup keys: bundle text contains a seq field", at >= 0);
        String dup = pretty.substring(0, at) + "\"seq\": 99, \"seq\": 0"
                + pretty.substring(at + "\"seq\": 0".length());
        check("dup keys: audit mutation of a signed bundle rejected (raw)",
                jsonRejected(dup));
        check("dup keys: untouched bundle text still parses",
                !jsonRejected(pretty));
    }

    private static void testObservedPeersU32() {
        // F-07: observed_peers is a u32 on the wire, but Checkpoint
        // stored it in a signed int: 2^31 and above became negative
        // in fromMap, and toMap then re-serialized a value the
        // schema itself rejects — a valid bundle could not survive
        // a Java parse/serialize round trip (Java rejected its own
        // output). The field is a long now; the full u32 range
        // round-trips exactly.
        byte[] seed = testSeed();
        byte[] pub = Ed25519.publickeyFromSeed(seed);
        DepinCore.Observation o = syntheticObservations(1).get(0);
        DepinCore.Checkpoint base = DepinCore.makeCheckpoint(
                0, o, DepinCore.ZERO32, DepinCore.ZERO32, 50, pub);

        long[] probes = {2147483648L, 4294967295L}; // 2^31, 2^32-1
        for (long probe : probes) {
            Map<String, Object> m = base.toMap();
            m.put("observed_peers", probe);
            DepinCore.Checkpoint wide = DepinCore.Checkpoint.fromMap(m);
            // checkpointHash covers observed_peers: recompute it
            // for the probed value. (The sequential chain is not
            // what this finding is about, so the bundle checks
            // below run at hash level, recomputeChain=false —
            // the same level as the app's export self-check.)
            wide.checkpointHash =
                    DepinCore.checkpointHash(DepinCore.CURRENT, wide);
            Object roundTripped = null;
            boolean roundTripOk = true;
            try {
                roundTripped = DepinCore.Checkpoint.fromMap(wide.toMap())
                        .toMap().get("observed_peers");
            } catch (RuntimeException e) {
                roundTripOk = false;
            }
            check("peers u32: " + probe + " survives fromMap -> toMap unchanged",
                    roundTripOk && Long.valueOf(probe).equals(roundTripped));
            Map<String, Object> bundle = DepinCore.assembleBundle(
                    seed, java.util.Collections.singletonList(wide),
                    1762000000L, 50);
            check("peers u32: bundle carrying " + probe + " verifies",
                    DepinCore.verifyBundle(bundle, 50, false).isEmpty());
            Map<String, Object> reparsed =
                    Json.parseObject(Json.canonical(bundle));
            check("peers u32: canonical text round trip stays valid ("
                            + probe + ")",
                    DepinCore.verifyBundle(reparsed, 50, false).isEmpty());
        }

        // Just above the u32 range the schema still refuses.
        Map<String, Object> over = base.toMap();
        over.put("observed_peers", 4294967296L);
        boolean aboveRejected = false;
        try {
            DepinCore.Checkpoint.fromMap(over);
        } catch (IllegalArgumentException e) {
            aboveRejected = true;
        }
        check("peers u32: 2^32 still rejected", aboveRejected);
    }

    private static void testArchiveHeaderRepairF04() throws Exception {
        // F-04: an archive holding ONLY a valid header line whose
        // trailing newline is missing (the remnant of an
        // interrupted earlier write). appendToArchive recorded
        // hasHeader from the PRE-repair file, then
        // truncatePartialTail emptied the file — it holds no
        // newline to cut back to — so the migrated entry landed
        // headerless and the NEXT load's sweep quarantined the
        // archive as header-damaged: the migrated history
        // vanished from the normal path (bytes preserved in the
        // quarantine file, recoverable only by hand).
        byte[] seed = testSeed();
        byte[] pub = Ed25519.publickeyFromSeed(seed);
        String deviceId = DepinCore.deviceIdFromPubkey(pub);
        List<DepinCore.Observation> obs = syntheticObservations(4);
        List<DepinCore.Checkpoint> v04Cps =
                profileCheckpoints(DepinCore.FMT_V04, obs, 1, pub);

        File dir = new File(System.getProperty("java.io.tmpdir"),
                "depin-archive-f04-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        File file = new File(dir, "journal.json");
        writeJsonlJournal(file, v04Cps, "0.4", deviceId, pub, seed);
        Map<String, Object> ahdr = new java.util.LinkedHashMap<>();
        ahdr.put("type", "header");
        ahdr.put("format", "quantus-depin-journal");
        ahdr.put("version", "0.4");
        ahdr.put("device_id", deviceId);
        ahdr.put("pubkey", Hex.encode(pub));
        File archive = new File(dir, JournalStore.ARCHIVE_V04_FILE_NAME);
        // Valid header bytes, trailing newline missing — nothing else.
        java.nio.file.Files.write(archive.toPath(),
                Json.canonical(ahdr).getBytes(StandardCharsets.UTF_8));

        JournalStore store = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("f04: migration archived the v0.4 entry",
                store.archivedV04Count() == 1 && store.count() == 0
                        && store.archivedOnLoadV04() == 1);
        String archiveText = new String(
                java.nio.file.Files.readAllBytes(archive.toPath()),
                StandardCharsets.UTF_8);
        String[] lines = archiveText.split("\n");
        Map<String, Object> first = null;
        try {
            first = Json.parseObject(lines[0].trim());
        } catch (RuntimeException ignored) {
            // first stays null: the header is not there.
        }
        check("f04: archive begins with its header after repair + migration",
                first != null && "header".equals(first.get("type"))
                        && "0.4".equals(first.get("version"))
                        && lines.length == 2);
        // The restart is where the history used to vanish: the
        // headerless archive read as header-damaged and was
        // quarantined, taking the preserved count to 0.
        JournalStore reopened = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("f04: archived history survives a restart on the normal path",
                reopened.archivedV04Count() == 1
                        && !reopened.archiveRecoveryOccurred()
                        && reopened.droppedOnLoad() == 0);

        // Control: a fully terminated archive (header + one
        // entry) takes a further migrated entry and stays
        // well-formed — re-deriving the header state after the
        // repair must not disturb the ordinary path.
        File dir2 = new File(System.getProperty("java.io.tmpdir"),
                "depin-archive-f04ctl-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dir2.mkdirs();
        File file2 = new File(dir2, "journal.json");
        List<DepinCore.Checkpoint> otherHead =
                profileCheckpoints(DepinCore.FMT_V04,
                        java.util.Collections.singletonList(obs.get(1)), 1, pub);
        writeJsonlJournal(file2, otherHead, "0.4", deviceId, pub, seed);
        File archive2 = new File(dir2, JournalStore.ARCHIVE_V04_FILE_NAME);
        StringBuilder ab = new StringBuilder();
        ab.append(Json.canonical(ahdr)).append('\n');
        Map<String, Object> e0 = v04Cps.get(0).toMap();
        e0.put("entry_sig", Hex.encode(DepinCore.journalEntrySig(
                seed, v04Cps.get(0).checkpointHash, v04Cps.get(0).seq)));
        ab.append(Json.canonical(e0)).append('\n');
        java.nio.file.Files.write(archive2.toPath(),
                ab.toString().getBytes(StandardCharsets.UTF_8));
        JournalStore store2 = JournalStore.forFile(file2, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        JournalStore reopened2 = JournalStore.forFile(file2, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));
        check("f04: terminated archive keeps its header and both entries",
                store2.archivedV04Count() == 2
                        && reopened2.archivedV04Count() == 2
                        && !reopened2.archiveRecoveryOccurred());
    }

    private static void testJournalCheckpointCap() throws Exception {
        // F-05: the write side had NO checkpoint-count cap —
        // append happily wrote seq == MAX_CHECKPOINTS + 1 — while
        // the reload path (Checkpoint.fromMap) accepts seq only
        // up to MAX_CHECKPOINTS. A record at the seam was written,
        // dropped on the next load, and deleted from disk by the
        // post-drop rewrite: stored history lost, unlike the
        // disclosed export refusal. (At the 600 s cadence the
        // boundary is ~3.8 years out.) One constant now governs
        // both sides: append refuses seq > MAX_CHECKPOINTS — the
        // largest seq fromMap accepts — so anything append ever
        // wrote reloads losslessly, and the refusal surfaces
        // instead of the loss.
        //
        // The boundary is driven directly, as the audit drove
        // it: a journal filled to seq MAX-1 on disk, then the two
        // boundary appends through the store. Entry signatures
        // are stubbed via the store's EntrySigner/EntryVerifier
        // seams (the cap arithmetic is what is pinned, not the
        // cryptography); checkpoint hashes and linkage are real,
        // and the fsync seam is neutralized for speed.
        byte[] seed = testSeed();
        byte[] pub = Ed25519.publickeyFromSeed(seed);
        String deviceId = DepinCore.deviceIdFromPubkey(pub);
        JournalStore.EntrySigner dummySigner = (h, s) -> new byte[64];
        JournalStore.EntryVerifier dummyVerifier = (h, s, sig) -> true;
        final int max = DepinCore.MAX_CHECKPOINTS;
        final long baseTs = 1762000000L;

        File dir = new File(System.getProperty("java.io.tmpdir"),
                "depin-journal-cap-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        File file = new File(dir, "journal.json");
        DepinCore.Checkpoint tail;
        try (java.io.BufferedWriter w = new java.io.BufferedWriter(
                new java.io.OutputStreamWriter(
                        new java.io.FileOutputStream(file),
                        StandardCharsets.UTF_8), 1 << 16)) {
            Map<String, Object> hdr = new java.util.LinkedHashMap<>();
            hdr.put("type", "header");
            hdr.put("format", "quantus-depin-journal");
            hdr.put("version", DepinCore.VERSION);
            hdr.put("device_id", deviceId);
            hdr.put("pubkey", Hex.encode(pub));
            w.write(Json.canonical(hdr));
            w.write('\n');
            byte[] prevState = DepinCore.ZERO32;
            byte[] prevHash = DepinCore.ZERO32;
            String dummySig = Hex.encode(new byte[64]);
            DepinCore.Checkpoint lastCp = null;
            for (int i = 0; i < max; i++) {
                DepinCore.Observation o = new DepinCore.Observation();
                o.timestampUnix = baseTs + i * 600L;
                o.bestBlockNumber = 360000L + i * 7L;
                o.bestBlockHash = DepinCore.sha256(
                        ("cap-block-" + i).getBytes(StandardCharsets.US_ASCII));
                o.observedPeers = 12;
                o.finalizedBlockNumber = o.bestBlockNumber - 2;
                DepinCore.Checkpoint cp = DepinCore.makeCheckpoint(
                        i, o, prevState, prevHash, 1, pub);
                Map<String, Object> m = cp.toMap();
                m.put("entry_sig", dummySig);
                w.write(Json.canonical(m));
                w.write('\n');
                prevState = cp.chainState;
                prevHash = cp.checkpointHash;
                lastCp = cp;
            }
            tail = lastCp;
        }
        JournalStore store = JournalStore.forFile(file, deviceId, Hex.encode(pub), dummySigner, dummyVerifier);
        store.setFsyncForTest(out -> { });
        check("cap: journal filled to seq MAX-1 loads whole",
                store.count() == max && store.droppedOnLoad() == 0);

        // seq == MAX is the largest value the reload path
        // accepts, so append must accept it too.
        DepinCore.Observation oMax = new DepinCore.Observation();
        oMax.timestampUnix = baseTs + (long) max * 600L;
        oMax.bestBlockNumber = 360000L + (long) max * 7L;
        oMax.bestBlockHash = DepinCore.sha256(
                "cap-block-max".getBytes(StandardCharsets.US_ASCII));
        oMax.observedPeers = 12;
        oMax.finalizedBlockNumber = oMax.bestBlockNumber - 2;
        DepinCore.Checkpoint cpMax = DepinCore.makeCheckpoint(
                max, oMax, tail.chainState, tail.checkpointHash, 1, pub);
        store.append(cpMax);
        check("cap: append at seq MAX (the reload bound) succeeds",
                store.count() == max + 1);

        // seq == MAX + 1 could never reload: append must refuse
        // it outright — surfaced — instead of writing a record
        // the next load would drop and delete.
        DepinCore.Observation oOver = new DepinCore.Observation();
        oOver.timestampUnix = baseTs + ((long) max + 1) * 600L;
        oOver.bestBlockNumber = 360000L + ((long) max + 1) * 7L;
        oOver.bestBlockHash = DepinCore.sha256(
                "cap-block-over".getBytes(StandardCharsets.US_ASCII));
        oOver.observedPeers = 12;
        oOver.finalizedBlockNumber = oOver.bestBlockNumber - 2;
        DepinCore.Checkpoint cpOver = DepinCore.makeCheckpoint(
                (long) max + 1, oOver,
                cpMax.chainState, cpMax.checkpointHash, 1, pub);
        boolean refused = false;
        try {
            store.append(cpOver);
        } catch (IllegalStateException e) {
            refused = true;
        }
        check("cap: append beyond seq MAX refuses instead of writing",
                refused && store.count() == max + 1);

        JournalStore reloaded = JournalStore.forFile(file, deviceId, Hex.encode(pub), dummySigner, dummyVerifier);
        check("cap: everything append wrote reloads losslessly",
                reloaded.count() == max + 1
                        && reloaded.droppedOnLoad() == 0
                        && reloaded.last() != null
                        && reloaded.last().seq == max);
    }

    /** Models the JDK's chunked stream for the F-03 server
     *  shape: the body is "1;" plus a chunk extension whose
     *  bytes drip in at fixed intervals. A chunked stream parses
     *  the chunk-size line INSIDE a single read() call — reading
     *  the extension bytes one by one — so the call does not
     *  return until the line completes (~drips x dripMs), which
     *  is exactly what hid the wait from readCapped's
     *  between-reads deadline checks. */
    private static final class ChunkHeaderDripStream extends java.io.InputStream {
        private final int drips;
        private final long dripMs;
        private int stage = 0; // 0 = chunk header, 1 = data byte, 2 = eof
        private volatile boolean closed = false;
        long internalWaits = 0;

        ChunkHeaderDripStream(int drips, long dripMs) {
            this.drips = drips;
            this.dripMs = dripMs;
        }

        @Override
        public int read() throws java.io.IOException {
            byte[] one = new byte[1];
            int n = read(one, 0, 1);
            return n < 0 ? -1 : (one[0] & 0xFF);
        }

        @Override
        public int read(byte[] b, int off, int len) throws java.io.IOException {
            if (stage == 0) {
                for (int i = 0; i < drips; i++) {
                    dripWait();
                }
                stage = 1;
            }
            if (stage == 1) {
                stage = 2;
                b[off] = 'x';
                return 1;
            }
            return -1;
        }

        private void dripWait() throws java.io.IOException {
            // Sliced sleep so disconnect()/interrupt ends the
            // wait promptly, the way disconnect() ends a socket
            // read mid-flight.
            long end = System.currentTimeMillis() + dripMs;
            while (!closed) {
                long left = end - System.currentTimeMillis();
                if (left <= 0) {
                    internalWaits++;
                    return;
                }
                try {
                    Thread.sleep(Math.min(left, 25));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new java.io.IOException(
                            "interrupted during chunk-header drip");
                }
            }
            throw new java.io.IOException(
                    "stream closed during chunk-header drip");
        }

        /** Stands in for HttpURLConnection.disconnect(). */
        void disconnect() {
            closed = true;
        }
    }

    private static void testRpcChunkedBodyDeadline() throws Exception {
        // F-03: the audit's drip server — chunk extension bytes
        // at 300 ms intervals against a 400 ms budget. The
        // pre-fix body path (readCapped called bare, as httpPost
        // did) followed the stream for ~3,015 ms: the single
        // read() call consumed the whole chunk-size line
        // internally, and the deadline was only noticed after
        // it returned. readBody runs the same loop under the
        // runWithDeadline watchdog (the header phase's
        // mechanism), so the call is cut AT the budget.
        ChunkHeaderDripStream drip = new ChunkHeaderDripStream(10, 300);
        java.util.concurrent.atomic.AtomicBoolean aborted =
                new java.util.concurrent.atomic.AtomicBoolean(false);
        long deadline = System.nanoTime() + 400L * 1_000_000L;
        long t0 = System.nanoTime();
        boolean deadlineThrown = false;
        try {
            RpcClient.readBody(drip, deadline,
                    () -> {
                        aborted.set(true);
                        drip.disconnect();
                    }, "testChunked");
        } catch (RpcClient.RpcException e) {
            deadlineThrown = e.getMessage() != null
                    && e.getMessage().contains("deadline");
        }
        long elapsedMs = (System.nanoTime() - t0) / 1_000_000L;
        check("rpc chunked body: drip-fed chunk extension aborts at the deadline",
                deadlineThrown && aborted.get());
        check("rpc chunked body: abort is timely (~budget, not ~3 s)",
                elapsedMs < 2_000 && drip.internalWaits <= 3);

        // A timely body through the same composition comes back
        // whole.
        byte[] payload = resultJson("{\"ok\":true}")
                .getBytes(StandardCharsets.UTF_8);
        byte[] got = RpcClient.readBody(
                new java.io.ByteArrayInputStream(payload),
                System.nanoTime() + 5_000L * 1_000_000L,
                () -> { }, "testChunked");
        check("rpc chunked body: timely body returned whole",
                Arrays.equals(got, payload));

        // The size cap, enforced by readCapped inside the
        // watchdog, surfaces as readCapped's own refusal — not
        // as a watchdog-wrapped message.
        byte[] big = new byte[300 * 1024];
        boolean capThrown = false;
        try {
            RpcClient.readBody(new java.io.ByteArrayInputStream(big),
                    System.nanoTime() + 60_000L * 1_000_000L,
                    () -> { }, "testChunked");
        } catch (RpcClient.RpcException e) {
            capThrown = e.getMessage().contains("exceeds");
        }
        check("rpc chunked body: size cap refusal surfaces unchanged",
                capThrown);
    }

    private static void testJournalAppendGeneration() throws Exception {
        // F-09: the audit's interleaving, driven against the
        // store. A tick captures its generation and passes the
        // service-side isCurrent check; THEN the service is
        // stopped (requestStop) and restarted
        // (beginNewGeneration); THEN the tick's append runs.
        // Before the fix the append had no generation to check
        // and the stale checkpoint landed (demonstrated against
        // the v0.3.3 API in the v0.9 progress memo). The gated
        // append re-verifies the generation under the store
        // lock at write time and must refuse.
        byte[] seed = testSeed();
        byte[] pub = Ed25519.publickeyFromSeed(seed);
        String deviceId = DepinCore.deviceIdFromPubkey(pub);
        File dir = new File(System.getProperty("java.io.tmpdir"),
                "depin-journal-gen-" + System.nanoTime());
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        File file = new File(dir, "journal.json");
        JournalStore j = JournalStore.forFile(file, deviceId, Hex.encode(pub), testSigner(seed), testVerifier(pub));

        ServiceGeneration.PROCESS.beginNewGeneration(); // known-live generation
        long gen = ServiceGeneration.PROCESS.capture();
        DepinCore.Checkpoint cp = DepinCore.makeCheckpoint(
                0, syntheticObservations(1).get(0),
                j.nextPrevState(), j.nextPrevCheckpointHash(), 50, pub);
        check("f09: generation is current when the tick checks (precondition)",
                ServiceGeneration.PROCESS.isCurrent(gen));
        ServiceGeneration.PROCESS.requestStop();
        ServiceGeneration.PROCESS.beginNewGeneration();
        boolean refused = false;
        String refuseMsg = null;
        try {
            j.append(cp, gen);
        } catch (IllegalStateException e) {
            refused = true;
            refuseMsg = e.getMessage();
        }
        check("f09: stale generation append refused at write time",
                refused && refuseMsg != null
                        && refuseMsg.contains("generation")
                        && j.count() == 0);

        // The live generation's own append goes through.
        long live = ServiceGeneration.PROCESS.capture();
        j.append(cp, live);
        check("f09: current generation append succeeds", j.count() == 1);

        // A stop with NO restart latches stale too: a generation
        // captured before it can never append afterwards.
        long gen2 = ServiceGeneration.PROCESS.capture();
        DepinCore.Checkpoint cp2 = DepinCore.makeCheckpoint(
                1, syntheticObservations(2).get(1),
                j.nextPrevState(), j.nextPrevCheckpointHash(), 50, pub);
        ServiceGeneration.PROCESS.requestStop();
        boolean refused2 = false;
        try {
            j.append(cp2, gen2);
        } catch (IllegalStateException e) {
            refused2 = true;
        }
        check("f09: append after a bare stop is refused too",
                refused2 && j.count() == 1);
        ServiceGeneration.PROCESS.beginNewGeneration(); // leave PROCESS live
    }

    private static void testPendingExportHolder() {
        // F-10: the pending export payload lives in
        // application-scoped state, not in an Activity instance
        // field. For state held this way, an Activity recreation
        // while the document picker is open is indistinguishable
        // from simply reading the holder again from a fresh
        // instance — which is precisely the property the fix
        // relies on, pinned here at code level. (The Activity
        // wiring itself is Android-bound; it is verified by the
        // APK build, and the result handler now also refuses to
        // open the destination when no payload is pending, so a
        // lost export can no longer leave an empty file.)
        PendingExport.clear();
        check("export holder: empty at start", PendingExport.peek() == null);
        PendingExport.set("{\"bundle\":1}");
        check("export holder: payload survives recreation (held outside the Activity)",
                "{\"bundle\":1}".equals(PendingExport.peek()));
        check("export holder: completion takes the payload and clears it",
                "{\"bundle\":1}".equals(PendingExport.take())
                        && PendingExport.peek() == null
                        && PendingExport.take() == null);
        PendingExport.set("{\"bundle\":2}");
        PendingExport.clear();
        check("export holder: cancel clears the payload",
                PendingExport.peek() == null);
        PendingExport.set("old");
        PendingExport.set("new");
        check("export holder: a new export supersedes an abandoned one",
                "new".equals(PendingExport.take()));
    }

    /** One F-11 replay: run the audit's four rounds through a
     *  fresh RPC client + plausibility + streak, applying the
     *  tick bookkeeping with or without noteRejected() on the
     *  inconsistent path. Returns which rounds (index) were
     *  permitted to record a fresh segment's first checkpoint,
     *  and whether the inconsistent round really occurred. */
    private static boolean[][] replayF11(boolean noteOnInconsistent)
            throws Exception {
        String bestHash = "0x" + "ab".repeat(32);
        String finHash = "0x" + "cd".repeat(32);
        java.util.concurrent.atomic.AtomicLong finalized =
                new java.util.concurrent.atomic.AtomicLong(99);
        RpcClient client = new RpcClient(cannedTransport(request -> {
            if (request.contains("system_syncState")) {
                return resultJson("{\"currentBlock\":100,\"highestBlock\":100,"
                        + "\"startingBlock\":90}");
            }
            if (request.contains("chain_getBlockHash")) {
                return resultJson("\"" + bestHash + "\"");
            }
            if (request.contains("chain_getFinalizedHead")) {
                return resultJson("\"" + finHash + "\"");
            }
            if (request.contains("chain_getHeader")) {
                return resultJson("{\"number\":\"0x"
                        + Long.toHexString(finalized.get()) + "\"}");
            }
            if (request.contains("system_health")) {
                return resultJson("{\"peers\":5,\"isSyncing\":false}");
            }
            return resultJson("null");
        }));
        ObservationPlausibility plausibility = new ObservationPlausibility();
        SegmentPolicy policy = new SegmentPolicy();
        boolean[] permitted = new boolean[4];
        boolean[] sawInconsistent = new boolean[1];
        long[] fins = {99, 101, 99, 99};
        for (int round = 0; round < 4; round++) {
            finalized.set(fins[round]);
            RpcClient.NodeObservation node;
            try {
                node = client.fetchObservation();
            } catch (RpcClient.InconsistentObservation e) {
                sawInconsistent[0] = true;
                // The tick's bookkeeping for a round that threw:
                // the F-11 fix calls noteRejected() here; the
                // pre-fix service returned silently.
                if (noteOnInconsistent) {
                    policy.noteRejected();
                }
                continue;
            }
            ObservationPlausibility.Decision d =
                    plausibility.evaluate(node.observation);
            if (!d.accepted) {
                policy.noteRejected();
                continue;
            }
            permitted[round] = policy.noteAcceptedWhileSegmentEmpty();
        }
        return new boolean[][]{permitted, sawInconsistent};
    }

    private static void testSegmentStartStreakF11() throws Exception {
        // F-11: rounds good(100/99) -> inconsistent(100/101) ->
        // good(100/99) -> good(100/99), against the production
        // fetch (finalized > best genuinely throws
        // InconsistentObservation inside fetchObservation) and
        // the production streak machine, with the tick
        // bookkeeping the fixed service applies. "Consecutive"
        // is load-bearing: the inconsistent round is a REJECTED
        // reading and must break the streak, so a fresh
        // segment's first checkpoint is permitted only after
        // the fourth round.
        boolean[][] fixed = replayF11(true);
        check("f11: middle round is genuinely inconsistent (precondition)",
                fixed[1][0]);
        check("f11: good -> inconsistent -> good does NOT open the segment",
                !fixed[0][0] && !fixed[0][2]);
        check("f11: the fourth round (second consecutive good) opens it",
                fixed[0][3]);

        // Contrast — the pre-fix wiring replayed against the
        // same production machinery: without noteRejected() on
        // the exception path, the segment opens at round 3 even
        // though the two good readings were never consecutive.
        // This is the defect F-11 names, kept as a pin so the
        // difference the one call makes stays visible.
        boolean[][] legacy = replayF11(false);
        check("f11: without the reset, round 3 opens the segment (the defect)",
                legacy[1][0] && legacy[0][2]);
    }

    // ---------------- tiny assertion plumbing ----------------

    private static void check(String name, boolean ok) {
        if (ok) {
            passed++;
            System.out.println("PASS " + name);
        } else {
            failed++;
            System.out.println("FAIL " + name);
        }
    }
}
