package app.quantusnode.depin;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Quantus DePIN proof format v0.5 — generation and verification,
 * following the shared v0.5 contract with the Python reference
 * implementation (tools/depin_core.py in this repository).
 * Bundles produced here must verify there and vice versa; the JVM
 * harness pins byte equality against contract-derived vectors.
 *
 * The builder/verifier are parameterized by format version
 * (FormatProfile): the current format is "0.5"; legacy profiles
 * "0.4" and "0.3" exist so the journal migration can verify the
 * internal consistency of pre-v0.5 entries (see JournalStore) and
 * so archived bundles stay verifiable. Generation always uses the
 * current profile.
 *
 * v0.5 changes relative to v0.4 (re-audit of v0.4):
 *  - format domains versioned to QDP1/{seed,ckpt,bundle}/v0.5.
 *    The chain-seed INPUTS are unchanged from v0.4: the seed binds
 *    the slot (timestamp // 600), finalized block number (i64, -1
 *    when absent) and observed peer count, so one computed chain
 *    segment serves exactly one (slot, finalized, peers) claim —
 *    shifting a checkpoint's timestamp into another slot requires
 *    redoing the sequential work (H-01 mitigation, together with
 *    the scorer-side slot dedup on the Python side).
 *  - verification parity round 2 (R-M01): the FULL schema of every
 *    checkpoint is validated before any bundle_hash / signature
 *    work (matching the reference's order); witness lists must be
 *    sorted ascending, unique and at most 512 entries; a JSON null
 *    is malformed for every typed field (finalized_block_number:
 *    null is NOT "absent" — absent means the key is missing);
 *    integer ranges match the reference schema exactly (seq,
 *    timestamp, block numbers, peer counts, created_at_unix).
 *  - witness peer hashes are retained on checkpoints and included
 *    in the checkpoint hash (count u32 + sorted concatenation),
 *    exactly as the reference encodes them. This app still never
 *    produces witnesses (peer lists are not obtainable over the
 *    node's safe RPC surface), but it verifies bundles that carry
 *    them instead of silently dropping the field.
 *
 * Parameters stay fixed by profile (production: 600-second slots,
 * 1,000,000 iterations); the app always uses production and the
 * test profile exists only for the harness.
 */
final class DepinCore {
    private DepinCore() {}

    static final String FORMAT = "quantus-depin-proof";
    static final String VERSION = "0.5";

    static final byte[] DOMAIN_SEED_V05 = ascii("QDP1/seed/v0.5");
    static final byte[] DOMAIN_CKPT_V05 = ascii("QDP1/ckpt/v0.5");
    static final byte[] DOMAIN_BUNDLE_V05 = ascii("QDP1/bundle/v0.5");
    static final byte[] DOMAIN_SEED_V04 = ascii("QDP1/seed/v0.4");
    static final byte[] DOMAIN_CKPT_V04 = ascii("QDP1/ckpt/v0.4");
    static final byte[] DOMAIN_BUNDLE_V04 = ascii("QDP1/bundle/v0.4");
    static final byte[] DOMAIN_SEED_V03 = ascii("QDP1/seed/v0.3");
    /** Legacy domains, retained ONLY so the journal can verify the
     *  internal consistency of pre-v0.5 entries during migration
     *  (see JournalStore). Never used for new checkpoints. */
    static final byte[] DOMAIN_CKPT_V03 = ascii("QDP1/ckpt/v0.3");
    static final byte[] DOMAIN_BUNDLE_V03 = ascii("QDP1/bundle/v0.3");
    static final byte[] DOMAIN_JOURNAL_V1 = ascii("QDP1/journal/v1");
    static final byte[] NETWORK_ID = ascii("quantus");
    static final byte[] ZERO32 = new byte[32];

    static final int SLOT_SEC = 600;
    static final int PRODUCTION_ITERATIONS = 1_000_000;
    static final int TEST_ITERATIONS = 50;
    static final int MAX_CHECKPOINTS = 200_000;
    /** Reference schema cap on witness hashes per checkpoint. */
    static final int MAX_WITNESSES_PER_CHECKPOINT = 512;

    /**
     * One format version's domains and chain-seed shape. The v0.4
     * and v0.5 chains share the seed INPUT layout (slot / finalized
     * / peers bound); the v0.3 chain predates that binding and its
     * seed covers only (pubkey, network, prev state, block hash,
     * seq, block number).
     */
    static final class FormatProfile {
        final String version;
        final byte[] seedDomain;
        final byte[] ckptDomain;
        final byte[] bundleDomain;
        final boolean boundSeedInputs;

        private FormatProfile(String version, byte[] seedDomain,
                              byte[] ckptDomain, byte[] bundleDomain,
                              boolean boundSeedInputs) {
            this.version = version;
            this.seedDomain = seedDomain;
            this.ckptDomain = ckptDomain;
            this.bundleDomain = bundleDomain;
            this.boundSeedInputs = boundSeedInputs;
        }
    }

    static final FormatProfile FMT_V05 = new FormatProfile("0.5",
            DOMAIN_SEED_V05, DOMAIN_CKPT_V05, DOMAIN_BUNDLE_V05, true);
    static final FormatProfile FMT_V04 = new FormatProfile("0.4",
            DOMAIN_SEED_V04, DOMAIN_CKPT_V04, DOMAIN_BUNDLE_V04, true);
    static final FormatProfile FMT_V03 = new FormatProfile("0.3",
            DOMAIN_SEED_V03, DOMAIN_CKPT_V03, DOMAIN_BUNDLE_V03, false);
    /** The format this build generates and (by default) verifies. */
    static final FormatProfile CURRENT = FMT_V05;

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static String deviceIdFromPubkey(byte[] pubkey) {
        byte[] h = sha256(pubkey);
        return "qdp1-" + Hex.encode(Arrays.copyOf(h, 12));
    }

    // ---------------- strict field access (M-01) ----------------

    /**
     * Integer fields accept ONLY values the JSON parser produced
     * for an integral literal (Long). A fractional or exponent
     * literal (8.0, 8e0) parses to Double and is rejected here —
     * the Python reference rejects the same inputs at schema
     * validation, so verdicts agree.
     */
    static long strictLong(Object v, String field) {
        if (v instanceof Long) return (Long) v;
        throw new IllegalArgumentException(field + ": expected a JSON integer");
    }

    static String strictString(Object v, String field) {
        if (v instanceof String) return (String) v;
        throw new IllegalArgumentException(field + ": expected a string");
    }

    static byte[] strictHex32(Object v, String field) {
        String s = strictString(v, field);
        byte[] b = Hex.decodeCanonical(s);
        if (b.length != 32) {
            throw new IllegalArgumentException(field + ": expected 32 bytes");
        }
        return b;
    }

    static byte[] strictHex64(Object v, String field) {
        String s = strictString(v, field);
        byte[] b = Hex.decodeCanonical(s);
        if (b.length != 64) {
            throw new IllegalArgumentException(field + ": expected 64 bytes");
        }
        return b;
    }

    /**
     * Range check matching the reference schema (R-M01): every
     * integer field carries the same [lo, hi] bounds in both
     * implementations, so a value one side accepts is never
     * rejected by the other.
     */
    static long strictRange(long v, long lo, long hi, String field) {
        if (v < lo || v > hi) {
            throw new IllegalArgumentException(
                    field + ": " + v + " outside [" + lo + ", " + hi + "]");
        }
        return v;
    }

    // ---------------- sequential chain ----------------

    /**
     * One chain segment under a format profile. For the bound
     * profiles (v0.4 / v0.5) the seed binds, in order: the profile's
     * seed domain, the device public key, the network identifier,
     * the previous chain state, the best block hash, seq, block
     * number, the checkpoint's slot (timestamp // SLOT_SEC), the
     * finalized block number as i64 (-1 when absent) and the
     * observed peer count as u32. The legacy v0.3 profile's seed
     * stops after block number (its historical layout). Iterations
     * of plain SHA-256 follow.
     */
    static byte[] sequentialChain(FormatProfile fmt, byte[] prevState,
                                  byte[] blockHash, long seq,
                                  long blockNumber, int iterations,
                                  byte[] pubkey, long slot,
                                  long finalizedOrMinus1, long peers) {
        ByteArrayOutputStream seedIn = new ByteArrayOutputStream();
        seedIn.write(fmt.seedDomain, 0, fmt.seedDomain.length);
        seedIn.write(pubkey, 0, pubkey.length);
        seedIn.write(NETWORK_ID, 0, NETWORK_ID.length);
        seedIn.write(prevState, 0, prevState.length);
        seedIn.write(blockHash, 0, blockHash.length);
        writeU64(seedIn, seq);
        writeU64(seedIn, blockNumber);
        if (fmt.boundSeedInputs) {
            writeU64(seedIn, slot);
            writeI64(seedIn, finalizedOrMinus1);
            writeU32(seedIn, peers);
        }
        byte[] state = sha256(seedIn.toByteArray());
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (int i = 0; i < iterations; i++) {
                state = md.digest(state);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        return state;
    }

    /** v0.4 chain segment (legacy profile wrapper, kept for the
     *  harness's v0.4 golden vectors and journal migration). */
    static byte[] sequentialChainV04(byte[] prevState, byte[] blockHash,
                                     long seq, long blockNumber,
                                     int iterations, byte[] pubkey,
                                     long slot, long finalizedOrMinus1,
                                     long peers) {
        return sequentialChain(FMT_V04, prevState, blockHash, seq,
                blockNumber, iterations, pubkey, slot,
                finalizedOrMinus1, peers);
    }

    // ---------------- journal entry signatures (H-04) ----------------

    /** The exact bytes a journal entry signature covers:
     *  "QDP1/journal/v1" || checkpoint_hash || seq (u64be). */
    static byte[] journalEntryMessage(byte[] checkpointHash, long seq) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(DOMAIN_JOURNAL_V1, 0, DOMAIN_JOURNAL_V1.length);
        out.write(checkpointHash, 0, checkpointHash.length);
        writeU64(out, seq);
        return out.toByteArray();
    }

    static byte[] journalEntrySig(byte[] seed, byte[] checkpointHash, long seq) {
        return Ed25519.sign(seed, journalEntryMessage(checkpointHash, seq));
    }

    static boolean verifyJournalEntrySig(byte[] pubkey, byte[] checkpointHash,
                                         long seq, byte[] sig) {
        if (sig == null || sig.length != 64) return false;
        return Ed25519.verify(pubkey, journalEntryMessage(checkpointHash, seq), sig);
    }

    // ---------------- checkpoint ----------------

    /** One raw observation, as read from the node's RPC. */
    static final class Observation {
        long timestampUnix;
        long bestBlockNumber;
        byte[] bestBlockHash;       // 32 bytes
        int observedPeers;
        Long finalizedBlockNumber;  // null only in synthetic tests
        /** Witness peer HASHES (32-byte values), if any. The app
         *  itself never sets this (no witness source over safe RPC);
         *  it exists so generation matches the reference encoding. */
        List<byte[]> witnessPeerHashes;
    }

    static final class Checkpoint {
        long seq;
        long timestampUnix;
        long bestBlockNumber;
        byte[] bestBlockHash;
        /** A u32 on the wire, held in a long (F-07, v0.9): as a
         *  signed int, values at or above 2^31 went negative in
         *  fromMap and toMap then re-serialized a value the
         *  schema itself rejects — a valid record could not
         *  survive a parse/serialize round trip. */
        long observedPeers;
        int iterations;
        byte[] prevCheckpointHash;
        byte[] chainState;
        Long finalizedBlockNumber;  // may be null (then encoded as -1)
        /** Sorted, deduplicated witness peer hashes; never null. */
        List<byte[]> witnessPeerHashes = new ArrayList<>();
        byte[] checkpointHash;

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("seq", seq);
            m.put("timestamp_unix", timestampUnix);
            m.put("best_block_number", bestBlockNumber);
            m.put("best_block_hash", Hex.encode(bestBlockHash));
            m.put("observed_peers", observedPeers);
            m.put("iterations", (long) iterations);
            m.put("prev_checkpoint_hash", Hex.encode(prevCheckpointHash));
            m.put("chain_state", Hex.encode(chainState));
            if (finalizedBlockNumber != null) {
                m.put("finalized_block_number", finalizedBlockNumber);
            }
            if (!witnessPeerHashes.isEmpty()) {
                List<Object> ws = new ArrayList<>();
                for (byte[] w : witnessPeerHashes) {
                    ws.add(Hex.encode(w));
                }
                m.put("witness_peer_hashes", ws);
            }
            m.put("checkpoint_hash", Hex.encode(checkpointHash));
            return m;
        }

        /**
         * Strict parse (M-01, tightened by R-M01): integer fields
         * must be JSON integers within the reference schema's
         * ranges, hex fields canonical lowercase of the right
         * length, no unknown fields, and NO field may be JSON null
         * (the reference's typed schema rejects nulls —
         * finalized_block_number in particular: null is malformed,
         * only a MISSING key means "absent"). Witness lists must
         * be sorted ascending, unique and at most
         * MAX_WITNESSES_PER_CHECKPOINT long, exactly as the
         * reference requires; generation normalizes via
         * sortedUnique(), so a wire list that is not already in
         * canonical order is not something a conforming producer
         * emits. Violations raise IllegalArgumentException;
         * callers (bundle verification, journal load) treat that as
         * rejection of the enclosing record.
         */
        static Checkpoint fromMap(Map<String, Object> m) {
            for (String k : m.keySet()) {
                if (!CKPT_KEYS.contains(k)) {
                    throw new IllegalArgumentException("unknown checkpoint field: " + k);
                }
            }
            Checkpoint c = new Checkpoint();
            c.seq = strictRange(strictLong(m.get("seq"), "seq"),
                    0, MAX_CHECKPOINTS, "seq");
            c.timestampUnix = strictRange(
                    strictLong(m.get("timestamp_unix"), "timestamp_unix"),
                    0, Long.MAX_VALUE, "timestamp_unix");
            c.bestBlockNumber = strictRange(
                    strictLong(m.get("best_block_number"), "best_block_number"),
                    0, Long.MAX_VALUE, "best_block_number");
            c.bestBlockHash = strictHex32(m.get("best_block_hash"), "best_block_hash");
            long peers = strictRange(
                    strictLong(m.get("observed_peers"), "observed_peers"),
                    0, 0xFFFF_FFFFL, "observed_peers");
            c.observedPeers = peers;
            long iters = strictLong(m.get("iterations"), "iterations");
            if (iters < 1 || iters > Integer.MAX_VALUE) {
                throw new IllegalArgumentException("iterations out of range");
            }
            c.iterations = (int) iters;
            c.prevCheckpointHash = strictHex32(
                    m.get("prev_checkpoint_hash"), "prev_checkpoint_hash");
            c.chainState = strictHex32(m.get("chain_state"), "chain_state");
            if (m.containsKey("finalized_block_number")) {
                // Present — including present-as-null, which
                // strictLong rejects (R-M01). The reference schema
                // range is [0, 2^63 - 1]; consistency with
                // best_block_number is a semantic check in the
                // verifier, as it is in the reference.
                c.finalizedBlockNumber = strictRange(
                        strictLong(m.get("finalized_block_number"),
                                "finalized_block_number"),
                        0, Long.MAX_VALUE, "finalized_block_number");
            }
            if (m.containsKey("witness_peer_hashes")) {
                Object wit = m.get("witness_peer_hashes");
                if (!(wit instanceof List)) {
                    throw new IllegalArgumentException(
                            "witness_peer_hashes: expected an array");
                }
                List<?> raw = (List<?>) wit;
                if (raw.size() > MAX_WITNESSES_PER_CHECKPOINT) {
                    throw new IllegalArgumentException(
                            "witness_peer_hashes: too many entries: " + raw.size());
                }
                byte[] prev = null;
                for (Object w : raw) {
                    byte[] h = strictHex32(w, "witness_peer_hashes[]");
                    if (prev != null && compareBytes(prev, h) >= 0) {
                        throw new IllegalArgumentException(
                                "witness_peer_hashes: not sorted ascending / unique");
                    }
                    prev = h;
                    c.witnessPeerHashes.add(h);
                }
            }
            c.checkpointHash = strictHex32(
                    m.get("checkpoint_hash"), "checkpoint_hash");
            return c;
        }
    }

    private static final Set<String> CKPT_KEYS = new HashSet<>(Arrays.asList(
            "seq", "timestamp_unix", "best_block_number", "best_block_hash",
            "observed_peers", "iterations", "prev_checkpoint_hash",
            "chain_state", "finalized_block_number", "witness_peer_hashes",
            "checkpoint_hash"));

    private static final Set<String> TOP_KEYS = new HashSet<>(Arrays.asList(
            "format", "version", "device_id", "pubkey", "created_at_unix",
            "params", "checkpoints", "bundle_hash", "signature"));

    private static final Set<String> PARAM_KEYS = new HashSet<>(Arrays.asList(
            "hash", "signature", "iterations_per_checkpoint",
            "checkpoint_interval_sec"));

    /** Unsigned byte-wise ordering, matching Python's sorted() on
     *  bytes objects. */
    static int compareBytes(byte[] a, byte[] b) {
        int n = Math.min(a.length, b.length);
        for (int i = 0; i < n; i++) {
            int d = (a[i] & 0xff) - (b[i] & 0xff);
            if (d != 0) return d;
        }
        return a.length - b.length;
    }

    static List<byte[]> sortedUnique(List<byte[]> in) {
        List<byte[]> out = new ArrayList<>();
        if (in != null) {
            for (byte[] w : in) {
                boolean dup = false;
                for (byte[] x : out) {
                    if (Arrays.equals(x, w)) { dup = true; break; }
                }
                if (!dup) out.add(w.clone());
            }
        }
        out.sort(DepinCore::compareBytes);
        return out;
    }

    private static byte[] checkpointHash(Checkpoint c, byte[] domain) {
        ByteArrayOutputStream enc = new ByteArrayOutputStream();
        enc.write(domain, 0, domain.length);
        writeU64(enc, c.seq);
        writeI64(enc, c.timestampUnix);
        writeU64(enc, c.bestBlockNumber);
        enc.write(c.bestBlockHash, 0, c.bestBlockHash.length);
        writeU32(enc, c.observedPeers);
        enc.write(c.prevCheckpointHash, 0, c.prevCheckpointHash.length);
        writeU64(enc, c.iterations);
        enc.write(c.chainState, 0, c.chainState.length);
        // finalized as i64 (-1 when absent), witness count u32,
        // then the witness hashes in sorted order.
        writeI64(enc, c.finalizedBlockNumber == null ? -1 : c.finalizedBlockNumber);
        List<byte[]> ws = new ArrayList<>(c.witnessPeerHashes);
        ws.sort(DepinCore::compareBytes);
        writeU32(enc, ws.size());
        for (byte[] w : ws) {
            enc.write(w, 0, w.length);
        }
        return sha256(enc.toByteArray());
    }

    static byte[] checkpointHash(FormatProfile fmt, Checkpoint c) {
        return checkpointHash(c, fmt.ckptDomain);
    }

    static byte[] checkpointHashV04(Checkpoint c) {
        return checkpointHash(c, DOMAIN_CKPT_V04);
    }

    /** v0.3-domain checkpoint hash — used ONLY to check the internal
     *  consistency of pre-v0.5 journal entries at migration/load
     *  time (their hashes were computed under the v0.3 domain). */
    static byte[] checkpointHashV03(Checkpoint c) {
        return checkpointHash(c, DOMAIN_CKPT_V03);
    }

    /** The legacy profile under which this checkpoint's stored hash
     *  recomputes, or null when it matches neither legacy profile.
     *  Journal classification helper (see JournalStore): the live
     *  journal accepts CURRENT-domain hashes exclusively; a legacy
     *  head entry is routed to the archive of the profile it
     *  verifies under. */
    static FormatProfile legacyProfileOf(Checkpoint c) {
        if (Arrays.equals(checkpointHash(FMT_V04, c), c.checkpointHash)) {
            return FMT_V04;
        }
        if (Arrays.equals(checkpointHash(FMT_V03, c), c.checkpointHash)) {
            return FMT_V03;
        }
        return null;
    }

    /** True when the checkpoint's stored hash recomputes from its
     *  fields under the current or any legacy domain. Diagnostic
     *  helper only; acceptance decisions use legacyProfileOf /
     *  the CURRENT profile explicitly (see JournalStore). */
    static boolean checkpointHashMatches(Checkpoint c) {
        return Arrays.equals(checkpointHash(CURRENT, c), c.checkpointHash)
                || legacyProfileOf(c) != null;
    }

    /**
     * Advance the chain by one checkpoint under a format profile:
     * computes chain_state and checkpoint_hash. prevState /
     * prevCheckpointHash are the previous checkpoint's values
     * (ZERO32 for seq 0).
     */
    static Checkpoint makeCheckpoint(FormatProfile fmt, long seq,
                                     Observation obs, byte[] prevState,
                                     byte[] prevCheckpointHash,
                                     int iterations, byte[] pubkey) {
        Checkpoint c = new Checkpoint();
        c.seq = seq;
        c.timestampUnix = obs.timestampUnix;
        c.bestBlockNumber = obs.bestBlockNumber;
        c.bestBlockHash = obs.bestBlockHash.clone();
        c.observedPeers = obs.observedPeers;
        c.iterations = iterations;
        c.prevCheckpointHash = prevCheckpointHash.clone();
        c.finalizedBlockNumber = obs.finalizedBlockNumber;
        c.witnessPeerHashes = sortedUnique(obs.witnessPeerHashes);
        long slot = obs.timestampUnix / SLOT_SEC;
        long fin = (obs.finalizedBlockNumber == null) ? -1 : obs.finalizedBlockNumber;
        c.chainState = sequentialChain(fmt, prevState, obs.bestBlockHash,
                seq, obs.bestBlockNumber, iterations, pubkey,
                slot, fin, obs.observedPeers);
        c.checkpointHash = checkpointHash(fmt, c);
        return c;
    }

    /** Advance the chain under the CURRENT format profile. */
    static Checkpoint makeCheckpoint(long seq, Observation obs,
                                     byte[] prevState, byte[] prevCheckpointHash,
                                     int iterations, byte[] pubkey) {
        return makeCheckpoint(CURRENT, seq, obs, prevState,
                prevCheckpointHash, iterations, pubkey);
    }

    // ---------------- bundle ----------------

    /**
     * Assemble and sign a bundle under a format profile from
     * already-computed checkpoints. Mirrors build_bundle in the
     * reference: bundle_hash covers the canonical JSON of
     * everything except bundle_hash and signature; the signature
     * is over the profile's bundle domain || hash.
     */
    static Map<String, Object> assembleBundle(FormatProfile fmt, byte[] seed,
                                              List<Checkpoint> checkpoints,
                                              long createdAtUnix,
                                              int iterations) {
        if (checkpoints.isEmpty()) {
            throw new IllegalArgumentException("at least one checkpoint is required");
        }
        byte[] pubkey = Ed25519.publickeyFromSeed(seed);
        Map<String, Object> bundle = new LinkedHashMap<>();
        bundle.put("format", FORMAT);
        bundle.put("version", fmt.version);
        bundle.put("device_id", deviceIdFromPubkey(pubkey));
        bundle.put("pubkey", Hex.encode(pubkey));
        bundle.put("created_at_unix", createdAtUnix);
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("hash", "SHA-256");
        params.put("signature", "Ed25519");
        params.put("iterations_per_checkpoint", (long) iterations);
        params.put("checkpoint_interval_sec", (long) SLOT_SEC);
        bundle.put("params", params);
        List<Object> cps = new ArrayList<>();
        for (Checkpoint c : checkpoints) {
            cps.add(c.toMap());
        }
        bundle.put("checkpoints", cps);
        byte[] bundleHash = bundleHash(fmt, bundle);
        bundle.put("bundle_hash", Hex.encode(bundleHash));
        byte[] sig = Ed25519.sign(seed, Ed25519.concat(fmt.bundleDomain, bundleHash));
        bundle.put("signature", Hex.encode(sig));
        return bundle;
    }

    /** Assemble and sign a bundle under the CURRENT profile. */
    static Map<String, Object> assembleBundle(byte[] seed,
                                              List<Checkpoint> checkpoints,
                                              long createdAtUnix,
                                              int iterations) {
        return assembleBundle(CURRENT, seed, checkpoints, createdAtUnix, iterations);
    }

    /** Build a full bundle under a format profile from raw
     *  observations (used by tests and by the cross-check
     *  generator; the app itself accumulates checkpoints
     *  incrementally in the journal instead). */
    static Map<String, Object> buildBundle(FormatProfile fmt, byte[] seed,
                                           List<Observation> observations,
                                           int iterations,
                                           long createdAtUnix) {
        byte[] pubkey = Ed25519.publickeyFromSeed(seed);
        List<Checkpoint> cps = new ArrayList<>();
        byte[] prevState = ZERO32;
        byte[] prevHash = ZERO32;
        long prevTs = Long.MIN_VALUE;
        long prevNumber = Long.MIN_VALUE;
        for (int i = 0; i < observations.size(); i++) {
            Observation o = observations.get(i);
            if (o.timestampUnix <= prevTs) {
                throw new IllegalArgumentException("timestamps must be strictly increasing");
            }
            if (o.bestBlockNumber < prevNumber) {
                throw new IllegalArgumentException("best_block_number must be non-decreasing");
            }
            Checkpoint c = makeCheckpoint(fmt, i, o, prevState, prevHash, iterations, pubkey);
            cps.add(c);
            prevState = c.chainState;
            prevHash = c.checkpointHash;
            prevTs = o.timestampUnix;
            prevNumber = o.bestBlockNumber;
        }
        long created = (createdAtUnix >= 0)
                ? createdAtUnix
                : observations.get(observations.size() - 1).timestampUnix;
        return assembleBundle(fmt, seed, cps, created, iterations);
    }

    /** Build a full bundle under the CURRENT profile. */
    static Map<String, Object> buildBundle(byte[] seed,
                                           List<Observation> observations,
                                           int iterations,
                                           long createdAtUnix) {
        return buildBundle(CURRENT, seed, observations, iterations, createdAtUnix);
    }

    static byte[] bundleHash(FormatProfile fmt,
                             Map<String, Object> bundleWithoutHashAndSig) {
        Map<String, Object> core = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : bundleWithoutHashAndSig.entrySet()) {
            if (e.getKey().equals("bundle_hash") || e.getKey().equals("signature")) {
                continue;
            }
            core.put(e.getKey(), e.getValue());
        }
        return sha256(Ed25519.concat(fmt.bundleDomain, Json.canonicalBytes(core)));
    }

    /**
     * Verify a bundle under a format profile, in the reference's
     * strict, fail-fast order (M-01 / H-05, re-ordered by R-M01 so
     * the FULL schema is validated before any cryptographic work —
     * previously the checkpoint schema was only parsed after the
     * bundle_hash and signature checks, one of the divergences the
     * re-audit listed):
     *   1. full schema: exact key sets; format / version; strict
     *      field types AND ranges for the top level, the params
     *      and EVERY checkpoint (Checkpoint.fromMap); params must
     *      equal the verifier's profile; every checkpoint's
     *      iterations must equal the params value; bundle_hash and
     *      signature must be canonical hex of the right length.
     *      Any failure returns before any hash, signature or chain
     *      work.
     *   2. bundle_hash recomputation — a mismatch returns before
     *      signature or chain work (a tampered public bundle can
     *      no longer be used to make the verifier redo the chain)
     *   3. signature, under the profile's bundle domain
     *   4. per-checkpoint semantics (seq, linkage, monotonicity,
     *      finalized within best) + checkpoint-hash recomputation
     *   5. optionally, the sequential chain — always recomputed
     *      with the PROFILE iteration count, never a claimed one
     * expectedIterations is the verifier-side profile value.
     * Returns the list of errors (empty = valid).
     *
     * @param recomputeChain when false, skip step 5 (the expensive
     *        step). The app uses this for its pre-export self-check;
     *        full verification is the verifier's job and is
     *        exercised against the reference in the test suite.
     */
    static List<String> verifyBundle(FormatProfile fmt,
                                     Map<String, Object> bundle,
                                     int expectedIterations,
                                     boolean recomputeChain) {
        List<String> errors = new ArrayList<>();
        try {
            // 1) full schema, before any cryptographic work
            for (String k : bundle.keySet()) {
                if (!TOP_KEYS.contains(k)) {
                    errors.add("unknown top-level field: " + k);
                }
            }
            for (String k : TOP_KEYS) {
                if (!bundle.containsKey(k)) {
                    errors.add("missing top-level field: " + k);
                }
            }
            if (!errors.isEmpty()) return errors;
            if (!FORMAT.equals(bundle.get("format"))) errors.add("format mismatch");
            if (!fmt.version.equals(bundle.get("version"))) {
                errors.add("version mismatch");
            }
            byte[] pubkey = strictHex32(bundle.get("pubkey"), "pubkey");
            if (!deviceIdFromPubkey(pubkey).equals(
                    strictString(bundle.get("device_id"), "device_id"))) {
                errors.add("device_id does not match pubkey");
            }
            strictRange(strictLong(bundle.get("created_at_unix"), "created_at_unix"),
                    0, Long.MAX_VALUE, "created_at_unix");

            Map<String, Object> params = Json.asObject(bundle.get("params"));
            for (String k : params.keySet()) {
                if (!PARAM_KEYS.contains(k)) {
                    errors.add("unknown params field: " + k);
                }
            }
            if (!"SHA-256".equals(params.get("hash"))) {
                errors.add("params.hash must be SHA-256");
            }
            if (!"Ed25519".equals(params.get("signature"))) {
                errors.add("params.signature must be Ed25519");
            }
            long paramsIterations = strictRange(
                    strictLong(params.get("iterations_per_checkpoint"),
                            "params.iterations_per_checkpoint"),
                    1, Long.MAX_VALUE, "params.iterations_per_checkpoint");
            strictRange(strictLong(params.get("checkpoint_interval_sec"),
                    "params.checkpoint_interval_sec"),
                    1, Long.MAX_VALUE, "params.checkpoint_interval_sec");
            if (!errors.isEmpty()) return errors;
            // params == verifier profile, fail-fast (still schema
            // stage: no hash/signature/chain work has happened).
            if (paramsIterations != expectedIterations) {
                errors.add("params.iterations_per_checkpoint does not match profile");
                return errors;
            }
            if (strictLong(params.get("checkpoint_interval_sec"),
                    "params.checkpoint_interval_sec") != SLOT_SEC) {
                errors.add("params.checkpoint_interval_sec does not match profile");
                return errors;
            }

            List<Object> rawCps = Json.asArray(bundle.get("checkpoints"));
            if (rawCps.isEmpty() || rawCps.size() > MAX_CHECKPOINTS) {
                errors.add("checkpoint count out of range: " + rawCps.size());
                return errors;
            }
            List<Checkpoint> cps = new ArrayList<>();
            for (Object o : rawCps) {
                Checkpoint c = Checkpoint.fromMap(Json.asObject(o));
                if (c.iterations != paramsIterations) {
                    errors.add("checkpoint iterations != params");
                }
                cps.add(c);
            }
            byte[] storedHash = strictHex32(bundle.get("bundle_hash"), "bundle_hash");
            byte[] sig = strictHex64(bundle.get("signature"), "signature");
            if (!errors.isEmpty()) return errors;

            // 2) bundle hash, fail-fast
            if (!Arrays.equals(bundleHash(fmt, bundle), storedHash)) {
                errors.add("bundle_hash recomputation mismatch");
                return errors;
            }

            // 3) signature
            if (!Ed25519.verify(pubkey,
                    Ed25519.concat(fmt.bundleDomain, storedHash), sig)) {
                errors.add("signature verification failed");
                return errors;
            }

            // 4) checkpoint semantics + hash recomputation
            byte[] prevHash = ZERO32;
            long prevTs = Long.MIN_VALUE;
            long prevNumber = Long.MIN_VALUE;
            for (int i = 0; i < cps.size(); i++) {
                Checkpoint c = cps.get(i);
                String tag = "checkpoint[" + i + "]";
                if (c.seq != i) errors.add(tag + ": seq mismatch");
                if (!Arrays.equals(c.prevCheckpointHash, prevHash)) {
                    errors.add(tag + ": prev_checkpoint_hash linkage broken");
                }
                if (c.timestampUnix <= prevTs) {
                    errors.add(tag + ": timestamp not strictly increasing");
                }
                if (c.bestBlockNumber < prevNumber) {
                    errors.add(tag + ": best_block_number decreased");
                }
                if (c.finalizedBlockNumber != null
                        && c.finalizedBlockNumber > c.bestBlockNumber) {
                    errors.add(tag + ": finalized_block_number out of range");
                }
                if (!Arrays.equals(checkpointHash(fmt, c), c.checkpointHash)) {
                    errors.add(tag + ": checkpoint_hash recomputation mismatch");
                }
                prevHash = c.checkpointHash;
                prevTs = c.timestampUnix;
                prevNumber = c.bestBlockNumber;
            }
            if (!errors.isEmpty()) return errors;

            // 5) sequential chain, profile iterations only
            if (recomputeChain) {
                byte[] prevState = ZERO32;
                for (int i = 0; i < cps.size(); i++) {
                    Checkpoint c = cps.get(i);
                    long slot = c.timestampUnix / SLOT_SEC;
                    long fin = (c.finalizedBlockNumber == null)
                            ? -1 : c.finalizedBlockNumber;
                    byte[] recomputed = sequentialChain(fmt, prevState,
                            c.bestBlockHash, i, c.bestBlockNumber,
                            expectedIterations, pubkey, slot, fin,
                            c.observedPeers);
                    if (!Arrays.equals(recomputed, c.chainState)) {
                        errors.add("checkpoint[" + i
                                + "]: sequential chain recomputation mismatch");
                        break;
                    }
                    prevState = c.chainState;
                }
            }
        } catch (RuntimeException e) {
            errors.add("malformed bundle: " + e.getMessage());
        }
        return errors;
    }

    /** Verify a bundle of the CURRENT format ("0.5"). */
    static List<String> verifyBundle(Map<String, Object> bundle,
                                     int expectedIterations) {
        return verifyBundle(CURRENT, bundle, expectedIterations, true);
    }

    /** Verify a bundle of the CURRENT format ("0.5"). */
    static List<String> verifyBundle(Map<String, Object> bundle,
                                     int expectedIterations,
                                     boolean recomputeChain) {
        return verifyBundle(CURRENT, bundle, expectedIterations, recomputeChain);
    }

    /** Verify a legacy v0.4 bundle (archival / migration use). */
    static List<String> verifyBundleV04(Map<String, Object> bundle,
                                        int expectedIterations) {
        return verifyBundle(FMT_V04, bundle, expectedIterations, true);
    }

    /** Verify a legacy v0.4 bundle (archival / migration use). */
    static List<String> verifyBundleV04(Map<String, Object> bundle,
                                        int expectedIterations,
                                        boolean recomputeChain) {
        return verifyBundle(FMT_V04, bundle, expectedIterations, recomputeChain);
    }

    // ---------------- binary writers (big-endian) ----------------

    static void writeU64(ByteArrayOutputStream out, long v) {
        for (int i = 7; i >= 0; i--) {
            out.write((int) (v >>> (8 * i)) & 0xff);
        }
    }

    private static void writeI64(ByteArrayOutputStream out, long v) {
        writeU64(out, v);
    }

    private static void writeU32(ByteArrayOutputStream out, long v) {
        for (int i = 3; i >= 0; i--) {
            out.write((int) (v >>> (8 * i)) & 0xff);
        }
    }
}
