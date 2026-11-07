package app.quantusnode.depin;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The checkpoint journal: every checkpoint the observer has made,
 * in order, in app-private storage. (The on-disk name is the
 * historical "journal.json"; the content has been JSON Lines since
 * v0.4. The name is NOT changed: renaming it would orphan the real
 * journals this migration exists to carry forward.)
 *
 * Format (audit H-04 / M-04): JSON Lines — one header line, then
 * one line per checkpoint entry, APPEND-only in normal operation
 * (the v0.3 store rewrote the entire pretty-printed JSON document
 * on every checkpoint). Every entry carries an Ed25519 signature
 * by the device identity key over
 * "QDP1/journal/v1" || checkpoint_hash || seq (see DepinCore).
 *
 * Why: in v0.3 the journal was unauthenticated plaintext and the
 * app signed whatever it contained at export time, so anyone (or
 * any process) that could rewrite the journal file obtained the
 * identity's genuine signature over a forged history at the next
 * export. Now each entry is authenticated when written and
 * re-verified when read:
 *  - on load, every entry's signature is verified against the
 *    journal's device public key, its checkpoint hash is
 *    recomputed from its fields, and the prev-hash linkage and seq
 *    order are checked. The first entry that fails ANY check is
 *    dropped together with everything after it (a chain with a
 *    hole in the middle cannot vouch for its tail), the file is
 *    rewritten with the accepted prefix only, and the number of
 *    dropped entries is surfaced via droppedOnLoad() so the UI can
 *    say so instead of failing silently.
 *  - signing/verification go through the EntrySigner /
 *    EntryVerifier interfaces so this class stays free of Android
 *    types (and of raw seed material): the Android side supplies
 *    implementations backed by the Keystore-wrapped vault, the JVM
 *    harness supplies test-key ones.
 *  - partial writes (R-M04): an append interrupted mid-line (a
 *    kill between write and sync) leaves a tail line with no
 *    terminating newline. Before ANY parsing or appending, both
 *    the live journal and an archive file are truncated back to
 *    just after their last newline, and the truncation is counted
 *    in partialTailDropped(). Without this, the next append glued
 *    a fresh entry onto the partial line ("}{"), and the load
 *    after that dropped the merged line AND everything written
 *    after it — intact records lost to a recovery bug, not to any
 *    inconsistency of their own.
 *
 * Legacy entries NEVER live in this journal (v0.2.1 fix,
 * generalized in v0.3.0). A legacy entry's checkpoint hash
 * verifies only under its own format domain (v0.4 or v0.3), and a
 * bundle exported from a journal containing one can never pass
 * current-format verification — the export self-check failed
 * closed forever and no new history could be exported either.
 * Legacy entries are therefore preserved in a SEPARATE archive
 * file per format (ARCHIVE_V04_FILE_NAME / ARCHIVE_FILE_NAME,
 * next to the journal): same signed-JSONL shape, entries keep
 * their original seq / prev linkage / entry_sig, and the archives
 * are append-only and never deleted by this class. Two paths move
 * entries there:
 *  - Migration: a pre-v0.4 journal (single pretty-printed JSON
 *    document, unsigned entries, v0.3 checkpoint hashes) is
 *    detected by content. The prefix whose internal consistency
 *    holds (seq order, prev-hash linkage, checkpoint hash
 *    recomputing under the v0.3 domain, increasing timestamps) is
 *    re-signed and written to the v0.3 archive; everything from
 *    the first inconsistency on is dropped and counted in
 *    droppedOnLoad(). The live journal starts EMPTY.
 *  - Load defence: in a JSONL journal, entries at the head whose
 *    hash verifies under a legacy domain only (v0.4 first, then
 *    v0.3 — e.g. a journal written by the previous app version,
 *    whose live acceptance was that format) are moved to the
 *    matching archive the same way, provided their own legacy
 *    chain (seq, linkage, entry signature) is intact. The head
 *    prefix must be ONE legacy format; a format switch mid-prefix
 *    is an inconsistency and falls under the drop rule. Live
 *    acceptance is CURRENT-domain ONLY: a legacy or invalid entry
 *    appearing after current entries — including a current entry
 *    whose seq / prev anchor pointed into the archived prefix,
 *    since its hashes bind that anchor and it cannot be re-based
 *    — falls under the normal drop rule above.
 * After either path the live journal is empty or current-only, so
 * the next checkpoint starts a fresh current chain at seq 0 with
 * zero prev values (see nextPrevState / nextPrevCheckpointHash).
 * archivedV04Count() / archivedV03Count() report how many entries
 * each archive holds so the UI can say they are kept, distinctly
 * from droppedOnLoad().
 *
 * Header recovery (adversarial battery B4-F1 / B4-F2): the header
 * line itself is NOT authenticated — it cannot be, it is what
 * names the key the entries authenticate against — and before
 * this fix it was a single point of failure. A damaged header
 * (deleted, swapped with an entry line, bit-flipped) made load()
 * throw IllegalStateException out of the store, and corruption
 * inside the header's device_id bytes made a device load its own
 * journal as a FOREIGN identity: every entry failed verification
 * against the garbled key and bindIdentity then refused the real
 * one. The entries were intact; only the unauthenticated label
 * was broken, and there was no recovery path.
 *
 * The store is therefore now constructed with the EXPECTED
 * identity (deviceId + pubkey, as the runtime derives them from
 * the SeedVault — the vault, not the file, is the authority on
 * who this device is). On load:
 *  - no file, or a 0-byte / whitespace-only file: a fresh journal
 *    under the expected identity. NOT a recovery event.
 *  - a header that parses and matches the expected identity:
 *    entries load exactly as before.
 *  - a header that is missing, unparseable, not a header line, or
 *    names a different identity (including a foreign device's
 *    journal restored onto this device): the damaged file is
 *    QUARANTINED — renamed, bytes preserved exactly, to
 *    journal-corrupt-<yyyyMMdd-HHmmss>.jsonl next to the journal
 *    — and a fresh journal starts under the expected identity.
 *    The quarantined history is not silently deleted; it is
 *    recoverable by hand, and quarantinedFiles() /
 *    recoveryOccurred() surface it to the UI. The same rule
 *    covers a legacy (pre-v0.4) document whose device_id names a
 *    different device.
 *  - archive files carry the same header shape (see
 *    archiveHeaderMap); a damaged archive header is quarantined
 *    the same way (<name>.corrupt-<timestamp>) BEFORE any
 *    migration append can touch the file, its count reads as 0,
 *    and archiveRecoveryOccurred() flags it. Archive reading
 *    otherwise stays tolerant: the count path never throws.
 * Load never throws for file-content reasons; the only remaining
 * throws are genuine I/O failures (an unreadable file, or a
 * damaged file that cannot even be moved aside — destroying it
 * silently is the one outcome worse than failing loudly).
 *
 * v0.7 hardening (re-audit of v0.6):
 *  - M-06: the journal is read STREAMING, line by line, with a
 *    per-line cap (MAX_LINE_BYTES); the whole file is never
 *    materialized at once (a production journal can hold 100k
 *    entries). The JSON parser's own depth cap (Json.MAX_DEPTH)
 *    makes deeply nested input an ordinary parse failure, and
 *    load() additionally routes any StackOverflowError to
 *    quarantine as a backstop, so hostile content cannot wedge
 *    every future launch. (The one whole-content read left is
 *    the legacy single-document path, bounded by
 *    MAX_LEGACY_DOC_BYTES: that format is a single JSON document
 *    by construction and has been unwritten since v0.3.)
 *  - M-04: when the partial-tail truncation empties the file —
 *    the file was exactly one complete header line with no
 *    trailing newline — headerWritten is reset, so the next
 *    append rebuilds a valid header instead of gluing entries
 *    onto a headerless file that the next load would quarantine
 *    wholesale.
 *  - M-05: migration dedup trusts an archive entry ONLY when it
 *    fully verifies (see archiveVerifiedHashes). The lenient
 *    hash-string scan remains for the display count, but it no
 *    longer decides that a genuine record is "already preserved".
 *  - M-02: preserveCurrentSegment() sets the recorded segment
 *    aside (bytes exact, journal-segment-<timestamp>.jsonl) and
 *    restarts the store empty, for the service's poisoned-tail
 *    recovery (see SegmentPolicy in RpcClient.java).
 *    [WITHDRAWN in v0.8 — see below.]
 *
 * v0.8 hardening (re-audit of v0.7):
 *  - M-02 (asymmetric recovery): the poisoned-tail preservation
 *    above is REMOVED. The v0.7 re-audit showed the trigger
 *    could be inverted — a fake low RPC view (best=1, three
 *    times) healed the baseline downward and then "preserved"
 *    the device's GENUINE history out of the live journal.
 *    Recovery is now asymmetric by design: recorded, signed
 *    history is never set aside on RPC disagreement;
 *    disagreement only HOLDS appends, and the defences moved to
 *    the intake side (segment-start streak and the recorded-tail
 *    advance cap — see SegmentPolicy in RpcClient.java). The
 *    hold state persists in a sidecar (journal-hold.json, see
 *    setHold / holdInfo) so the notice survives process
 *    restarts; the sidecar is informational only — a damaged
 *    one is deleted, never quarantined, and never blocks the
 *    journal. The identity/format quarantine above (B4) is
 *    untouched: it never consults RPC.
 *  - M-03 (append retry safety): appends write from a
 *    known-good tail offset (goodTailOffset). Bytes beyond it —
 *    the remnant of an interrupted append in this same process —
 *    are truncated before the next append can glue onto them; a
 *    failed write is cut back to the offset before the failure
 *    propagates; and an fsync failure discards the in-memory
 *    state and rebuilds it from disk (reloadFromDisk) before
 *    the failure propagates, so memory and disk cannot disagree
 *    about whether the entry exists.
 *  - M-04 (defence in depth): append() itself refuses a
 *    checkpoint whose best_block_number is lower than the
 *    recorded tail's, so a stale-generation write that somehow
 *    reaches the store cannot record a backwards chain. (The
 *    service-level generation guard is ServiceGeneration in
 *    RpcClient.java.)
 *  - L-03 (archive headers): an archive header must VERIFY —
 *    device_id AND pubkey naming the expected identity — both
 *    in the construction-time sweep (a missing device_id is no
 *    longer tolerated, and the pubkey is now checked) and at
 *    every migration write: appendToArchive quarantines an
 *    archive whose header does not verify and starts a fresh
 *    one, rather than writing genuine entries under it.
 *
 * v0.9 hardening (fifth review of v0.8):
 *  - F-04 (archive tail repair): appendToArchive recorded the
 *    archive's header existence from the PRE-repair file and
 *    then truncated its partial tail — but an archive holding
 *    only an unterminated header line is truncated to EMPTY
 *    (it has no newline to cut back to), so the migrated
 *    entries landed headerless under a stale hasHeader and the
 *    next load's sweep quarantined the archive as
 *    header-damaged, taking the migrated history out of the
 *    normal path. The header state is now re-derived from the
 *    post-repair file whenever the repair changed the file.
 *  - F-05 (one checkpoint cap): append had no count cap while
 *    the reload path (Checkpoint.fromMap) accepts seq only up
 *    to DepinCore.MAX_CHECKPOINTS, so a record at seq MAX+1
 *    was written, dropped on the next load, and deleted from
 *    disk by the post-drop rewrite. Append now refuses
 *    seq > MAX_CHECKPOINTS — the one constant governs both
 *    sides — so anything append ever wrote reloads losslessly,
 *    and reaching the cap surfaces as a refusal instead of a
 *    silent loss.
 *  - F-09 (atomic generation gate): the generation overload of
 *    append re-verifies the caller's service generation UNDER
 *    the store lock at write time (see the method), closing
 *    the check-then-act gap between the service's isCurrent
 *    test and the write itself.
 *
 * The process-wide singleton lives in CompanionRuntime (the
 * Android side) so in-memory chain state can never diverge between
 * the Activity and the Service.
 */
final class JournalStore {
    static final String FILE_NAME = "journal.json";
    /** Sidecar archive for pre-v0.4 (v0.3-domain) entries. Never
     *  mixed into the live journal, never deleted by this class. */
    static final String ARCHIVE_FILE_NAME = "journal-archive-v0.3.jsonl";
    /** Sidecar archive for v0.4-domain entries (the live format
     *  of app v0.2.x). Same rules as the v0.3 archive. */
    static final String ARCHIVE_V04_FILE_NAME = "journal-archive-v0.4.jsonl";
    private static final String FORMAT = "quantus-depin-journal";
    /** Per-line input cap for journal / archive reading (M-06):
     *  a genuine header or entry line is at most a few tens of KB
     *  (a checkpoint carrying the maximum 512 witnesses); 1 MiB
     *  is generous headroom, and a longer line is corruption by
     *  definition here. */
    private static final int MAX_LINE_BYTES = 1024 * 1024;
    /** Total cap for the legacy single-document format (M-06):
     *  that document is one JSON value by construction, so it
     *  cannot be streamed as lines; 64 MiB is far beyond anything
     *  the v0.3-era app could have written on a device. */
    private static final int MAX_LEGACY_DOC_BYTES = 64 * 1024 * 1024;

    /** Signs one entry: (checkpointHash, seq) -> 64-byte signature. */
    interface EntrySigner {
        byte[] signEntry(byte[] checkpointHash, long seq);
    }

    /** Verifies one entry against the journal's device public key. */
    interface EntryVerifier {
        boolean verifyEntry(byte[] checkpointHash, long seq, byte[] signature);
    }

    /** Sidecar file (next to the journal) persisting the
     *  accumulation-hold state (M-02, v0.8). */
    static final String HOLD_FILE_NAME = "journal-hold.json";

    /** Snapshot of a persisted accumulation hold: the recorded
     *  tail the live view disagrees with, the latest disagreeing
     *  live best, and when the hold began (the observation
     *  timestamps, unix seconds). Immutable. */
    static final class HoldInfo {
        final long tailBest;
        final long tailTimestamp;
        final long liveBest;
        final long sinceUnix;
        final long updatedUnix;

        HoldInfo(long tailBest, long tailTimestamp, long liveBest,
                 long sinceUnix, long updatedUnix) {
            this.tailBest = tailBest;
            this.tailTimestamp = tailTimestamp;
            this.liveBest = liveBest;
            this.sinceUnix = sinceUnix;
            this.updatedUnix = updatedUnix;
        }
    }

    private final File file;
    private final String expectedDeviceId;
    private final String expectedPubkeyHex;
    private final EntrySigner signer;
    private final EntryVerifier verifier;
    private final List<DepinCore.Checkpoint> checkpoints = new ArrayList<>();
    private final List<byte[]> entrySigs = new ArrayList<>();
    private String deviceId;
    private String pubkeyHex;
    private int droppedOnLoad = 0;
    private int archivedOnLoadV04 = 0;
    private int archivedOnLoadV03 = 0;
    private int archivedTotalV04 = 0;
    private int archivedTotalV03 = 0;
    private int partialTailDropped = 0;
    private boolean headerWritten = false;
    /** Files quarantined during this load (B4): the live journal
     *  and/or damaged archives, bytes preserved. Empty when the
     *  load was entirely healthy. */
    private final List<File> quarantinedFiles = new ArrayList<>();
    private File quarantinedJournal = null;
    private boolean archiveRecovery = false;
    /** Byte offset just past the last complete, synced journal
     *  line — the known-good tail (M-03). Appends write from
     *  exactly this offset; anything beyond it on disk is the
     *  remnant of an interrupted write and is cut back before a
     *  further append, in the SAME process. Established by
     *  load() / reloadFromDisk(), advanced by appendLine(),
     *  reset by rewriteAll(). */
    private long goodTailOffset = 0;
    /** The persisted accumulation hold (M-02, v0.8), or null
     *  when appends are not being held. Mirrored to the
     *  journal-hold.json sidecar so the notice survives process
     *  restarts; see setHold / loadHold. */
    private HoldInfo hold = null;

    /** The durability sync of one append, behind an interface
     *  so the harness can simulate an fsync failure (M-03). */
    interface Fsync {
        void sync(FileOutputStream out) throws java.io.IOException;
    }

    private static final Fsync DEFAULT_FSYNC = out -> out.getFD().sync();
    private Fsync fsync = DEFAULT_FSYNC;

    /** Test seam (harness only): substitute the fsync of
     *  appends; null restores the production implementation. */
    void setFsyncForTest(Fsync f) {
        this.fsync = (f == null) ? DEFAULT_FSYNC : f;
    }

    JournalStore(File file, String expectedDeviceId,
                 String expectedPubkeyHex, EntrySigner signer,
                 EntryVerifier verifier) {
        this.file = file;
        this.expectedDeviceId = expectedDeviceId;
        this.expectedPubkeyHex = expectedPubkeyHex;
        this.signer = signer;
        this.verifier = verifier;
        // The expected identity is bound from construction: the
        // vault is the authority, never the file (B4-F2).
        this.deviceId = expectedDeviceId;
        this.pubkeyHex = expectedPubkeyHex;
        // Quarantine damaged archive headers BEFORE load() can
        // append migration entries to one of the archive files.
        quarantineDamagedArchives();
        load();
        archivedTotalV04 = countArchiveEntries(DepinCore.FMT_V04);
        archivedTotalV03 = countArchiveEntries(DepinCore.FMT_V03);
        // Restore a persisted accumulation hold (M-02, v0.8)
        // whose recorded tail still matches, so the held notice
        // survives process restarts.
        loadHold();
    }

    /** For the JVM harness: a journal over an explicit file with
     *  explicit (test-key) authentication and expected identity. */
    static JournalStore forFile(File file, String expectedDeviceId,
                                String expectedPubkeyHex,
                                EntrySigner signer,
                                EntryVerifier verifier) {
        return new JournalStore(file, expectedDeviceId,
                expectedPubkeyHex, signer, verifier);
    }

    /** Entries dropped during the most recent load (tampered,
     *  forged, or inconsistent tail). Surfaced in the UI. */
    synchronized int droppedOnLoad() {
        return droppedOnLoad;
    }

    /** Legacy entries moved to an archive during the most recent
     *  load (migration or load defence), both formats combined. */
    synchronized int archivedOnLoad() {
        return archivedOnLoadV04 + archivedOnLoadV03;
    }

    /** v0.4-format entries moved to their archive on this load. */
    synchronized int archivedOnLoadV04() {
        return archivedOnLoadV04;
    }

    /** v0.3-format entries moved to their archive on this load. */
    synchronized int archivedOnLoadV03() {
        return archivedOnLoadV03;
    }

    /** Total legacy entries currently preserved in the archive
     *  files, both formats combined. Surfaced in the UI, distinctly
     *  from droppedOnLoad(): archived entries are kept, not
     *  discarded. */
    synchronized int archivedCount() {
        return archivedTotalV04 + archivedTotalV03;
    }

    /** Entries preserved in the v0.4 archive file. */
    synchronized int archivedV04Count() {
        return archivedTotalV04;
    }

    /** Entries preserved in the v0.3 archive file. */
    synchronized int archivedV03Count() {
        return archivedTotalV03;
    }

    /** Partial (unterminated) tail lines truncated on open before
     *  parsing or appending (R-M04): 1 when the journal file ended
     *  mid-line — the remnant of an interrupted append — else 0.
     *  The partial line is by construction not a complete entry,
     *  so nothing verifiable is lost; the count exists so the UI
     *  can surface that a truncation happened at all. */
    synchronized int partialTailDropped() {
        return partialTailDropped;
    }

    /** True when this load quarantined anything (the live journal
     *  and/or an archive) because its header was damaged or named
     *  a different identity (B4). The UI surfaces this: a recovery
     *  must never be silent, even though nothing was deleted. */
    synchronized boolean recoveryOccurred() {
        return !quarantinedFiles.isEmpty();
    }

    /** True when an archive file's damaged header was quarantined
     *  during this load (its count therefore reads as 0). */
    synchronized boolean archiveRecoveryOccurred() {
        return archiveRecovery;
    }

    /** The quarantined live-journal file (original bytes
     *  preserved), or null when the live journal was healthy. */
    synchronized File quarantinedFile() {
        return quarantinedJournal;
    }

    /** Every file quarantined during this load — the live journal
     *  and/or damaged archives — in the order they were set aside. */
    synchronized List<File> quarantinedFiles() {
        return new ArrayList<>(quarantinedFiles);
    }

    /** The persisted accumulation hold (M-02, v0.8), or null
     *  when appends are not being held. The UI surfaces this:
     *  while the live RPC view disagrees with the recorded tail,
     *  accumulation is held — never destructive — and the notice
     *  must survive process restarts, which is why the state is
     *  mirrored to the journal-hold.json sidecar (see setHold). */
    synchronized HoldInfo holdInfo() {
        return hold;
    }

    // ---------------- loading ----------------

    /**
     * Truncate a JSONL file's partial tail (R-M04): when the file
     * is non-empty and does not end with '\n', its last line is
     * the remnant of an interrupted append and is cut back to just
     * after the previous newline (or to empty when there is no
     * complete line at all). Returns 1 when a truncation happened,
     * else 0. Reads backwards in chunks so even a long journal
     * costs one tail scan, not a full copy.
     */
    private static int truncatePartialTail(File f) {
        try {
            if (!f.exists() || f.length() == 0) {
                return 0;
            }
            try (java.io.RandomAccessFile raf =
                         new java.io.RandomAccessFile(f, "rw")) {
                long len = raf.length();
                raf.seek(len - 1);
                if (raf.read() == '\n') {
                    return 0;
                }
                long cut = 0;
                final int chunk = 8192;
                byte[] buf = new byte[chunk];
                long pos = len;
                scan:
                while (pos > 0) {
                    int n = (int) Math.min(chunk, pos);
                    pos -= n;
                    raf.seek(pos);
                    raf.readFully(buf, 0, n);
                    for (int i = n - 1; i >= 0; i--) {
                        if (buf[i] == (byte) '\n') {
                            cut = pos + i + 1;
                            break scan;
                        }
                    }
                }
                raf.setLength(cut);
                return 1;
            }
        } catch (Exception e) {
            throw new IllegalStateException(
                    "could not repair journal tail: " + f.getName(), e);
        }
    }

    private void load() {
        if (!file.exists()) {
            goodTailOffset = 0;
            return;
        }
        reloadFromDisk();
    }

    /** (Re)build the in-memory journal state from the file on
     *  disk, exactly as construction does — including the M-06
     *  StackOverflowError backstop, which quarantines the file
     *  and leaves a fresh store. Used by load() and by the M-03
     *  sync-failure recovery in appendLine: after an fsync
     *  failure the in-memory state can no longer be trusted to
     *  match the disk (the entry's bytes may or may not be
     *  durable), so it is discarded wholesale and rebuilt from
     *  what the disk actually holds before anything proceeds.
     *  On return, goodTailOffset is the file's true length (0
     *  when the journal was quarantined or never existed). */
    private void reloadFromDisk() {
        // The state is rebuilt FROM NOTHING: on a live store the
        // in-memory chain may hold entries the disk does not (or
        // miss ones it does), and loadInternal appends what it
        // accepts onto the current lists. (At construction the
        // lists are empty anyway, so this is a no-op there.)
        resetInMemoryState();
        try {
            loadInternal();
        } catch (StackOverflowError e) {
            // M-06 backstop: pathological content (deeply nested
            // JSON in some line) must route to quarantine, never
            // wedge every future launch. Json.MAX_DEPTH should
            // make this unreachable — parse failures are ordinary
            // IllegalArgumentExceptions — but the audit asked for
            // the store-level guarantee as well, and an Error
            // escaping load() is exactly what B4 set out to
            // eliminate. Any partially accepted state is dropped:
            // the file is set aside whole and the journal starts
            // fresh under the expected identity.
            resetInMemoryState();
            quarantineLiveJournal();
        }
        goodTailOffset = file.exists() ? file.length() : 0;
    }

    /** Drop all in-memory state accepted so far in this load.
     *  Used when the load itself is abandoned for quarantine. */
    private void resetInMemoryState() {
        checkpoints.clear();
        entrySigs.clear();
        droppedOnLoad = 0;
        archivedOnLoadV04 = 0;
        archivedOnLoadV03 = 0;
        partialTailDropped = 0;
        headerWritten = false;
    }

    /**
     * Streaming line reader with a per-line byte cap (M-06).
     * Lines are returned without their terminator; a line longer
     * than MAX_LINE_BYTES is consumed to its end but returned
     * truncated, with lastLineOverflow() set — the cap bounds the
     * memory any single line can demand, and such a line is
     * unparseable corruption to every caller anyway.
     */
    private static final class LineReader implements AutoCloseable {
        private final java.io.BufferedInputStream in;
        private final java.io.ByteArrayOutputStream buf =
                new java.io.ByteArrayOutputStream();
        private boolean lastOverflow = false;
        private boolean eof = false;

        LineReader(File f) throws java.io.IOException {
            this.in = new java.io.BufferedInputStream(
                    new FileInputStream(f));
        }

        boolean lastLineOverflow() {
            return lastOverflow;
        }

        /** The next line, or null at end of file. */
        String nextLine() throws java.io.IOException {
            if (eof) {
                return null;
            }
            buf.reset();
            lastOverflow = false;
            boolean any = false;
            while (true) {
                int b = in.read();
                if (b < 0) {
                    eof = true;
                    break;
                }
                any = true;
                if (b == (byte) '\n') {
                    break;
                }
                if (buf.size() < MAX_LINE_BYTES) {
                    buf.write(b);
                } else {
                    lastOverflow = true;
                }
            }
            if (!any) {
                return null; // clean EOF: nothing was read
            }
            return new String(buf.toByteArray(), StandardCharsets.UTF_8);
        }

        @Override
        public void close() throws java.io.IOException {
            in.close();
        }
    }

    /** Feed every line of a file to a consumer until it returns
     *  false. Tolerant by design (archive reading must never
     *  wedge the load): a missing or unreadable file simply
     *  delivers no lines. */
    private interface LineConsumer {
        boolean onLine(String line, boolean overflow);
    }

    private static void forEachLine(File f, LineConsumer consumer) {
        if (!f.exists()) {
            return;
        }
        try (LineReader lr = new LineReader(f)) {
            String line;
            while ((line = lr.nextLine()) != null) {
                if (!consumer.onLine(line, lr.lastLineOverflow())) {
                    break;
                }
            }
        } catch (Exception ignored) {
            // Tolerant archive path; see archiveHashesPresent.
        }
    }

    private void loadInternal() {
        final String firstLine;
        final boolean firstOverflow;
        Map<String, Object> legacyDoc = null;
        boolean legacyDecided = false;
        try (LineReader lr = new LineReader(file)) {
            String found = null;
            boolean foundOverflow = false;
            String line;
            while ((line = lr.nextLine()) != null) {
                boolean ov = lr.lastLineOverflow();
                if (line.trim().isEmpty() && !ov) {
                    continue; // blank lines carry nothing
                }
                found = line;
                foundOverflow = ov;
                break;
            }
            firstLine = found;
            firstOverflow = foundOverflow;
            if (firstLine == null) {
                return; // empty / whitespace only: a fresh journal,
                        // not a recovery (B4)
            }
            if (firstOverflow) {
                // A first line beyond the cap cannot be a header
                // and cannot start a legacy document (that is
                // exactly "{"), so the file is damaged.
                quarantineLiveJournal();
                return;
            }
            Map<String, Object> firstObj = null;
            try {
                firstObj = Json.parseObject(firstLine);
            } catch (RuntimeException e) {
                firstObj = null;
            }
            if (firstObj != null && firstObj.containsKey("checkpoints")) {
                // A legacy document written on ONE line.
                legacyDoc = firstObj;
                legacyDecided = true;
            } else if (firstObj == null && firstLine.trim().equals("{")) {
                // Legacy candidate: the pre-v0.4 journal is ONE
                // pretty-printed JSON object, whose first line is
                // exactly "{". Accumulate the remainder under the
                // document cap; anything else that starts this way
                // but does not parse into a legacy document is
                // damaged and quarantines.
                StringBuilder doc = new StringBuilder(firstLine);
                long total = firstLine.length();
                boolean tooBig = false;
                while ((line = lr.nextLine()) != null) {
                    total += line.length() + 1L;
                    if (lr.lastLineOverflow()
                            || total > MAX_LEGACY_DOC_BYTES) {
                        tooBig = true;
                        break;
                    }
                    doc.append('\n').append(line);
                }
                if (tooBig) {
                    quarantineLiveJournal();
                    return;
                }
                try {
                    Map<String, Object> root =
                            Json.parseObject(doc.toString());
                    if (root.containsKey("checkpoints")) {
                        legacyDoc = root;
                    }
                } catch (RuntimeException ignored) {
                    // Not a legacy document after all.
                }
                if (legacyDoc == null) {
                    quarantineLiveJournal();
                    return;
                }
                legacyDecided = true;
            }
            if (!legacyDecided) {
                // JSONL path: the first line is the header
                // candidate. It must parse, be a header, and name
                // the EXPECTED identity (B4). Any other outcome —
                // header deleted, an entry line swapped into its
                // place, bit damage inside it, a foreign journal
                // — quarantines the whole file (bytes preserved)
                // and starts a fresh journal, instead of throwing
                // out of the load or adopting a garbled identity.
                Map<String, Object> header = firstObj;
                Object d = (header == null) ? null : header.get("device_id");
                Object p = (header == null) ? null : header.get("pubkey");
                if (header == null || !"header".equals(header.get("type"))
                        || !expectedDeviceId.equals(d)
                        || !expectedPubkeyHex.equals(p)) {
                    quarantineLiveJournal();
                    return;
                }
            }
        } catch (java.io.IOException e) {
            // An I/O failure, not file content: the one load
            // failure that still throws (the runtime surfaces it).
            throw new IllegalStateException(
                    "checkpoint journal is unreadable", e);
        }
        if (legacyDecided) {
            handleLegacyDocument(legacyDoc);
            return;
        }
        headerWritten = true;
        // R-M04: repair an interrupted final append. This runs
        // only AFTER the header has validated, so a file on its
        // way to quarantine keeps its exact original bytes (the
        // truncation previously ran before any parsing and would
        // have silently rewritten the damaged file first).
        partialTailDropped = truncatePartialTail(file);
        if (file.length() == 0) {
            // M-04: the file was exactly one complete header line
            // with NO trailing newline, and the truncation cut it
            // as the remnant of an interrupted write. The header
            // carries no unique data — identity comes from the
            // vault — so the journal is simply fresh; what must
            // NOT survive is headerWritten == true, which made
            // the next append glue entry lines onto a headerless
            // file that the NEXT load then quarantined wholesale,
            // valid post-recovery history included.
            headerWritten = false;
            return;
        }
        // Stream the entries from a fresh reader over the (now
        // repaired) file, stepping past the header line first.
        try (LineReader lr = new LineReader(file)) {
            String line;
            while ((line = lr.nextLine()) != null) {
                if (line.trim().isEmpty() && !lr.lastLineOverflow()) {
                    continue;
                }
                break; // the validated header line
            }
            loadJsonlEntries(lr);
        } catch (java.io.IOException e) {
            throw new IllegalStateException(
                    "checkpoint journal is unreadable", e);
        }
    }

    /** A legacy (pre-v0.4) document: a foreign one quarantines
     *  whole (B4); an own one migrates, with content-shaped
     *  migration failures also falling back to quarantine (the
     *  original document is still intact on disk at that point:
     *  migration writes go to the archive and a tmp file first). */
    private void handleLegacyDocument(Map<String, Object> legacy) {
        Object d = legacy.get("device_id");
        if (d instanceof String && !expectedDeviceId.equals(d)) {
            quarantineLiveJournal();
            return;
        }
        try {
            migrateLegacy(legacy);
        } catch (IllegalStateException e) {
            quarantineLiveJournal();
        }
    }

    private static byte[] readAllBytes(File f) throws Exception {
        try (FileInputStream in = new FileInputStream(f)) {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int n;
            while ((n = in.read(chunk)) >= 0) {
                out.write(chunk, 0, n);
            }
            return out.toByteArray();
        }
    }

    /** Process the entry lines after a validated header. Runs the
     *  load-defence / acceptance state machine exactly as before;
     *  only the line supply changed (streaming, capped — M-06). */
    private void loadJsonlEntries(LineReader lr) throws java.io.IOException {
        byte[] lastHash = DepinCore.ZERO32;
        // Load defence state: a legacy (v0.4- or v0.3-domain)
        // prefix at the head of the file is archived, not accepted
        // live. The prefix must be ONE legacy format and form its
        // own intact chain (seq from 0, prev linkage, entry
        // signatures). Classification tries the newer legacy
        // format (v0.4) first, per DepinCore.legacyProfileOf.
        boolean headPhase = true;
        DepinCore.FormatProfile legacyFmt = null;
        byte[] lastLegacyHash = DepinCore.ZERO32;
        long legacySeq = 0;
        List<DepinCore.Checkpoint> arcCps = new ArrayList<>();
        List<byte[]> arcSigs = new ArrayList<>();
        boolean dropped = false;
        String rawLine;
        while ((rawLine = lr.nextLine()) != null) {
            boolean overflow = lr.lastLineOverflow();
            String line = rawLine.trim();
            if (line.isEmpty() && !overflow) continue;
            if (dropped) {
                droppedOnLoad++;
                continue;
            }
            // An over-cap line cannot be a well-formed entry
            // (M-06): it takes the ordinary drop path.
            Object[] parsed = overflow ? null : parseEntryLine(line);
            if (parsed == null) {
                dropped = true;
                droppedOnLoad++;
                continue;
            }
            DepinCore.Checkpoint cp = (DepinCore.Checkpoint) parsed[0];
            byte[] sig = (byte[]) parsed[1];
            boolean current = Arrays.equals(
                    DepinCore.checkpointHash(DepinCore.CURRENT, cp), cp.checkpointHash);
            DepinCore.FormatProfile legacy =
                    current ? null : DepinCore.legacyProfileOf(cp);
            if (headPhase && legacy != null
                    && (legacyFmt == null || legacyFmt == legacy)) {
                boolean legacyIntact = cp.seq == legacySeq
                        && Arrays.equals(cp.prevCheckpointHash, lastLegacyHash)
                        && verifier.verifyEntry(cp.checkpointHash, cp.seq, sig);
                if (legacyIntact) {
                    legacyFmt = legacy;
                    arcCps.add(cp);
                    arcSigs.add(sig);
                    legacySeq++;
                    lastLegacyHash = cp.checkpointHash;
                    continue;
                }
                // A broken legacy head is not archived; it falls
                // under the same drop rule as any inconsistency.
                dropped = true;
                droppedOnLoad++;
                continue;
            }
            headPhase = false;
            if (!acceptEntry(cp, sig, lastHash, current)) {
                dropped = true;
                droppedOnLoad++;
                continue;
            }
            lastHash = cp.checkpointHash;
        }
        if (!arcCps.isEmpty()) {
            // Archive FIRST (it is the only copy of these entries),
            // then rewrite the live file without them.
            appendToArchive(legacyFmt, arcCps, arcSigs);
            if (legacyFmt == DepinCore.FMT_V04) {
                archivedOnLoadV04 = arcCps.size();
            } else {
                archivedOnLoadV03 = arcCps.size();
            }
        }
        if (dropped || !arcCps.isEmpty()) {
            // Persist the accepted live prefix so the corruption /
            // legacy prefix does not have to be re-processed (and
            // re-dropped / re-archived) forever.
            rewriteAll();
        }
    }

    // ---------------- header recovery (B4) ----------------

    private static String quarantineTimestamp() {
        return new java.text.SimpleDateFormat("yyyyMMdd-HHmmss",
                java.util.Locale.US).format(new java.util.Date());
    }

    /** Move a file aside without altering its bytes: rename, or
     *  (across filesystems) copy-then-delete. False when the file
     *  could not be moved at all — its bytes then stay exactly
     *  where they were, never half-destroyed. */
    private static boolean movePreserving(File src, File dest) {
        if (src.renameTo(dest)) {
            return true;
        }
        try {
            byte[] bytes = readAllBytes(src);
            try (FileOutputStream out = new FileOutputStream(dest)) {
                out.write(bytes);
                out.getFD().sync();
            }
            if (src.delete()) {
                return true;
            }
            // Copy exists but the original would not go away:
            // remove the copy rather than leave two diverging
            // versions of the same history.
            //noinspection ResultOfMethodCallIgnored
            dest.delete();
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /** Quarantine the live journal (B4): rename it, bytes exact,
     *  to journal-corrupt-<timestamp>.jsonl (-1, -2... on name
     *  collisions). The store is left as a fresh journal under the
     *  expected identity: nothing has been accepted yet when this
     *  runs, and the identity fields were bound at construction.
     *  Throws only when the damaged file cannot even be moved —
     *  silently overwriting an unrecoverable history would be
     *  worse than failing loudly (the runtime surfaces it). */
    private void quarantineLiveJournal() {
        String base = "journal-corrupt-" + quarantineTimestamp();
        File dest = new File(file.getParentFile(), base + ".jsonl");
        int n = 1;
        while (dest.exists()) {
            dest = new File(file.getParentFile(),
                    base + "-" + (n++) + ".jsonl");
        }
        if (!movePreserving(file, dest)) {
            throw new IllegalStateException(
                    "could not quarantine damaged journal: " + file.getName());
        }
        quarantinedJournal = dest;
        quarantinedFiles.add(dest);
        headerWritten = false;
        // A hold recorded against the quarantined tail is stale
        // the moment the tail leaves (v0.8): drop the sidecar
        // with it, so no phantom hold notice outlives the
        // history it referred to.
        hold = null;
        File hf = holdFile();
        if (hf.exists()) {
            //noinspection ResultOfMethodCallIgnored
            hf.delete();
        }
    }

    // ---------------- accumulation hold (M-02, v0.8) ----------------

    private File holdFile() {
        return new File(file.getParentFile(), HOLD_FILE_NAME);
    }

    /** Record (or refresh) the accumulation hold: the live RPC
     *  view disagrees with the recorded tail, so appends are
     *  being held — never destructively resolved. The state is
     *  mirrored to the journal-hold.json sidecar (tmp + rename +
     *  sync) so the notice survives process restarts; the
     *  recorded tail is captured from the journal itself, so the
     *  sidecar can never claim a hold against a tail that does
     *  not exist. The first-set time is kept across refreshes
     *  against the same tail. Persistence is best-effort: the
     *  hold is a notice, not the data, and failing to write it
     *  must never fail an observation round — the in-memory hold
     *  still drives this process. No-op when the journal is
     *  empty (there is no recorded tail to disagree with). */
    synchronized void setHold(long liveBest, long nowUnix) {
        DepinCore.Checkpoint tail = last();
        if (tail == null) {
            return;
        }
        long since = (hold != null
                && hold.tailBest == tail.bestBlockNumber
                && hold.tailTimestamp == tail.timestampUnix)
                ? hold.sinceUnix : nowUnix;
        hold = new HoldInfo(tail.bestBlockNumber, tail.timestampUnix,
                liveBest, since, nowUnix);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", "journal_hold");
        m.put("tail_best", tail.bestBlockNumber);
        m.put("tail_timestamp", tail.timestampUnix);
        m.put("live_best", liveBest);
        m.put("since_unix", since);
        m.put("updated_unix", nowUnix);
        File hf = holdFile();
        File tmp = new File(hf.getParentFile(), hf.getName() + ".tmp");
        try {
            try (FileOutputStream out = new FileOutputStream(tmp)) {
                out.write((Json.canonical(m) + "\n")
                        .getBytes(StandardCharsets.UTF_8));
                out.getFD().sync();
            }
            if (!tmp.renameTo(hf)) {
                //noinspection ResultOfMethodCallIgnored
                tmp.delete();
            }
        } catch (Exception ignored) {
            // Best effort by design; see the doc above.
        }
    }

    /** Clear the hold (the live view caught up and an append
     *  landed): memory and sidecar together. */
    synchronized void clearHold() {
        hold = null;
        File hf = holdFile();
        if (hf.exists()) {
            //noinspection ResultOfMethodCallIgnored
            hf.delete();
        }
    }

    /** Restore the persisted hold at construction. The hold is
     *  honoured only when it names the CURRENT recorded tail
     *  exactly (best and timestamp): a hold whose tail has since
     *  moved on — appended past, dropped, or quarantined — is
     *  stale and is discarded. A damaged sidecar is likewise
     *  deleted and ignored: it is a notice, never a reason to
     *  quarantine, block, or otherwise touch the journal. */
    private void loadHold() {
        File hf = holdFile();
        if (!hf.exists()) {
            return;
        }
        try {
            String text = new String(readAllBytes(hf),
                    StandardCharsets.UTF_8);
            Map<String, Object> m = Json.parseObject(text.trim());
            long tailBest = Json.asLong(m.get("tail_best"));
            long tailTs = Json.asLong(m.get("tail_timestamp"));
            long liveBest = Json.asLong(m.get("live_best"));
            long since = Json.asLong(m.get("since_unix"));
            long updated = Json.asLong(m.get("updated_unix"));
            DepinCore.Checkpoint tail = last();
            if (tail == null || tail.bestBlockNumber != tailBest
                    || tail.timestampUnix != tailTs) {
                // Stale: the recorded tail it referred to is gone.
                //noinspection ResultOfMethodCallIgnored
                hf.delete();
                return;
            }
            hold = new HoldInfo(tailBest, tailTs, liveBest, since, updated);
        } catch (Exception e) {
            //noinspection ResultOfMethodCallIgnored
            hf.delete();
            hold = null;
        }
    }

    // ---------------- archive header quarantine (B4 / L-03) ----------------

    /** Quarantine one archive file whose header does not verify:
     *  rename it, bytes exact, to <name>.corrupt-<yyyyMMdd-HHmmss>
     *  (-1, -2... on collisions) and flag the recovery. Returns
     *  the quarantined file, or null when the file could not be
     *  moved — in which case it stays in place and NOTHING may be
     *  written to it either: the migration write that needed it
     *  aborts instead of appending under an unverified header
     *  (L-03). Never throws. */
    private File quarantineArchiveFile(DepinCore.FormatProfile fmt) {
        File af = archiveFile(fmt);
        String base = af.getName() + ".corrupt-" + quarantineTimestamp();
        File dest = new File(af.getParentFile(), base);
        int n = 1;
        while (dest.exists()) {
            dest = new File(af.getParentFile(), base + "-" + (n++));
        }
        if (!movePreserving(af, dest)) {
            return null;
        }
        quarantinedFiles.add(dest);
        archiveRecovery = true;
        return dest;
    }

    /** Validate both archive files' headers before load() can
     *  append anything to them, quarantining the ones that do
     *  not verify. Archives DO carry the same header shape as
     *  the live journal (see archiveHeaderMap). Since v0.8
     *  (L-03) a header verifies only when it names the expected
     *  device_id AND the expected pubkey: before, a missing
     *  device_id was tolerated and the pubkey was never checked.
     *  An unreadable file is still left alone — archive reading
     *  must never wedge the load. */
    private void quarantineDamagedArchives() {
        for (DepinCore.FormatProfile fmt
                : new DepinCore.FormatProfile[]{
                        DepinCore.FMT_V04, DepinCore.FMT_V03}) {
            if (archiveHeaderDamaged(archiveFile(fmt))) {
                quarantineArchiveFile(fmt);
            }
            // When the move fails the damaged archive stays in
            // place; the tolerant count path reads what parses,
            // and appendToArchive refuses to write under it
            // (L-03) rather than repairing by appending.
        }
    }

    /** True when an archive's first real line is not a VERIFIED
     *  header for this device: unparseable, not a header line, a
     *  different device_id, or a missing / different pubkey
     *  (L-03). Only the first non-empty line is examined
     *  (streaming — M-06); a missing, empty or unreadable file
     *  delivers no verdict here and is not "damaged" — it simply
     *  has no header to write under yet. */
    private boolean archiveHeaderDamaged(File af) {
        if (!af.exists() || af.length() == 0) {
            return false;
        }
        final boolean[] damaged = new boolean[1];
        forEachLine(af, (rawLine, overflow) -> {
            String line = rawLine.trim();
            if (line.isEmpty() && !overflow) {
                return true; // keep looking for the first real line
            }
            if (overflow) {
                damaged[0] = true;
                return false;
            }
            final Map<String, Object> m;
            try {
                m = Json.parseObject(line);
            } catch (RuntimeException e) {
                damaged[0] = true;
                return false;
            }
            damaged[0] = !"header".equals(m.get("type"))
                    || !expectedDeviceId.equals(m.get("device_id"))
                    || !expectedPubkeyHex.equals(m.get("pubkey"));
            return false;
        });
        return damaged[0];
    }

    /** Parse one JSONL entry line into {checkpoint, entry_sig},
     *  or null when the line is not a well-formed signed entry. */
    private Object[] parseEntryLine(String line) {
        try {
            Map<String, Object> entry = Json.parseObject(line);
            Object sigObj = entry.get("entry_sig");
            if (!(sigObj instanceof String)) return null;
            byte[] sig = Hex.decodeCanonical((String) sigObj);
            if (sig.length != 64) return null;
            Map<String, Object> cpMap = new LinkedHashMap<>(entry);
            cpMap.remove("entry_sig");
            DepinCore.Checkpoint cp = DepinCore.Checkpoint.fromMap(cpMap);
            return new Object[]{cp, sig};
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Verify one entry against the accepted LIVE prefix. Live
     *  acceptance is current-domain only (see the class doc): a
     *  legacy-domain entry here is rejected like any other
     *  inconsistency. Appends the entry when every check holds. */
    private boolean acceptEntry(DepinCore.Checkpoint cp, byte[] sig,
                                byte[] lastHash, boolean hashCurrent) {
        if (cp.seq != checkpoints.size()) return false;
        if (!Arrays.equals(cp.prevCheckpointHash, lastHash)) return false;
        if (!hashCurrent) return false;
        if (!verifier.verifyEntry(cp.checkpointHash, cp.seq, sig)) return false;
        checkpoints.add(cp);
        entrySigs.add(sig);
        return true;
    }

    // ---------------- legacy migration ----------------

    private void migrateLegacy(Map<String, Object> root) {
        // The identity fields are NOT adopted from the document:
        // they were bound to the expected identity at construction
        // (load() has already quarantined a document naming a
        // different device), and the archive header written below
        // must name this device, not whatever the file claims.
        final List<Object> raw;
        try {
            raw = Json.asArray(root.get("checkpoints"));
        } catch (RuntimeException e) {
            throw new IllegalStateException(
                    "legacy checkpoint journal is unreadable", e);
        }
        // The internally consistent prefix goes to the ARCHIVE
        // (re-signed under the journal signature scheme), never
        // into the live journal: its checkpoint hashes are
        // v0.3-domain and would poison every current-format export.
        List<DepinCore.Checkpoint> arcCps = new ArrayList<>();
        List<byte[]> arcSigs = new ArrayList<>();
        byte[] lastHash = DepinCore.ZERO32;
        long lastTs = Long.MIN_VALUE;
        for (Object o : raw) {
            DepinCore.Checkpoint cp = null;
            try {
                cp = DepinCore.Checkpoint.fromMap(Json.asObject(o));
            } catch (RuntimeException ignored) {
                // Falls through as an inconsistency: drop the tail.
            }
            boolean consistent = cp != null
                    && cp.seq == arcCps.size()
                    && Arrays.equals(cp.prevCheckpointHash, lastHash)
                    && cp.timestampUnix > lastTs
                    && Arrays.equals(
                            DepinCore.checkpointHashV03(cp), cp.checkpointHash);
            if (!consistent) {
                droppedOnLoad += raw.size() - arcCps.size();
                break;
            }
            arcCps.add(cp);
            arcSigs.add(signer.signEntry(cp.checkpointHash, cp.seq));
            lastHash = cp.checkpointHash;
            lastTs = cp.timestampUnix;
        }
        if (!arcCps.isEmpty()) {
            // The pretty-printed document format existed only in
            // the v0.3 era, so its entries archive under v0.3.
            appendToArchive(DepinCore.FMT_V03, arcCps, arcSigs);
            archivedOnLoadV03 = arcCps.size();
        }
        headerWritten = false; // force a JSONL rewrite below
        rewriteAll();
    }

    // ---------------- archive ----------------

    private File archiveFile(DepinCore.FormatProfile fmt) {
        String name = (fmt == DepinCore.FMT_V04)
                ? ARCHIVE_V04_FILE_NAME : ARCHIVE_FILE_NAME;
        return new File(file.getParentFile(), name);
    }

    private Map<String, Object> archiveHeaderMap(DepinCore.FormatProfile fmt) {
        Map<String, Object> h = new LinkedHashMap<>();
        h.put("type", "header");
        h.put("format", FORMAT);
        h.put("version", fmt.version);
        h.put("device_id", deviceId);
        h.put("pubkey", pubkeyHex);
        return h;
    }

    /** Checkpoint hashes (hex) named by the lines of one
     *  archive, plus whether it has a header line. LENIENT by
     *  design: malformed lines are ignored, and a line counts by
     *  carrying a checkpoint_hash string, verified or not. This
     *  feeds the DISPLAY count (archivedV04Count and kin) only.
     *  Since v0.7 it must NOT decide that an entry is preserved —
     *  M-05 showed a two-line fake archive (a header and a bare
     *  {"checkpoint_hash": H} line) making migration skip the
     *  genuine record H, whose only real copy was then rewritten
     *  away. Preservation decisions use archiveVerifiedHashes. */
    private Set<String> archiveHashesPresent(DepinCore.FormatProfile fmt,
                                             boolean[] hasHeaderOut) {
        Set<String> out = new HashSet<>();
        File af = archiveFile(fmt);
        if (!af.exists()) {
            return out;
        }
        forEachLine(af, (rawLine, overflow) -> {
            String line = rawLine.trim();
            if (line.isEmpty() || overflow) {
                return true;
            }
            try {
                Map<String, Object> m = Json.parseObject(line);
                if ("header".equals(m.get("type"))) {
                    hasHeaderOut[0] = true;
                } else if (m.get("checkpoint_hash") instanceof String) {
                    out.add((String) m.get("checkpoint_hash"));
                }
            } catch (RuntimeException ignored) {
                // Not a parseable line; not an entry we hold.
            }
            return true;
        });
        return out;
    }

    /** Checkpoint hashes (hex) of the entries in one archive
     *  that FULLY VERIFY (M-05): the archive header must name the
     *  expected identity AND the expected public key, and every
     *  counted entry must recompute its checkpoint hash under the
     *  archive format's domain and carry an entry_sig that
     *  verifies under this device's key. Anything less — a bare
     *  hash line, a broken signature, a foreign or inconsistent
     *  header — counts as NOT preserved, so migration re-copies
     *  the genuine record. The failure direction is deliberate:
     *  doubt duplicates an archive line; it never loses the only
     *  genuine copy. */
    private Set<String> archiveVerifiedHashes(DepinCore.FormatProfile fmt) {
        Set<String> out = new HashSet<>();
        File af = archiveFile(fmt);
        if (!af.exists()) {
            return out;
        }
        final boolean[] headerSeen = new boolean[1];
        final boolean[] headerOk = new boolean[1];
        forEachLine(af, (rawLine, overflow) -> {
            String line = rawLine.trim();
            if (line.isEmpty() && !overflow) {
                return true;
            }
            if (!headerSeen[0]) {
                headerSeen[0] = true;
                if (overflow) {
                    return false;
                }
                try {
                    Map<String, Object> h = Json.parseObject(line);
                    headerOk[0] = "header".equals(h.get("type"))
                            && expectedDeviceId.equals(h.get("device_id"))
                            && expectedPubkeyHex.equals(h.get("pubkey"));
                } catch (RuntimeException e) {
                    headerOk[0] = false;
                }
                return headerOk[0];
            }
            if (overflow) {
                return true; // not a verifiable entry; keep scanning
            }
            Object[] parsed = parseEntryLine(line);
            if (parsed == null) {
                return true;
            }
            DepinCore.Checkpoint cp = (DepinCore.Checkpoint) parsed[0];
            byte[] sig = (byte[]) parsed[1];
            byte[] recomputed = (fmt == DepinCore.FMT_V04)
                    ? DepinCore.checkpointHashV04(cp)
                    : DepinCore.checkpointHashV03(cp);
            if (Arrays.equals(recomputed, cp.checkpointHash)
                    && verifier.verifyEntry(cp.checkpointHash, cp.seq, sig)) {
                out.add(Hex.encode(cp.checkpointHash));
            }
            return true;
        });
        return headerOk[0] ? out : new HashSet<>();
    }

    private int countArchiveEntries(DepinCore.FormatProfile fmt) {
        return archiveHashesPresent(fmt, new boolean[1]).size();
    }

    /** Append entries to one format's archive file (creating it,
     *  with its header, on first use). Entries already preserved
     *  are skipped, so a crash between archiving and the live
     *  rewrite cannot duplicate them on the next load — where
     *  "preserved" means FULLY VERIFIED in the archive (M-05, see
     *  archiveVerifiedHashes), never merely named by a hash
     *  string. The archive's own partial tail is truncated
     *  first (R-M04), so an interrupted earlier archive append
     *  cannot glue the new entries onto its remnant; beyond that
     *  repair the archive is never truncated or deleted here.
     *
     *  L-03 (v0.8): the write goes under a VERIFIED header only.
     *  A header LINE existing used to be enough — its device_id
     *  and pubkey were never checked on this path — so genuine
     *  entries could be migrated under a header that does not
     *  bind them to this device's identity. Now an existing
     *  header that does not verify is quarantined FIRST and the
     *  migration proceeds into a fresh archive under a header
     *  this store wrote itself; if the file cannot even be moved
     *  aside, the write aborts (the load then quarantines the
     *  source journal instead, so the originals survive either
     *  way) rather than appending under the bad header. */
    private void appendToArchive(DepinCore.FormatProfile fmt,
                                 List<DepinCore.Checkpoint> cps,
                                 List<byte[]> sigs) {
        File af = archiveFile(fmt);
        boolean[] hasHeader = new boolean[1];
        archiveHashesPresent(fmt, hasHeader); // header existence only
        if (hasHeader[0] && archiveHeaderDamaged(af)) {
            if (quarantineArchiveFile(fmt) == null) {
                throw new IllegalStateException(
                        "archive header does not verify and the file "
                                + "could not be quarantined: " + af.getName());
            }
            hasHeader[0] = false; // fresh archive, header written below
        }
        if (truncatePartialTail(af) != 0) {
            // F-04 (v0.9): the repair may have removed the very
            // header whose existence was recorded above — an
            // archive holding ONLY an unterminated header line
            // is truncated to empty, there being no newline to
            // cut back to — leaving hasHeader stale: the
            // migrated entries then landed headerless, and the
            // next load's sweep quarantined the archive as
            // header-damaged, taking the migrated history out
            // of the normal path. Re-derive the header state
            // from the post-repair file. (When the truncation
            // removed only a partial ENTRY, the header still
            // reads as present and nothing changes.)
            hasHeader[0] = false;
            archiveHashesPresent(fmt, hasHeader);
        }
        Set<String> present = archiveVerifiedHashes(fmt);
        StringBuilder sb = new StringBuilder();
        if (!hasHeader[0]) {
            sb.append(Json.canonical(archiveHeaderMap(fmt))).append('\n');
        }
        for (int i = 0; i < cps.size(); i++) {
            if (!present.add(Hex.encode(cps.get(i).checkpointHash))) {
                continue; // already archived
            }
            sb.append(entryLine(cps.get(i), sigs.get(i))).append('\n');
        }
        if (sb.length() == 0) {
            return;
        }
        try (FileOutputStream out = new FileOutputStream(af, true)) {
            out.write(sb.toString().getBytes(StandardCharsets.UTF_8));
            out.getFD().sync();
        } catch (Exception e) {
            throw new IllegalStateException("could not write journal archive", e);
        }
    }

    // ---------------- writing ----------------

    private Map<String, Object> headerMap() {
        Map<String, Object> h = new LinkedHashMap<>();
        h.put("type", "header");
        h.put("format", FORMAT);
        h.put("version", DepinCore.VERSION);
        h.put("device_id", deviceId);
        h.put("pubkey", pubkeyHex);
        return h;
    }

    private static String entryLine(DepinCore.Checkpoint c, byte[] sig) {
        Map<String, Object> m = c.toMap();
        m.put("entry_sig", Hex.encode(sig));
        return Json.canonical(m);
    }

    /** Full rewrite (header + all entries) via tmp + rename. Used
     *  for migration, post-drop cleanup and identity binding —
     *  never on the per-checkpoint path. */
    private void rewriteAll() {
        StringBuilder sb = new StringBuilder();
        sb.append(Json.canonical(headerMap())).append('\n');
        for (int i = 0; i < checkpoints.size(); i++) {
            sb.append(entryLine(checkpoints.get(i), entrySigs.get(i))).append('\n');
        }
        File tmp = new File(file.getParentFile(), file.getName() + ".tmp");
        try {
            try (FileOutputStream out = new FileOutputStream(tmp)) {
                out.write(sb.toString().getBytes(StandardCharsets.UTF_8));
                out.getFD().sync();
            }
            if (!tmp.renameTo(file)) {
                throw new IllegalStateException("journal rename failed");
            }
            headerWritten = true;
            goodTailOffset = file.length();
        } catch (Exception e) {
            throw new IllegalStateException("could not persist journal", e);
        }
    }

    /** Truncate a file to exactly len bytes. */
    private static void truncateFileTo(File f, long len) {
        try (java.io.RandomAccessFile raf =
                     new java.io.RandomAccessFile(f, "rw")) {
            raf.setLength(len);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "could not truncate journal file: " + f.getName(), e);
        }
    }

    /** Append ONE signed entry line from the known-good tail
     *  offset (M-03). The normal per-checkpoint path: O(1)
     *  instead of the v0.3 full-document rewrite.
     *
     *  Before writing, the file is checked against
     *  goodTailOffset. A previous append in THIS process may
     *  have died between write() and sync() — process kill,
     *  power loss the OS survived, a failed fsync — leaving
     *  partial bytes beyond the offset while the entry never
     *  entered the in-memory chain. The load-time repair (R-M04)
     *  only runs at the NEXT launch; appending blindly in this
     *  process would glue the new line onto that remnant ("}{"),
     *  and the load after that would drop the merged line AND
     *  every entry written after it. So bytes beyond the offset
     *  are truncated back first. A file SHORTER than the offset
     *  means synced content vanished underneath the store, which
     *  no local repair can reason about: the state is rebuilt
     *  from disk and this append aborts (the service retries on
     *  the next round).
     *
     *  Failure handling mirrors the same rule. When the WRITE
     *  fails, the file is cut back to the offset before the
     *  failure propagates, so the remnant cannot poison a later
     *  append. When SYNC fails, the complete line is already in
     *  the file but its durability is unknown: the in-memory
     *  state is discarded and rebuilt from the disk truth
     *  (reloadFromDisk) before the failure propagates, so memory
     *  and disk can never disagree about whether the entry
     *  exists. */
    private void appendLine(DepinCore.Checkpoint c, byte[] sig) {
        byte[] lineBytes = (entryLine(c, sig) + "\n")
                .getBytes(StandardCharsets.UTF_8);
        long onDisk = file.length();
        if (onDisk > goodTailOffset) {
            truncateFileTo(file, goodTailOffset);
        } else if (onDisk < goodTailOffset) {
            reloadFromDisk();
            throw new IllegalStateException(
                    "journal file shrank beneath its synced tail; "
                            + "state rebuilt from disk, append aborted");
        }
        boolean written = false;
        try (FileOutputStream out = new FileOutputStream(file, true)) {
            out.write(lineBytes);
            written = true;
            fsync.sync(out);
        } catch (Exception e) {
            if (!written) {
                try {
                    truncateFileTo(file, goodTailOffset);
                } catch (RuntimeException ignored) {
                    // The load-time repair (R-M04) remains as
                    // the backstop for a remnant that survives.
                }
            } else {
                reloadFromDisk();
            }
            throw new IllegalStateException("could not append to journal", e);
        }
        goodTailOffset += lineBytes.length;
    }

    // ---------------- public operations ----------------

    /** Confirm the journal's identity binding and make sure the
     *  header is on disk (first use). The identity itself is fixed
     *  at construction (the expected identity from the vault);
     *  this call exists so the service states the identity it
     *  derived independently and any disagreement — a programming
     *  error, never file content, since load() quarantines foreign
     *  journals — is caught instead of mixing two identities into
     *  one chain. */
    synchronized void bindIdentity(String deviceId, String pubkeyHex) {
        if (!this.deviceId.equals(deviceId)
                || !this.pubkeyHex.equals(pubkeyHex)) {
            throw new IllegalStateException(
                    "journal belongs to a different device identity");
        }
        if (!headerWritten) {
            rewriteAll();
        }
    }

    /** Append without a generation expectation (tools and the
     *  JVM harness; the service uses the generation overload). */
    synchronized void append(DepinCore.Checkpoint c) {
        appendInternal(c);
    }

    /**
     * Append for the observation service, gated on the service
     * generation (F-09, v0.9). The service has always CHECKED
     * ServiceGeneration.isCurrent(gen) before appending, but
     * the check and the write were two separate steps: a stop
     * (requestStop) and a restart (beginNewGeneration) landing
     * between them still let the stale tick's checkpoint into
     * the new generation's journal session. Here the generation
     * is re-verified UNDER the store lock, as part of the write
     * itself: a generation captured before the stop can never
     * pass this gate afterwards, however the steps interleave.
     * Refusal is an IllegalStateException; nothing is written.
     */
    synchronized void append(DepinCore.Checkpoint c,
                             long expectedGeneration) {
        if (!ServiceGeneration.PROCESS.isCurrent(expectedGeneration)) {
            throw new IllegalStateException(
                    "stale service generation " + expectedGeneration
                            + ": append refused");
        }
        appendInternal(c);
    }

    /** The append itself; called only from the two synchronized
     *  appends above, so it always runs under the store lock. */
    private void appendInternal(DepinCore.Checkpoint c) {
        if (c.seq > DepinCore.MAX_CHECKPOINTS) {
            // F-05 (v0.9): ONE cap governs both sides of the
            // journal. Checkpoint.fromMap — the reload path —
            // accepts seq only up to MAX_CHECKPOINTS; append
            // previously had no cap at all, so a record at
            // seq MAX+1 was written, dropped by the next load,
            // and deleted from disk by the post-drop rewrite.
            // Refuse here instead: anything append ever wrote
            // reloads losslessly, and reaching the cap surfaces
            // (the service reports the failure) rather than
            // silently losing a stored record.
            throw new IllegalStateException(
                    "checkpoint seq " + c.seq
                            + " exceeds the journal cap "
                            + DepinCore.MAX_CHECKPOINTS
                            + " (the largest seq the reload path accepts)");
        }
        long expectedSeq = checkpoints.size();
        if (c.seq != expectedSeq) {
            throw new IllegalStateException(
                    "checkpoint seq " + c.seq + " != journal length " + expectedSeq);
        }
        if (!checkpoints.isEmpty()) {
            DepinCore.Checkpoint last = checkpoints.get(checkpoints.size() - 1);
            if (!Arrays.equals(c.prevCheckpointHash, last.checkpointHash)) {
                throw new IllegalStateException("checkpoint does not extend the journal");
            }
            if (c.timestampUnix <= last.timestampUnix) {
                throw new IllegalStateException("checkpoint timestamp not increasing");
            }
            if (c.bestBlockNumber < last.bestBlockNumber) {
                // Defence in depth (M-04, v0.8): the service
                // holds regressions, so a checkpoint arriving
                // here with a best below the recorded tail is a
                // stale-generation write or a bug — refuse it
                // rather than record a chain whose best runs
                // backwards. Equality stays legal: the format
                // requires best to be non-decreasing only.
                throw new IllegalStateException(
                        "checkpoint best block number regresses below the recorded tail");
            }
        }
        byte[] sig = signer.signEntry(c.checkpointHash, c.seq);
        if (sig == null || sig.length != 64) {
            throw new IllegalStateException("journal entry signer returned a bad signature");
        }
        if (!headerWritten) {
            // First write ever: lay down header + this entry in one
            // full write rather than appending to a headerless file.
            checkpoints.add(c);
            entrySigs.add(sig);
            try {
                rewriteAll();
            } catch (RuntimeException e) {
                // Keep memory and disk in step (M-03): the entry
                // did not reach the file, so it must not stay in
                // the in-memory chain either.
                checkpoints.remove(checkpoints.size() - 1);
                entrySigs.remove(entrySigs.size() - 1);
                throw e;
            }
            return;
        }
        appendLine(c, sig);
        checkpoints.add(c);
        entrySigs.add(sig);
    }

    synchronized List<DepinCore.Checkpoint> checkpoints() {
        return new ArrayList<>(checkpoints);
    }

    synchronized int count() {
        return checkpoints.size();
    }

    synchronized DepinCore.Checkpoint last() {
        return checkpoints.isEmpty() ? null : checkpoints.get(checkpoints.size() - 1);
    }

    synchronized byte[] nextPrevState() {
        DepinCore.Checkpoint last = last();
        return last == null ? DepinCore.ZERO32.clone() : last.chainState.clone();
    }

    synchronized byte[] nextPrevCheckpointHash() {
        DepinCore.Checkpoint last = last();
        return last == null ? DepinCore.ZERO32.clone() : last.checkpointHash.clone();
    }
}
