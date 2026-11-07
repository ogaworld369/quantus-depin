package app.quantusnode.depin;

import android.content.Context;

import java.io.File;
import java.util.Arrays;

/**
 * Process-wide shared objects (Android side): the one JournalStore
 * instance the Activity and the Service both use, so in-memory
 * chain state can never diverge between them. Mirrors the bench
 * app's session-holder pattern.
 *
 * The journal's entry authentication (v0.4, audit H-04) is wired
 * here: the signer unwraps the identity seed via the Keystore
 * vault for each append, signs, and zeroes + locks the working
 * copy immediately (L-01); the verifier needs only the device
 * public key, captured once at construction.
 *
 * The store is constructed with the identity derived HERE, from
 * the vault (B4): the vault is the authority on who this device
 * is, so a damaged or foreign journal file can no longer dictate
 * — or garble — the identity it is read under.
 *
 * Store construction itself is additionally wrapped (B4): the
 * store no longer throws for file content (damaged journals are
 * quarantined and recovered inside it), so what can still fail
 * here is genuine I/O trouble. Such a failure is caught once,
 * persisted to the error log, mirrored into
 * CompanionStatus.journalError for the UI / service, and the same
 * IllegalStateException is rethrown to every caller — no retry
 * loop, no repeated log spam from the 2-second UI refresh, and
 * no silent null for a caller to trip over later.
 *
 * Construction is ASYNCHRONOUS since v0.7 (re-audit M-07): the
 * load reads and re-verifies every journal entry's signature, so
 * its cost grows with the accumulated history, and both previous
 * construction sites ran on the main thread (Activity.onCreate's
 * touch, Service.onCreate) — a long history froze the UI and
 * delayed the foreground transition on every restart. Now
 * prefetchJournal() starts construction once, on a dedicated
 * background thread; journal() (for background callers: the
 * service executor, the export threads) waits on the readiness
 * latch; journalIfReady() (for the UI) returns null while
 * preparation is in flight so the Activity can show a preparing
 * state instead of blocking.
 */
final class CompanionRuntime {
    private CompanionRuntime() {}

    private static volatile JournalStore journal;
    private static volatile IllegalStateException journalFailure;
    private static final java.util.concurrent.CountDownLatch journalLatch =
            new java.util.concurrent.CountDownLatch(1);
    private static boolean journalInitStarted = false;

    /** Start journal construction on a background thread (once).
     *  Safe to call from the main thread: it never blocks. */
    static synchronized void prefetchJournal(Context context) {
        if (journalInitStarted) {
            return;
        }
        journalInitStarted = true;
        final Context appContext = context.getApplicationContext();
        Thread t = new Thread(() -> buildJournal(appContext),
                "depin-journal-init");
        t.setDaemon(true);
        t.start();
    }

    /** True once construction has finished, successfully or not. */
    static boolean journalReady() {
        return journalLatch.getCount() == 0;
    }

    /** The constructed store, or null while preparation is in
     *  flight (or after a failure — distinguish via
     *  journalFailure() / CompanionStatus). For the UI thread,
     *  which must never block on history-length work (M-07). */
    static JournalStore journalIfReady() {
        return journal;
    }

    /** The construction failure every blocking caller receives,
     *  or null when construction succeeded or is still running. */
    static IllegalStateException journalFailure() {
        return journalFailure;
    }

    /** The store for background callers: starts construction if
     *  needed and waits for it. Throws the cached failure, as
     *  before — no retry loop, no repeated logging. */
    static JournalStore journal(Context context) {
        prefetchJournal(context);
        try {
            journalLatch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(
                    "interrupted while waiting for the journal", e);
        }
        if (journalFailure != null) {
            throw journalFailure;
        }
        return journal;
    }

    private static void buildJournal(Context context) {
        try {
            buildJournalOrThrow(context);
        } catch (IllegalStateException e) {
            journalFailure = e;
        } finally {
            journalLatch.countDown();
        }
    }

    private static void buildJournalOrThrow(Context context) {
        AndroidSeedVault vault = new AndroidSeedVault(context);
        final byte[] pubkey;
        try {
            pubkey = vault.publicKey();
        } catch (Exception e) {
            // The identity stage failed, not the journal: mirror
            // it into the identity-error channel so the UI names
            // the real cause, as the pre-M-07 code did.
            CompanionStatus.identityError =
                    e.getClass().getSimpleName() + ": " + e.getMessage();
            throw new IllegalStateException(
                    "identity unavailable for journal authentication", e);
        } finally {
            // The journal only needs the public key long-term.
            // lock() is the vault's wipe hook; since R-L01 the
            // vault holds no plaintext cache for it to wipe.
            vault.lock();
        }
        JournalStore.EntrySigner signer = (checkpointHash, seq) -> {
            final byte[] seed;
            try {
                seed = vault.loadOrCreateSeed();
            } catch (Exception e) {
                throw new IllegalStateException(
                        "identity unavailable for journal signing", e);
            }
            try {
                return DepinCore.journalEntrySig(seed, checkpointHash, seq);
            } finally {
                // Zero the working copy: the seed is
                // re-unwrapped per append (one checkpoint per
                // 600 s slot, so the cost is irrelevant)
                // instead of resting in memory (L-01 / R-L01).
                Arrays.fill(seed, (byte) 0);
                vault.lock();
            }
        };
        JournalStore.EntryVerifier verifier =
                (checkpointHash, seq, sig) -> DepinCore.verifyJournalEntrySig(
                        pubkey, checkpointHash, seq, sig);
        try {
            journal = new JournalStore(
                    new File(context.getFilesDir(), JournalStore.FILE_NAME),
                    DepinCore.deviceIdFromPubkey(pubkey),
                    Hex.encode(pubkey),
                    signer, verifier);
        } catch (Throwable t) {
            CompanionStatus.journalError =
                    t.getClass().getSimpleName() + ": " + t.getMessage();
            recordError(context, "journal_open", t);
            throw new IllegalStateException(
                    "journal unavailable: "
                            + t.getClass().getSimpleName()
                            + ": " + t.getMessage(), t);
        }
    }

    // ---------------- persistent error log ----------------

    /** Record a failure durably; never throws. */
    static void recordError(Context context, String kind, Throwable t) {
        try {
            CrashLog.record(context.getFilesDir(), kind, t);
        } catch (Throwable ignored) {
            // Diagnostics must never take the app down with them.
        }
    }

    /** Full persisted error log text, or null when empty. */
    static String errorLog(Context context) {
        try {
            return CrashLog.readAll(context.getFilesDir());
        } catch (Throwable ignored) {
            return null;
        }
    }

    /** The most recent persisted error entry, or null. */
    static String lastErrorEntry(Context context) {
        return CrashLog.lastEntry(errorLog(context));
    }
}
