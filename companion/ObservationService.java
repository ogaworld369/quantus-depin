package app.quantusnode.depin;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * The observation loop. While running, it wakes every 30 seconds
 * and checks whether the current fixed 600-second slot already has
 * a checkpoint; if not, it tries to observe the node once. Each
 * attempt is a short burst (a handful of loopback RPC reads, then
 * one sequential-chain computation), so the service itself is idle
 * almost all of the time and adds negligible load to the node it
 * observes — the companion must never become a burden on the thing
 * it measures.
 *
 * Honesty rules enforced here:
 *  - a slot whose observation fails (node down, RPC unreachable,
 *    state moved mid-round) gets NO checkpoint. The gap stays a gap.
 *  - a reorg/desync that moves best backwards also produces no
 *    checkpoint (the format requires non-decreasing best).
 *  - timestamps come from the device clock at observation time;
 *    nothing is backdated or interpolated.
 *
 * v0.7 changes (re-audit of v0.6):
 *  - M-07: identity / journal initialization runs on the
 *    service's executor thread, after the foreground transition —
 *    loading and re-verifying a long journal is history-length
 *    work and no longer blocks onCreate (which delayed the
 *    foreground call and froze startup on every restart).
 *  - M-02: SegmentPolicy is wired in. A fresh segment records
 *    its first checkpoint only after 2 consecutive plausible
 *    readings, and a recorded tail implausibly far above the
 *    healed baseline is preserved as its own segment file while
 *    a new segment starts — a poisoned first response can no
 *    longer wedge accumulation forever.
 *    [The preservation half is WITHDRAWN in v0.8 — see below.]
 *
 * v0.8 changes (re-audit of v0.7):
 *  - M-02 (asymmetric recovery): the poisoned-tail preservation
 *    is REMOVED — the re-audit showed a fake LOW view could
 *    invert it and evict genuine history. Recorded, signed
 *    history is now never set aside on RPC disagreement:
 *    disagreement only HOLDS appends (regressions, and readings
 *    beyond the recorded-tail advance cap), the hold state is
 *    persisted by the journal (JournalStore.setHold) so the
 *    notice survives restarts, and appending resumes by itself
 *    when the live view catches up. The intake-side defences
 *    stay and grow: the segment-start streak, plus the new
 *    advance cap (SegmentPolicy.tailAdvanceAllowed) bounding
 *    how far a checkpoint may run ahead of the recorded tail.
 *  - M-04 (stop/start race): each tick captures the process
 *    service generation (ServiceGeneration) at its start and
 *    re-checks it immediately before appending; onDestroy
 *    requests the stop (flag + generation advance) BEFORE
 *    shutting the executor down, and a restarted service begins
 *    a new generation. A stale tick's append can therefore
 *    never land in a new generation's journal session. The
 *    journal's own best-monotonicity refusal is the backstop.
 *
 * v0.9 changes (fifth review of v0.8):
 *  - F-09: the M-04 guard was check-then-act — the service
 *    tested the generation, then appended as a separate step,
 *    so a stop+restart landing between the two still let a
 *    stale tick write once. The append now goes through
 *    JournalStore's generation overload, which re-verifies
 *    the captured generation under the store lock at write
 *    time; the service's own check stays as the quiet
 *    early-out, and a refusal that still slips through the
 *    gap is retired quietly when the generation is stale.
 *  - F-11: the segment-start streak ("2 CONSECUTIVE plausible
 *    readings") was not reset when a round failed as
 *    INCONSISTENT — the fetch threw before plausibility ever
 *    ran, and the catch returned without noteRejected(), so
 *    good -> inconsistent -> good still opened a segment on
 *    the second good reading. Every round that produces no
 *    accepted reading now breaks the streak: the inconsistent
 *    path, and the transport-failure path with the same shape
 *    (a malformed or unreachable round is not an accepted
 *    reading either; resetting costs at most one extra round
 *    before a fresh segment's first checkpoint).
 */
public class ObservationService extends Service {
    static final String ACTION_START = "app.quantusnode.depin.action.START";
    static final String ACTION_STOP = "app.quantusnode.depin.action.STOP";

    private static final String CHANNEL_ID = "depin_observation";
    private static final int NOTIFICATION_ID = 4203;
    private static final long TICK_SECONDS = 30;

    private ScheduledExecutorService scheduler;
    private RpcClient rpc;
    private JournalStore journal;
    private AndroidSeedVault vault;
    private byte[] pubkey;
    private boolean identityReady = false;
    /** Plausibility baseline for accepted observations (R-M03),
     *  seeded from the journal tail during background init so the
     *  jump / regression rules bind across restarts, not just
     *  within one service lifetime. */
    private ObservationPlausibility plausibility;
    /** Segment-start streak / recorded-tail advance cap
     *  (M-02, redesigned in v0.8). */
    private final SegmentPolicy segmentPolicy = new SegmentPolicy();

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        // M-07: onCreate does NO history-length work. The journal
        // construction (a full read + per-entry signature
        // verification of the accumulated history) starts here on
        // the runtime's background thread, and the identity setup
        // completes later, on this service's own executor (see
        // initThenSchedule) — after the foreground transition.
        // Before v0.7 all of it ran synchronously below, on the
        // main thread, so every restart's startup cost grew with
        // the journal.
        rpc = new RpcClient(RpcClient.DEFAULT_ENDPOINT);
        CompanionRuntime.prefetchJournal(this);
    }

    /** Identity + journal initialization, run on the service
     *  executor thread (M-07). Blocks on the runtime's readiness
     *  latch when journal construction is still in flight — that
     *  is exactly what this background thread is for. On success
     *  the tick loop is scheduled; on failure the failure is
     *  surfaced (notification + status) and the service stops,
     *  from a foreground state, as a normal shutdown. */
    private void initThenSchedule() {
        // Catch Throwable, not just Exception: vault / journal
        // construction sits inside the same guard, and any failure
        // (including Errors) must be persisted — before v0.1.1 the
        // reason lived only in memory and died with the process.
        try {
            vault = new AndroidSeedVault(this);
            journal = CompanionRuntime.journal(this);
            byte[] seed = vault.loadOrCreateSeed();
            try {
                pubkey = Ed25519.publickeyFromSeed(seed);
            } finally {
                // Only the public key is needed for the service's
                // lifetime (L-01): zero the working copy at once.
                // Since the v0.5 fix round (R-L01) the vault keeps
                // no plaintext cache at all, so this copy is the
                // only one that ever exists here.
                java.util.Arrays.fill(seed, (byte) 0);
            }
            String deviceId = DepinCore.deviceIdFromPubkey(pubkey);
            journal.bindIdentity(deviceId, Hex.encode(pubkey));
            CompanionStatus.deviceId = deviceId;
            CompanionStatus.identityError = null;
            DepinCore.Checkpoint last = journal.last();
            // Seed the plausibility baseline from the persisted
            // journal tail (R-M03): the last accepted observation
            // of previous runs is the baseline of this one.
            plausibility = (last != null)
                    ? ObservationPlausibility.seededWith(
                            last.bestBlockNumber, last.timestampUnix)
                    : new ObservationPlausibility();
            if (last != null) {
                CompanionStatus.lastCheckpointUnix = last.timestampUnix;
                CompanionStatus.lastBest = last.bestBlockNumber;
                CompanionStatus.lastFinalized =
                        last.finalizedBlockNumber == null ? -1 : last.finalizedBlockNumber;
                // Checkpoint.observedPeers is a long since F-07;
                // the status field is a display int, and values
                // this app records itself pass the RPC intake
                // bound (MAX_PEERS) long before they are stored.
                CompanionStatus.lastPeers = (int) last.observedPeers;
            }
            // Surface a hold persisted by a previous process
            // (M-02, v0.8): the notice must be true from the
            // first screen after a restart, not only after the
            // next disagreeing tick.
            JournalStore.HoldInfo hold = journal.holdInfo();
            if (hold != null) {
                CompanionStatus.lastError =
                        "ノードの応答が記録済みの履歴（best " + hold.tailBest
                                + "）と食い違うためチェックポイントを保留しています"
                                + "（現在の応答 best " + hold.liveBest + "）";
            }
            identityReady = true;
        } catch (Throwable t) {
            if (scheduler == null || scheduler.isShutdown()) {
                return; // destroyed during init; nothing to surface into
            }
            // Foreground state was established in onStartCommand,
            // so stopping from here is a normal shutdown, not a
            // contract violation. Say why on the notification and
            // in the status first. A journal failure (B4) is named
            // as one: starting observation with nowhere to record
            // would fail silently otherwise.
            if (CompanionStatus.journalError != null) {
                CompanionStatus.lastError =
                        "ジャーナルを開けなかったため観測を開始できません: "
                                + CompanionStatus.journalError;
                updateNotification("観測を開始できません（ジャーナルを開けません）");
            } else {
                CompanionStatus.identityError = describe(t);
                CompanionRuntime.recordError(this, "service_init", t);
                CompanionStatus.lastError =
                        "ID鍵の準備に失敗したため観測を開始できません: "
                                + CompanionStatus.identityError;
                updateNotification("観測を開始できません（ID鍵の準備に失敗）");
            }
            CompanionStatus.startRequestedUnix = 0;
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelf();
            return;
        }
        if (scheduler == null || scheduler.isShutdown()) {
            return; // destroyed during init
        }
        CompanionStatus.serviceRunning = true;
        CompanionStatus.startRequestedUnix = 0;
        updateNotification("観測中");
        scheduler.scheduleWithFixedDelay(this::tickSafely,
                0, TICK_SECONDS, TimeUnit.SECONDS);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            CompanionStatus.startRequestedUnix = 0;
            stopSelf();
            return START_NOT_STICKY;
        }
        // startForegroundService() contract: startForeground MUST be
        // called promptly, whatever state onCreate left behind.
        // v0.1.0 stopped without it when identity init had failed
        // (the Keystore CALLER_NONCE_PROHIBITED rejection), which
        // turned a recoverable init failure into a process crash
        // (ForegroundServiceDidNotStartInTimeException, confirmed in
        // the user's system log). So: go foreground FIRST, then
        // decide whether observation can actually run.
        try {
            createNotificationChannel();
            startForegroundNow(buildNotification("観測を開始しています"));
        } catch (Throwable t) {
            CompanionRuntime.recordError(this, "start_foreground", t);
            CompanionStatus.identityError = describe(t);
            CompanionStatus.startRequestedUnix = 0;
            stopSelf();
            return START_NOT_STICKY;
        }
        if (scheduler != null) {
            return START_STICKY; // already running (or initializing)
        }
        // M-07: initialization (identity + the history-length
        // journal load) runs on the executor thread, NOT here —
        // startForeground has been called above, promptly, and
        // initThenSchedule decides from there whether observation
        // can actually run, scheduling the ticks only once the
        // identity is ready. The user-visible "starting" state is
        // CompanionStatus.startRequestedUnix, held by the Activity
        // until init resolves it one way or the other.
        // M-04: a fresh service generation begins with this
        // start; ticks captured under any earlier generation are
        // stale from here on.
        ServiceGeneration.PROCESS.beginNewGeneration();
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "depin-observer");
            t.setDaemon(true);
            return t;
        });
        scheduler.execute(this::initThenSchedule);
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        // M-04: request the stop FIRST — flag latched, generation
        // advanced — so a tick still in flight on the executor
        // sees its generation go stale and returns without
        // appending, instead of landing a write after shutdown
        // (or inside a restarted service's session).
        ServiceGeneration.PROCESS.requestStop();
        CompanionStatus.serviceRunning = false;
        if (scheduler != null) {
            scheduler.shutdownNow();
            scheduler = null;
        }
        if (vault != null) {
            // Emergency wipe hook (L-01). Since R-L01 the vault
            // holds no plaintext seed cache, so this is a no-op
            // safeguard rather than a load-bearing zeroing.
            vault.lock();
        }
        super.onDestroy();
    }

    private void tickSafely() {
        try {
            tick();
        } catch (Throwable t) {
            CompanionStatus.lastError = "内部エラー: " + t.getMessage();
            CompanionRuntime.recordError(this, "tick", t);
        }
    }

    private void startForegroundNow(Notification notification) {
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }
    }

    private static String describe(Throwable t) {
        return t.getClass().getSimpleName() + ": " + String.valueOf(t.getMessage());
    }

    private void tick() {
        if (!identityReady) {
            return;
        }
        // M-04: capture the service generation NOW; it is
        // re-checked immediately before the append, after the
        // (comparatively long) RPC round, so a stop or restart
        // that lands mid-round retires this tick quietly.
        final long gen = ServiceGeneration.PROCESS.capture();
        long now = System.currentTimeMillis() / 1000L;
        long slot = now / DepinCore.SLOT_SEC;
        DepinCore.Checkpoint last = journal.last();
        if (last != null && last.timestampUnix / DepinCore.SLOT_SEC >= slot) {
            return; // this slot already has its checkpoint
        }
        CompanionStatus.lastAttemptUnix = now;

        // One round budget covers the observation AND the peer-id
        // fetch (R-M02): the peer-id call no longer runs on its own
        // unbounded path after the round's deadline has closed.
        RpcClient.NodeObservation round;
        rpc.beginRound();
        try {
            try {
                round = rpc.fetchObservation();
            } catch (RpcClient.InconsistentObservation e) {
                // F-11: a reading WAS taken and found
                // inconsistent — that is a rejected reading, and
                // it must break the segment-start streak exactly
                // like a plausibility rejection does. This catch
                // used to return without noteRejected(), so
                // good -> inconsistent -> good still counted as
                // two consecutive good readings.
                segmentPolicy.noteRejected();
                CompanionStatus.lastError = "観測の整合性が取れず見送り: " + e.getMessage();
                return;
            } catch (RpcClient.RpcException e) {
                // Same shape (F-11): the round produced no
                // accepted reading — unreachable node, deadline,
                // malformed response — so the "consecutive"
                // streak must not silently bridge across it.
                segmentPolicy.noteRejected();
                CompanionStatus.lastError = "ノードに接続できず: " + e.getMessage();
                return;
            }
            if (CompanionStatus.nodePeerId == null) {
                try {
                    CompanionStatus.nodePeerId = rpc.fetchLocalPeerId();
                } catch (RpcClient.RpcException ignored) {
                    // Informational only; retried on a later tick.
                }
            }
        } finally {
            rpc.endRound();
        }
        DepinCore.Observation o = round.observation;

        // Plausibility against the accepted-observation baseline
        // (M-02, extended by R-M03): the loopback endpoint is
        // unauthenticated, so absurd values (finalized ahead of
        // best, a best number that jumped implausibly far, a
        // regression) are treated as a gap, never written. The
        // baseline persists across restarts (seeded from the
        // journal tail) and persistent regressions re-adopt a new
        // baseline after three rounds instead of wedging forever.
        ObservationPlausibility.Decision decision = plausibility.evaluate(o);
        if (!decision.accepted) {
            // A rejection also breaks the segment-start streak
            // (M-02a): the readings that open a segment must be
            // CONSECUTIVELY plausible.
            segmentPolicy.noteRejected();
            if (last != null && o.bestBlockNumber < last.bestBlockNumber) {
                // The live view sits below the recorded tail
                // (v0.8): accumulation is held, never resolved
                // destructively. Persist the hold so the notice
                // survives restarts.
                journal.setHold(o.bestBlockNumber, o.timestampUnix);
            }
            CompanionStatus.lastError = "観測値が異常なため見送り: " + decision.reason;
            return;
        }
        if (decision.baselineInitializing) {
            CompanionStatus.lastError =
                    "初回の観測を基準値として受理しました（比較対象の履歴がまだありません）";
        }

        if (journal.count() == 0
                && !segmentPolicy.noteAcceptedWhileSegmentEmpty()) {
            // M-02(a): a fresh segment (new journal, or one
            // emptied by quarantine) records its first checkpoint
            // only after 2 consecutive plausible readings. A
            // single poisoned first response can adopt the
            // in-memory baseline, but it cannot put a checkpoint
            // on disk by itself.
            CompanionStatus.lastError =
                    "新しいセグメントの開始を確認しています"
                            + "（連続した正常な観測が複数回必要です）";
            return;
        }

        if (last != null) {
            if (o.bestBlockNumber < last.bestBlockNumber) {
                // Reachable only via a baselineReset acceptance:
                // the observation is believed and the baseline has
                // adopted it, but the bundle format requires
                // non-decreasing best across checkpoints, so
                // writing it now would poison every future export.
                // Hold the append — and hold ONLY (v0.8): the
                // recorded history is never preserved, quarantined
                // or restarted over an RPC disagreement, however
                // large. Appends resume as soon as best reaches
                // the recorded tail again (see
                // ObservationPlausibility's class doc), and the
                // persisted hold keeps the notice honest across
                // restarts in the meantime.
                journal.setHold(o.bestBlockNumber, o.timestampUnix);
                CompanionStatus.lastError =
                        "best の基準値を再採用しましたが、記録済みの best ("
                                + last.bestBlockNumber + ") に再び達するまで"
                                + "チェックポイントを保留します: " + decision.reason;
                return;
            }
            if (!SegmentPolicy.tailAdvanceAllowed(
                    last.bestBlockNumber, last.timestampUnix,
                    o.bestBlockNumber, o.timestampUnix)) {
                // M-02(b), v0.8 advance cap (design review A4):
                // a checkpoint may run ahead of the recorded tail
                // by at most the wall time elapsed since the tail
                // was recorded, at the chain's plausible cadence —
                // cap = tail + elapsed intervals × 6,000 + 6,000.
                // Plausibility bounds a reading against the
                // in-memory baseline — which healing can move —
                // but the recorded tail cannot move, so a jump
                // beyond the cap is HELD here instead of being
                // recorded. Held, again, never destructive. (The
                // status text states the disagreement and the
                // pause only; it does not assert which side is
                // wrong.)
                journal.setHold(o.bestBlockNumber, o.timestampUnix);
                CompanionStatus.lastError =
                        "観測された best (" + o.bestBlockNumber
                                + ") と記録済みの末尾（best "
                                + last.bestBlockNumber
                                + "）の差が上限を超えているため、"
                                + "チェックポイントを保留します";
                return;
            }
            if (o.timestampUnix <= last.timestampUnix) {
                return; // clock oddity; never write a non-increasing timestamp
            }
        }

        DepinCore.Checkpoint cp = DepinCore.makeCheckpoint(
                journal.count(), o,
                journal.nextPrevState(), journal.nextPrevCheckpointHash(),
                DepinCore.PRODUCTION_ITERATIONS, pubkey);
        if (!ServiceGeneration.PROCESS.isCurrent(gen)) {
            // M-04: a stop (and possibly a restart) landed while
            // this tick's RPC round was in flight. This tick
            // belongs to a dead generation: its append must not
            // land in the live generation's journal session.
            // Return quietly — the live generation's own ticks
            // observe the following slots.
            return;
        }
        try {
            // F-09: the generation is re-verified by the store,
            // under its lock, as part of the write itself — the
            // check above is only the quiet early-out, so the
            // check-then-act gap (stop+restart landing between
            // the test and the write) can no longer admit a
            // stale checkpoint.
            journal.append(cp, gen);
        } catch (IllegalStateException e) {
            if (!ServiceGeneration.PROCESS.isCurrent(gen)) {
                // Went stale inside the gap: retire quietly,
                // exactly as the early-out above does. Any
                // other refusal is a real journal problem and
                // propagates to tickSafely, which surfaces it.
                return;
            }
            throw e;
        }
        journal.clearHold();

        CompanionStatus.lastError = null;
        CompanionStatus.lastCheckpointUnix = cp.timestampUnix;
        CompanionStatus.lastBest = cp.bestBlockNumber;
        CompanionStatus.lastFinalized =
                cp.finalizedBlockNumber == null ? -1 : cp.finalizedBlockNumber;
        CompanionStatus.lastPeers = (int) cp.observedPeers; // F-07: long -> display int
        CompanionStatus.lastSyncing = round.syncing;
        updateNotification("最終チェックポイント "
                + formatTime(cp.timestampUnix) + " / 蓄積 " + journal.count() + " 件");
    }

    // ---------------- notification ----------------

    private void createNotificationChannel() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm != null && nm.getNotificationChannel(CHANNEL_ID) == null) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID, "DePIN 観測", NotificationManager.IMPORTANCE_LOW);
            channel.setDescription("Quantus ノードの観測サービスが動作中であることを示します");
            nm.createNotificationChannel(channel);
        }
    }

    private Notification buildNotification(String text) {
        PendingIntent open = PendingIntent.getActivity(
                this, 0,
                new Intent(this, MainActivity.class),
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentTitle("Quantus DePIN Companion")
                .setContentText(text)
                .setContentIntent(open)
                .setOngoing(true)
                .build();
    }

    private void updateNotification(String text) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm != null) {
            nm.notify(NOTIFICATION_ID, buildNotification(text));
        }
    }

    private static String formatTime(long unix) {
        return new SimpleDateFormat("HH:mm:ss", Locale.US)
                .format(new Date(unix * 1000L));
    }
}
