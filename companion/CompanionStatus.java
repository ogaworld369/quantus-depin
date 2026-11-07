package app.quantusnode.depin;

/**
 * Process-wide live status, written by ObservationService and read
 * by MainActivity (same process). Anything that must survive a
 * process restart lives in the JournalStore instead; this is only
 * the volatile "what is happening right now" view.
 */
final class CompanionStatus {
    private CompanionStatus() {}

    static volatile boolean serviceRunning = false;
    /** Unix time the user last tapped "start", until the service
     *  confirms it is running (or has failed); 0 when idle. Lets
     *  the UI show "starting" instead of looking unresponsive. */
    static volatile long startRequestedUnix = 0;
    static volatile String deviceId = null;
    static volatile String nodePeerId = null;
    static volatile long lastAttemptUnix = 0;
    static volatile long lastCheckpointUnix = 0;
    static volatile long lastBest = -1;
    static volatile long lastFinalized = -1;
    static volatile int lastPeers = -1;
    static volatile boolean lastSyncing = false;
    static volatile String lastError = null;
    static volatile String identityError = null;
    /** Set when the journal itself could not be opened (B4):
     *  kept distinct from identityError so the UI names the real
     *  cause. CompanionRuntime records the failure in the
     *  persistent error log at the moment it happens. */
    static volatile String journalError = null;
}
