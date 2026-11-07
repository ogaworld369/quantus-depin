package app.quantusnode.depin;

/**
 * The pending bundle export, held at APPLICATION scope (F-10,
 * v0.9). The export flow builds the bundle JSON, then opens the
 * system document picker (ACTION_CREATE_DOCUMENT) and writes
 * the JSON to the chosen destination when the picker returns.
 * The payload used to live in a MainActivity INSTANCE field:
 * while the picker was on screen, an Activity recreation
 * (rotation, theme change, process-pressure rebuild) replaced
 * the instance and the payload died with the old one — the
 * export was lost (and the result handler then failed on a
 * null payload, after the destination file had already been
 * created empty).
 *
 * This holder is process-wide state, like CompanionStatus:
 * recreation of any Activity leaves it untouched. It is set
 * when the picker opens, taken (read + cleared) when a
 * destination comes back, and cleared when the picker is
 * cancelled — so a payload can neither be lost to recreation
 * nor leak into a later, unrelated export. Nothing here is
 * persisted: a full process death still drops a pending
 * export, which is correct — the user re-taps export, and no
 * stale bundle from a previous process can be written under
 * a fresh picker result.
 */
final class PendingExport {
    private static String pendingJson;

    private PendingExport() {}

    /** Stash the payload for the picker round trip, replacing
     *  any previous one (a new export supersedes an abandoned
     *  one). */
    static synchronized void set(String json) {
        pendingJson = json;
    }

    /** The pending payload, without clearing it. */
    static synchronized String peek() {
        return pendingJson;
    }

    /** Read the payload AND clear the holder: completion
     *  consumes it, so it can never be written twice. */
    static synchronized String take() {
        String json = pendingJson;
        pendingJson = null;
        return json;
    }

    /** Drop any pending payload (picker cancelled). */
    static synchronized void clear() {
        pendingJson = null;
    }
}
