package app.quantusnode.depin;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * Persistent, app-private error log: the reason a failure happened
 * must survive the process that died from it. CompanionStatus is
 * in-memory only, so before v0.1.1 an init failure vanished with
 * the process and the relaunched UI had nothing to show.
 *
 * Entries record ONLY: timestamp, a short kind tag, the exception
 * class, its message and the top stack frames (plus the cause
 * chain). No key material, no seed bytes, no journal contents —
 * exception messages in this app never carry secrets, and stack
 * frames are class/method names only.
 *
 * The file is capped: once it grows past MAX_BYTES the oldest
 * entries are dropped at an entry boundary.
 *
 * Pure java.io on purpose (no Android types), so the JVM harness
 * exercises this exact code.
 */
final class CrashLog {
    static final String FILE_NAME = "error-log.txt";

    private static final int MAX_BYTES = 64 * 1024;
    private static final int MAX_FRAMES = 16;
    private static final int MAX_MESSAGE_CHARS = 500;
    private static final String ENTRY_MARKER = "=== ";

    private CrashLog() {}

    static synchronized void record(File dir, String kind, Throwable t) {
        StringBuilder sb = new StringBuilder();
        sb.append(ENTRY_MARKER).append(timestamp()).append(" [").append(kind).append("]\n");
        appendThrowable(sb, t, false);
        appendEntry(dir, sb.toString());
    }

    static synchronized void recordMessage(File dir, String kind, String message) {
        String entry = ENTRY_MARKER + timestamp() + " [" + kind + "]\n"
                + truncate(message) + "\n";
        appendEntry(dir, entry);
    }

    /** Full log text, or null when nothing has been recorded. */
    static synchronized String readAll(File dir) {
        File file = new File(dir, FILE_NAME);
        if (!file.exists()) {
            return null;
        }
        try (FileInputStream in = new FileInputStream(file)) {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int n;
            while ((n = in.read(chunk)) >= 0) {
                out.write(chunk, 0, n);
            }
            String text = out.toString(StandardCharsets.UTF_8.name());
            return text.isEmpty() ? null : text;
        } catch (IOException e) {
            return null;
        }
    }

    static synchronized void clear(File dir) {
        //noinspection ResultOfMethodCallIgnored
        new File(dir, FILE_NAME).delete();
    }

    /** The most recent entry in a log text (or the whole text). */
    static String lastEntry(String logText) {
        if (logText == null) {
            return null;
        }
        int idx = logText.lastIndexOf("\n" + ENTRY_MARKER);
        if (idx < 0) {
            return logText.strip();
        }
        return logText.substring(idx + 1).strip();
    }

    // ---------------- internals ----------------

    private static void appendEntry(File dir, String entry) {
        try {
            String existing = readAll(dir);
            String combined = (existing == null ? "" : existing) + entry;
            if (combined.length() > MAX_BYTES) {
                int cut = combined.length() - MAX_BYTES;
                int boundary = combined.indexOf(ENTRY_MARKER, cut);
                combined = boundary >= 0
                        ? combined.substring(boundary)
                        : combined.substring(cut);
            }
            try (FileOutputStream out = new FileOutputStream(new File(dir, FILE_NAME))) {
                out.write(combined.getBytes(StandardCharsets.UTF_8));
            }
        } catch (IOException ignored) {
            // Diagnostics must never take the app down with them.
        }
    }

    private static void appendThrowable(StringBuilder sb, Throwable t, boolean causedBy) {
        if (t == null) {
            sb.append("(no throwable)\n");
            return;
        }
        if (causedBy) {
            sb.append("Caused by: ");
        }
        sb.append(t.getClass().getName()).append(": ")
                .append(truncate(String.valueOf(t.getMessage()))).append('\n');
        StackTraceElement[] frames = t.getStackTrace();
        int n = Math.min(frames.length, MAX_FRAMES);
        for (int i = 0; i < n; i++) {
            sb.append("    at ").append(frames[i]).append('\n');
        }
        if (frames.length > n) {
            sb.append("    ... ").append(frames.length - n).append(" more\n");
        }
        if (t.getCause() != null && t.getCause() != t) {
            appendThrowable(sb, t.getCause(), true);
        }
    }

    private static String truncate(String s) {
        if (s == null) {
            return "";
        }
        return s.length() <= MAX_MESSAGE_CHARS
                ? s : s.substring(0, MAX_MESSAGE_CHARS) + "…";
    }

    private static String timestamp() {
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
                .format(new Date());
    }
}
