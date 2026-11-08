package app.quantusnode.depin;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;

/**
 * Adversarial battery 4: journal corruption fuzz for JournalStore.
 *
 * Standalone tooling, NOT wired into run-tests.sh. Compile and run
 * manually against the device-independent core classes:
 *
 *   javac -d /tmp/fuzz-classes \
 *     app/src/main/java/app/quantusnode/depin/{Hex,Json,Ed25519,DepinCore,RpcClient,SeedVault,JournalStore,CompanionStatus,CrashLog}.java \
 *     tests/app/quantusnode/depin/FuzzJournalMain.java
 *   java -cp /tmp/fuzz-classes app.quantusnode.depin.FuzzJournalMain [cases] [seed]
 *
 * Per case: build a valid current-format journal (1..20 entries),
 * apply one seeded byte/line-level corruption, then assert:
 *   (1) load never throws out of the store API;
 *   (2) the accepted entry set is a PREFIX of the original entries
 *       (by checkpoint hash) - no resurrection, reordering or
 *       forged acceptance;
 *   (3) migration classification never archives anything (the
 *       journal is purely current-format, so any archived entry
 *       would be a misclassification or a promoted corruption);
 *   (4) after a recovery + append cycle the file parses line by
 *       line as JSON objects and the accepted prefix is intact.
 */
public final class FuzzJournalMain {

    private static JournalStore.EntrySigner signer(byte[] seed) {
        return (hash, seq) -> DepinCore.journalEntrySig(seed, hash, seq);
    }

    private static JournalStore.EntryVerifier verifier(byte[] pub) {
        return (hash, seq, sig) ->
                DepinCore.verifyJournalEntrySig(pub, hash, seq, sig);
    }

    private static DepinCore.Observation obs(int caseIdx, int i, long ts0) {
        long number = 350000L + i * 100L;
        DepinCore.Observation o = new DepinCore.Observation();
        o.timestampUnix = ts0 + i * 600L;
        o.bestBlockNumber = number;
        o.bestBlockHash = DepinCore.sha256(
                ("fuzz-block-" + caseIdx + "-" + number)
                        .getBytes(StandardCharsets.US_ASCII));
        o.observedPeers = 8 + (i % 5);
        o.finalizedBlockNumber = number - 10;
        return o;
    }

    private static List<String> hashesOf(JournalStore s) {
        List<String> out = new ArrayList<>();
        for (DepinCore.Checkpoint cp : s.checkpoints()) {
            out.add(Hex.encode(cp.checkpointHash));
        }
        return out;
    }

    private static boolean isPrefix(List<String> accepted,
                                    List<String> original) {
        if (accepted.size() > original.size()) {
            return false;
        }
        for (int i = 0; i < accepted.size(); i++) {
            if (!accepted.get(i).equals(original.get(i))) {
                return false;
            }
        }
        return true;
    }

    /** Apply one corruption; returns a short description. */
    private static String corrupt(File file, Random rng) throws Exception {
        byte[] data = Files.readAllBytes(file.toPath());
        String text = new String(data, StandardCharsets.UTF_8);
        int op = rng.nextInt(12);
        switch (op) {
            case 0: {
                int cut = rng.nextInt(data.length + 1);
                Files.write(file.toPath(), Arrays.copyOf(data, cut));
                return "truncate at byte " + cut + "/" + data.length;
            }
            case 1: {
                int i = rng.nextInt(data.length);
                data[i] ^= (byte) (1 << rng.nextInt(8));
                Files.write(file.toPath(), data);
                return "flip one bit at byte " + i;
            }
            case 2: {
                int i = rng.nextInt(data.length);
                data[i] = (byte) rng.nextInt(256);
                Files.write(file.toPath(), data);
                return "set byte " + i + " to a random value";
            }
            case 3: {
                List<String> lines = linesOf(text);
                int i = rng.nextInt(lines.size());
                lines.add(i, lines.get(i));
                writeLines(file, lines);
                return "duplicate line " + i;
            }
            case 4: {
                List<String> lines = linesOf(text);
                String src = lines.get(rng.nextInt(lines.size()));
                int len = 1 + rng.nextInt(Math.max(1, src.length()));
                String tail = src.substring(0, len);
                Files.write(file.toPath(),
                        (text + tail).getBytes(StandardCharsets.UTF_8));
                return "append partial line (prefix of a valid line, "
                        + "no newline)";
            }
            case 5: {
                StringBuilder g = new StringBuilder();
                int len = 1 + rng.nextInt(40);
                for (int i = 0; i < len; i++) {
                    g.append((char) (32 + rng.nextInt(95)));
                }
                Files.write(file.toPath(),
                        (text + g + "\n").getBytes(StandardCharsets.UTF_8));
                return "append garbage line";
            }
            case 6: {
                int i = text.indexOf('\n', rng.nextInt(
                        Math.max(1, text.length() - 1)));
                if (i < 0) {
                    i = text.indexOf('\n');
                }
                String out = text.substring(0, i) + "\r" + text.substring(i);
                Files.write(file.toPath(),
                        out.getBytes(StandardCharsets.UTF_8));
                return "CRLF injection before a newline";
            }
            case 7: {
                List<String> lines = linesOf(text);
                int i = rng.nextInt(lines.size());
                lines.remove(i);
                writeLines(file, lines);
                return "delete line " + i;
            }
            case 8: {
                List<String> lines = linesOf(text);
                int i = rng.nextInt(lines.size());
                int j = rng.nextInt(lines.size());
                Collections.swap(lines, i, j);
                writeLines(file, lines);
                return "swap lines " + i + " and " + j;
            }
            case 9: {
                int i = rng.nextInt(Math.max(1, data.length - 16));
                Arrays.fill(data, i, Math.min(data.length, i + 16),
                        (byte) 0);
                Files.write(file.toPath(), data);
                return "zero a 16-byte region at " + i;
            }
            case 10: {
                List<String> lines = linesOf(text);
                String last = lines.get(lines.size() - 1);
                Files.write(file.toPath(),
                        (text + last + "\n").getBytes(StandardCharsets.UTF_8));
                return "append a duplicate of the last line (replay)";
            }
            default: {
                List<String> lines = linesOf(text);
                int i = rng.nextInt(lines.size() + 1);
                lines.add(i, "");
                writeLines(file, lines);
                return "insert blank line at " + i;
            }
        }
    }

    private static List<String> linesOf(String text) {
        List<String> lines = new ArrayList<>(
                Arrays.asList(text.split("\n", -1)));
        if (!lines.isEmpty() && lines.get(lines.size() - 1).isEmpty()) {
            lines.remove(lines.size() - 1);
        }
        return lines;
    }

    private static void writeLines(File file, List<String> lines)
            throws Exception {
        String out = String.join("\n", lines) + "\n";
        Files.write(file.toPath(), out.getBytes(StandardCharsets.UTF_8));
    }

    private static void deleteTree(File f) {
        if (f.isDirectory()) {
            File[] kids = f.listFiles();
            if (kids != null) {
                for (File k : kids) {
                    deleteTree(k);
                }
            }
        }
        //noinspection ResultOfMethodCallIgnored
        f.delete();
    }

    /** Returns null when every invariant held, else a description. */
    private static String runCase(int caseIdx, Random rng) {
        File dir = new File(System.getProperty("java.io.tmpdir"),
                "depin-fuzz-journal-" + caseIdx + "-" + System.nanoTime());
        try {
            //noinspection ResultOfMethodCallIgnored
            dir.mkdirs();
            File file = new File(dir, JournalStore.FILE_NAME);
            byte[] seed = new byte[32];
            rng.nextBytes(seed);
            byte[] pub = Ed25519.publickeyFromSeed(seed);
            String deviceId = DepinCore.deviceIdFromPubkey(pub);
            long ts0 = 1762000000L + caseIdx * 100000L;
            int n = 1 + (caseIdx % 20);

            JournalStore store = JournalStore.forFile(file, deviceId, Hex.encode(pub), signer(seed), verifier(pub));
            store.bindIdentity(deviceId, Hex.encode(pub));
            for (int i = 0; i < n; i++) {
                store.append(DepinCore.makeCheckpoint(
                        i, obs(caseIdx, i, ts0), store.nextPrevState(),
                        store.nextPrevCheckpointHash(), 50, pub));
            }
            List<String> original = hashesOf(store);
            if (original.size() != n) {
                return "setup failed: built " + original.size()
                        + " of " + n + " entries";
            }

            String corruption = corrupt(file, rng);

            JournalStore reopened;
            try {
                reopened = JournalStore.forFile(file, deviceId, Hex.encode(pub), signer(seed), verifier(pub));
            } catch (Throwable t) {
                return "load threw after corruption [" + corruption
                        + "]: " + t;
            }
            List<String> accepted = hashesOf(reopened);
            if (!isPrefix(accepted, original)) {
                return "accepted set is not a prefix of the original "
                        + "after corruption [" + corruption
                        + "]: accepted=" + accepted.size()
                        + " original=" + original.size();
            }
            if (reopened.archivedOnLoad() != 0
                    || reopened.archivedCount() != 0) {
                return "migration classification archived "
                        + reopened.archivedOnLoad()
                        + " entries from a purely current-format "
                        + "journal after corruption [" + corruption + "]";
            }

            // recovery + append cycle
            try {
                reopened.bindIdentity(deviceId, Hex.encode(pub));
                DepinCore.Checkpoint next = DepinCore.makeCheckpoint(
                        reopened.count(), obs(caseIdx, n, ts0),
                        reopened.nextPrevState(),
                        reopened.nextPrevCheckpointHash(), 50, pub);
                reopened.append(next);
                List<String> expect = new ArrayList<>(accepted);
                expect.add(Hex.encode(next.checkpointHash));
                JournalStore again = JournalStore.forFile(file, deviceId, Hex.encode(pub), signer(seed), verifier(pub));
                List<String> accepted2 = hashesOf(again);
                if (!accepted2.equals(expect)) {
                    return "after recovery+append, accepted set "
                            + "changed unexpectedly [" + corruption
                            + "]: expected " + expect.size()
                            + " entries, got " + accepted2.size();
                }
                // the file must parse line by line as JSON objects
                String text = new String(Files.readAllBytes(file.toPath()),
                        StandardCharsets.UTF_8);
                for (String line : text.split("\n", -1)) {
                    if (line.isEmpty()) {
                        continue;
                    }
                    Object v;
                    try {
                        v = Json.parse(line);
                    } catch (RuntimeException e) {
                        return "post-recovery file line is not valid "
                                + "JSON [" + corruption + "]: "
                                + e.getMessage();
                    }
                    if (!(v instanceof java.util.Map)) {
                        return "post-recovery file line is not a JSON "
                                + "object [" + corruption + "]";
                    }
                }
            } catch (Throwable t) {
                return "recovery+append threw [" + corruption + "]: "
                        + t;
            }
            return null;
        } catch (Throwable t) {
            return "case setup threw: " + t;
        } finally {
            deleteTree(dir);
        }
    }

    public static void main(String[] args) {
        int cases = args.length > 0 ? Integer.parseInt(args[0]) : 2000;
        long seed = args.length > 1 ? Long.parseLong(args[1]) : 20251107L;
        Random master = new Random(seed);
        int findings = 0;
        long t0 = System.currentTimeMillis();
        for (int c = 0; c < cases; c++) {
            String problem = runCase(c, new Random(master.nextLong()));
            if (problem != null) {
                findings++;
                System.out.println("FINDING case " + c + ": " + problem);
            }
            if ((c + 1) % 250 == 0) {
                System.out.println("progress " + (c + 1) + "/" + cases
                        + " findings=" + findings);
            }
        }
        System.out.println("DONE cases=" + cases + " findings=" + findings
                + " elapsed_ms=" + (System.currentTimeMillis() - t0));
    }
}
