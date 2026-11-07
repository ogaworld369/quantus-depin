package app.quantusnode.depin;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * JSON-RPC client for the on-device Quantus node's loopback RPC
 * (HTTP POST http://127.0.0.1:9944/), the same surface the Node app
 * itself polls. Only methods that pass the node's `--rpc-methods
 * safe` gate are used (bridge design memo section 2): system_health,
 * system_syncState, system_localPeerId, chain_getBlockHash,
 * chain_getFinalizedHead, chain_getHeader. Peer lists
 * (system_peers) are unsafe-gated and deliberately NOT attempted:
 * checkpoints carry no witness data in this prototype.
 *
 * Defensive shape mirrors the Node app's poller: short timeouts and
 * a hard response-size cap, so a wedged or spoofed local endpoint
 * cannot hang or flood the observer.
 *
 * v0.3.0 hardening (re-audit of v0.4):
 *  - R-M02: the whole-round deadline now ENFORCES, not just
 *    observes. Every HTTP call's connect/read timeouts are derived
 *    from the round's remaining budget (see timeoutFor), so a
 *    slow-drip endpoint is cut off mid-read instead of merely
 *    being noticed afterwards; and fetchLocalPeerId runs inside
 *    the same round budget (beginRound/endRound), not on a
 *    separate unbounded path.
 *  - R-M03: intake is strict-canonical BEFORE anything is signed
 *    or stored. Hex-encoded block numbers must match
 *    0x[0-9a-fA-F]+ exactly (no sign, no whitespace, no empty
 *    digits — "0x-1" previously parsed as -1 and was signed into
 *    the journal, wedging export forever) and every block number,
 *    hex or JSON, must be < 2^48; the peer count must be a JSON
 *    integer in [0, 100000]. Any violation fails the whole round
 *    cleanly: no checkpoint, no journal write.
 *
 * v0.7 hardening (re-audit of v0.6):
 *  - M-01: the round budget is now ONE ABSOLUTE deadline per HTTP
 *    call, spanning connect, request send, response headers and
 *    body. The v0.5 code set the socket read timeout to the
 *    remaining budget, but a read timeout bounds only the gap
 *    BETWEEN bytes: an endpoint dripping one byte per second
 *    never tripped it and the read followed the stream far past
 *    20 s. Now every read's wait is re-derived from the time left
 *    until the deadline, the deadline is checked inside the body
 *    read loop, and on expiry the connection is disconnected and
 *    the call fails.
 *
 * v0.8 hardening (re-audit of v0.7):
 *  - M-01 (header phase): the v0.7 deadline covered the body
 *    read loop, but the RESPONSE HEADER phase was still one
 *    blocking getResponseCode() whose only bound was the
 *    gap-based socket read timeout, checked for expiry only
 *    AFTER the headers had fully arrived — a peer dripping
 *    header bytes one at a time never tripped it and could hold
 *    the call past 20 s. The header wait now runs under
 *    runWithDeadline: the deadline is enforced DURING the read
 *    — a timed wait on a worker thread, with the connection
 *    disconnected the moment the deadline expires — so a peer
 *    dripping a header byte every 19 seconds against a 20 s
 *    budget is cut AT the deadline, mid-read, not merely
 *    noticed after the headers complete; the elapsed time is
 *    then also re-checked when headers arrive.
 *
 * v0.9 hardening (fifth review of v0.8):
 *  - F-03 (body phase): the same hole the v0.8 round closed
 *    for headers stayed open for a CHUNKED body. The JDK's
 *    chunked stream parses each chunk-size line INSIDE a
 *    single read() call — reading extension bytes one by one
 *    — so readCapped's between-reads deadline checks never
 *    ran while a drip-fed chunk extension ("1;...") was being
 *    consumed: a 400 ms budget measured 3,015 ms. The body
 *    read now runs under the same runWithDeadline watchdog
 *    as the header phase (see readBody): the remaining budget
 *    is recomputed for the wait, and on expiry the connection
 *    is disconnected, unblocking whatever the stream was
 *    doing inside its one long read.
 */
final class RpcClient {
    static final String DEFAULT_ENDPOINT = "http://127.0.0.1:9944/";
    private static final int CONNECT_TIMEOUT_MS = 3000;
    private static final int READ_TIMEOUT_MS = 5000;
    private static final int MAX_RESPONSE_BYTES = 256 * 1024;
    /** Whole-round deadline for one observation (audit M-02): the
     *  per-call timeouts alone allow ~6 calls x (3 s connect + 5 s
     *  read); without an overall budget a slow-drip endpoint could
     *  stretch one round indefinitely and stall the tick loop. */
    static final long OBSERVATION_DEADLINE_MS = 20_000;
    /** Floor for a derived per-call timeout (R-M02): when a small
     *  budget remains, a call still gets a brief real chance rather
     *  than a 1 ms timeout that can only fail. */
    static final int MIN_CALL_TIMEOUT_MS = 250;
    /** Plausibility bound for best-block growth (audit M-02): at
     *  the chain's fastest plausible cadence a block takes ~1 s, so
     *  600 slots' worth of blocks per elapsed slot is already
     *  generous headroom; beyond it the "node" is not believed. */
    static final long MAX_BLOCKS_PER_SLOT = 6000;
    /** Absolute sanity bound for block numbers at intake (R-M03):
     *  2^48 blocks is ~8900 years at one block per second; anything
     *  at or beyond it is not a block number, whatever answered. */
    static final long BLOCK_NUMBER_LIMIT = 1L << 48;
    /** Sanity bound for the reported peer count at intake. */
    static final int MAX_PEERS = 100_000;

    private final String endpoint;
    private final Transport transport;
    private final long observationDeadlineMs;
    private int nextId = 1;
    private long roundStartNanos = 0;

    RpcClient(String endpoint) {
        this.endpoint = endpoint;
        this.transport = null; // HTTP transport (default path below)
        this.observationDeadlineMs = OBSERVATION_DEADLINE_MS;
    }

    /** Test seam: the JVM harness injects a canned transport so the
     *  full request/response logic is exercised without sockets
     *  (this build VM intercepts direct TCP from spawned processes;
     *  on a device the HTTP transport below is what runs). */
    interface Transport {
        byte[] post(byte[] body) throws RpcException;
    }

    RpcClient(Transport transport) {
        this(transport, OBSERVATION_DEADLINE_MS);
    }

    /** Test seam with an explicit observation deadline, so the
     *  harness can exercise the deadline path without waiting 20 s. */
    RpcClient(Transport transport, long observationDeadlineMs) {
        this.endpoint = "(injected transport)";
        this.transport = transport;
        this.observationDeadlineMs = observationDeadlineMs;
    }

    static final class RpcException extends Exception {
        RpcException(String msg) { super(msg); }
        RpcException(String msg, Throwable cause) { super(msg, cause); }
    }

    /** Thrown when the node state moved between the reads of one
     *  observation round; the caller treats the slot as a gap rather
     *  than binding inconsistent values into a checkpoint. */
    static final class InconsistentObservation extends Exception {
        InconsistentObservation(String msg) { super(msg); }
    }

    /** One consistent round of node observations. */
    static final class NodeObservation {
        DepinCore.Observation observation;
        String localPeerId;
        boolean syncing;
        long highestBlock;
    }

    private void checkDeadline(String method) throws RpcException {
        if (roundStartNanos == 0) return;
        long elapsedMs = (System.nanoTime() - roundStartNanos) / 1_000_000L;
        if (elapsedMs > observationDeadlineMs) {
            throw new RpcException(method + ": observation deadline exceeded ("
                    + elapsedMs + " ms > " + observationDeadlineMs + " ms)");
        }
    }

    /**
     * The per-call timeout for a call made {@code elapsedMs} into a
     * round with budget {@code deadlineMs} (R-M02): the remaining
     * budget, floored at MIN_CALL_TIMEOUT_MS so a nearly-expired
     * round still gives the call a brief real chance; 0 means the
     * budget is exhausted and the round must abort instead of
     * starting another call. Pure function of (elapsed, deadline)
     * so the harness can pin it without sockets. Since v0.7 the
     * HTTP transport derives an absolute deadline instead of a
     * chain of per-phase timeouts (M-01: the floor let a drip-feed
     * peer restart a small wait forever); this remains the pinned
     * arithmetic statement of the round budget.
     */
    static int timeoutFor(long elapsedMs, long deadlineMs) {
        long remaining = deadlineMs - elapsedMs;
        if (remaining <= 0) {
            return 0;
        }
        return (int) Math.max(MIN_CALL_TIMEOUT_MS, remaining);
    }

    /** Open a round budget explicitly. fetchObservation() manages
     *  its own round when none is active; the service opens one
     *  around the observation AND the follow-up localPeerId fetch
     *  so both share the same 20 s budget (R-M02). Rounds do not
     *  nest: beginRound inside an active round is a no-op. */
    synchronized void beginRound() {
        if (roundStartNanos == 0) {
            roundStartNanos = System.nanoTime();
        }
    }

    /** Close the round budget opened by beginRound (or by
     *  fetchObservation when it manages its own). */
    synchronized void endRound() {
        roundStartNanos = 0;
    }

    synchronized Object call(String method, List<Object> params) throws RpcException {
        checkDeadline(method);
        Map<String, Object> req = new LinkedHashMap<>();
        req.put("jsonrpc", "2.0");
        req.put("id", (long) nextId++);
        req.put("method", method);
        req.put("params", params);
        byte[] body = Json.canonicalBytes(req);
        try {
            byte[] raw = (transport != null) ? transport.post(body) : httpPost(body, method);
            checkDeadline(method);
            if (raw.length > MAX_RESPONSE_BYTES) {
                throw new RpcException(method + ": response exceeds "
                        + MAX_RESPONSE_BYTES + " bytes");
            }
            Map<String, Object> resp = Json.parseObject(
                    new String(raw, StandardCharsets.UTF_8));
            Object error = resp.get("error");
            if (error != null) {
                String detail = (error instanceof Map)
                        ? String.valueOf(((Map<?, ?>) error).get("message"))
                        : String.valueOf(error);
                throw new RpcException(method + ": RPC error: " + detail);
            }
            return resp.get("result");
        } catch (RpcException e) {
            throw e;
        } catch (IllegalArgumentException e) {
            throw new RpcException(method + ": malformed response: " + e.getMessage(), e);
        }
    }

    /** The absolute deadline (nanoTime) for one HTTP call: the
     *  enclosing round's deadline when a round is active, else the
     *  call's own start plus the observation budget. One deadline
     *  spans connect, send, headers and body (M-01). */
    private long callDeadlineNanos() throws RpcException {
        if (roundStartNanos != 0) {
            return roundStartNanos
                    + observationDeadlineMs * 1_000_000L;
        }
        return System.nanoTime()
                + observationDeadlineMs * 1_000_000L;
    }

    /** Milliseconds until deadlineNanos, or an RpcException when
     *  the deadline has already passed. */
    private static long remainingMs(long deadlineNanos, String method)
            throws RpcException {
        long remaining = (deadlineNanos - System.nanoTime()) / 1_000_000L;
        if (remaining <= 0) {
            throw new RpcException(method
                    + ": absolute deadline exceeded during call");
        }
        return remaining;
    }

    /** The on-device transport: one HTTP POST to the loopback
     *  endpoint, with the Node app's defensive shape (short timeouts,
     *  capped response) and ONE absolute deadline for the whole
     *  call (M-01). Inside an observation round the deadline is the
     *  round's; the connect wait is capped as before, and every
     *  subsequent phase's wait is the time LEFT until the deadline,
     *  so a slow-drip endpoint is cut off at the deadline itself —
     *  by the per-read socket timeout and by the in-loop deadline
     *  check plus disconnect in readCapped. */
    private byte[] httpPost(byte[] body, String method) throws RpcException {
        final long deadlineNanos = callDeadlineNanos();
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(endpoint).openConnection();
            conn.setConnectTimeout((int) Math.min(CONNECT_TIMEOUT_MS,
                    remainingMs(deadlineNanos, method)));
            conn.setReadTimeout((int) Math.min(READ_TIMEOUT_MS,
                    remainingMs(deadlineNanos, method)));
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body);
            }
            // The send phase is inside the deadline too.
            remainingMs(deadlineNanos, method);
            // Headers: bound this wait by the time left — and,
            // since v0.8, enforce it with a watchdog. A socket
            // read timeout bounds only the gap BETWEEN bytes, so
            // a peer dripping header bytes one at a time never
            // trips it, and the previous code checked the
            // deadline only AFTER getResponseCode() returned:
            // the header phase could run far past the budget
            // (audit M-01, header phase). The response code is
            // therefore requested on a worker thread under
            // runWithDeadline: on expiry the connection is
            // disconnected — which unblocks the worker's read —
            // and the call fails. The deadline is re-checked the
            // moment the headers are in.
            conn.setReadTimeout((int) remainingMs(deadlineNanos, method));
            final HttpURLConnection headerConn = conn;
            int code = runWithDeadline(headerConn::getResponseCode,
                    deadlineNanos, headerConn::disconnect, method);
            remainingMs(deadlineNanos, method);
            InputStream in = (code >= 200 && code < 300)
                    ? conn.getInputStream() : conn.getErrorStream();
            if (in == null) {
                throw new RpcException(method + ": HTTP " + code + " with no body");
            }
            // Body: read under the deadline watchdog, not just
            // the in-loop checks (F-03) — a chunked stream can
            // consume a slow chunk-size line inside ONE read()
            // call, where no between-reads check ever runs.
            byte[] raw = readBody(in, deadlineNanos, conn, method);
            if (code < 200 || code >= 300) {
                throw new RpcException(method + ": HTTP " + code);
            }
            return raw;
        } catch (java.net.SocketTimeoutException e) {
            // A per-phase wait ran out. When the absolute deadline
            // is what expired, say so — it is the M-01 failure the
            // caller (and the status UI) should see.
            if (System.nanoTime() >= deadlineNanos) {
                throw new RpcException(method
                        + ": absolute deadline exceeded during call", e);
            }
            throw new RpcException(method + ": " + e.getMessage(), e);
        } catch (IOException e) {
            throw new RpcException(method + ": " + e.getMessage(), e);
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    /**
     * Read a response body under an absolute deadline (M-01) and
     * the response-size cap. Before every read, the wait available
     * is recomputed from the time left until deadlineNanos: when a
     * connection is supplied its read timeout is set to exactly
     * that remainder, and when the deadline has passed the
     * connection is disconnected and the read aborts instead of
     * following the stream. A peer dripping ~1 byte per second is
     * therefore cut at the deadline: each drip only restarts a
     * SHORTER wait, never a fresh one. Package-private and static
     * (connection nullable) so the JVM harness can drive it with a
     * drip-feed stream and a short deadline — sockets cannot run
     * in this build VM, the deadline arithmetic is what is pinned.
     * Note the loop's own limit (F-03): its checks run BETWEEN
     * read() calls, so in production the transport never calls
     * it bare — readBody runs it under the runWithDeadline
     * watchdog, which bounds a single read() call itself (a
     * chunked stream consumes a slow chunk-size line inside one
     * call, where no between-reads check can run).
     */
    static byte[] readCapped(InputStream in, long deadlineNanos,
                             HttpURLConnection conn)
            throws IOException, RpcException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while (true) {
            long remaining = (deadlineNanos - System.nanoTime()) / 1_000_000L;
            if (remaining <= 0) {
                if (conn != null) {
                    conn.disconnect();
                }
                throw new RpcException(
                        "absolute deadline exceeded while reading response body");
            }
            if (conn != null) {
                conn.setReadTimeout((int) Math.min(Integer.MAX_VALUE, remaining));
            }
            n = in.read(buf);
            if (n < 0) {
                break;
            }
            out.write(buf, 0, n);
            if (out.size() > MAX_RESPONSE_BYTES) {
                throw new RpcException("response exceeds " + MAX_RESPONSE_BYTES + " bytes");
            }
        }
        return out.toByteArray();
    }

    /**
     * Read a response body under the absolute deadline (F-03,
     * v0.9): readCapped running on the runWithDeadline worker,
     * with the connection disconnected on expiry — the same
     * mechanism the header phase has used since v0.8. The wrap
     * is necessary, not decorative: for a chunked body the
     * stream consumes the chunk-size line (extension and all)
     * INSIDE a single read() call, so readCapped's
     * between-reads deadline checks — which do recompute the
     * remaining budget and re-arm the read timeout before every
     * read — never get a chance to run while that one call is
     * outstanding. The watchdog bounds the call itself: the
     * caller waits only for the time left until deadlineNanos,
     * and the disconnect unblocks the worker's read, exactly as
     * in the header phase. readCapped's own failures (its
     * deadline check between reads, the size cap) surface
     * unchanged: runWithDeadline re-wraps a checked exception
     * from the worker, so the original RpcException is
     * unwrapped and rethrown as-is.
     */
    static byte[] readBody(InputStream in, long deadlineNanos,
                           HttpURLConnection conn, String what)
            throws IOException, RpcException {
        try {
            return runWithDeadline(() -> readCapped(in, deadlineNanos, conn),
                    deadlineNanos, conn::disconnect, what);
        } catch (RpcException e) {
            if (e.getCause() instanceof RpcException) {
                throw (RpcException) e.getCause();
            }
            throw e;
        }
    }

    /** Harness form of readBody: the abort action stands in for
     *  disconnect() (it ends the stream's in-flight read), so the
     *  JVM harness can drive the exact production composition —
     *  watchdog around readCapped — with a drip-feed stream
     *  standing in for the chunked body. */
    static byte[] readBody(InputStream in, long deadlineNanos,
                           Runnable abort, String what)
            throws IOException, RpcException {
        try {
            return runWithDeadline(() -> readCapped(in, deadlineNanos, null),
                    deadlineNanos, abort, what);
        } catch (RpcException e) {
            if (e.getCause() instanceof RpcException) {
                throw (RpcException) e.getCause();
            }
            throw e;
        }
    }

    /**
     * Run one blocking call under an absolute deadline (M-01,
     * header phase, v0.8). A socket read timeout cannot bound a
     * peer that drips bytes slowly — each byte restarts the gap
     * timer — so the blocking wait itself is moved to a daemon
     * worker thread and the CALLER waits only for the time left
     * until deadlineNanos. On expiry the abort action runs (for
     * the header phase: disconnect the connection, which makes
     * the worker's pending read fail), the worker is interrupted,
     * and an RpcException is thrown; the daemon worker can never
     * keep the process alive. A call that finishes in time simply
     * returns its value; an IOException or RuntimeException from
     * the call propagates unchanged. Package-private and static
     * so the JVM harness can pin the deadline behaviour with a
     * drip-feed stream standing in for the header wait — sockets
     * cannot run in this build VM.
     */
    static <T> T runWithDeadline(java.util.concurrent.Callable<T> call,
                                 long deadlineNanos, Runnable abort,
                                 String what)
            throws IOException, RpcException {
        long remaining = (deadlineNanos - System.nanoTime()) / 1_000_000L;
        if (remaining <= 0) {
            abort.run();
            throw new RpcException(what
                    + ": absolute deadline exceeded during call");
        }
        java.util.concurrent.FutureTask<T> task =
                new java.util.concurrent.FutureTask<>(call);
        Thread worker = new Thread(task, "depin-rpc-deadline");
        worker.setDaemon(true);
        worker.start();
        try {
            return task.get(remaining,
                    java.util.concurrent.TimeUnit.MILLISECONDS);
        } catch (java.util.concurrent.TimeoutException e) {
            abort.run();
            task.cancel(true);
            throw new RpcException(what
                    + ": absolute deadline exceeded during call", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            abort.run();
            task.cancel(true);
            throw new RpcException(what
                    + ": interrupted while awaiting response", e);
        } catch (java.util.concurrent.ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof IOException) {
                throw (IOException) cause;
            }
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw new RpcException(what + ": " + cause, cause);
        }
    }

    private static List<Object> params(Object... items) {
        List<Object> list = new ArrayList<>();
        for (Object i : items) list.add(i);
        return list;
    }

    // ---------------- strict intake parsing (R-M03) ----------------

    /**
     * Parse a hex-encoded block number strictly: the string must
     * match 0x[0-9a-fA-F]+ exactly — a "0x" prefix, at least one
     * hex digit, no sign, no whitespace, nothing else — and the
     * value must be below BLOCK_NUMBER_LIMIT. The previous reader
     * ran the digits through Long.parseLong(..., 16) after
     * stripping the prefix, which parsed "0x-1" as -1: the value
     * was signed into the journal and then rejected by the bundle
     * schema at every export, wedging the history permanently.
     * Pure function, pinned by the harness.
     */
    static long parseHexBlockNumber(String s) throws RpcException {
        if (s == null || !s.startsWith("0x") || s.length() <= 2) {
            throw new RpcException("block number is not canonical hex: " + s);
        }
        long v = 0;
        for (int i = 2; i < s.length(); i++) {
            char c = s.charAt(i);
            int d;
            if (c >= '0' && c <= '9') {
                d = c - '0';
            } else if (c >= 'a' && c <= 'f') {
                d = c - 'a' + 10;
            } else if (c >= 'A' && c <= 'F') {
                d = c - 'A' + 10;
            } else {
                throw new RpcException("block number is not canonical hex: " + s);
            }
            v = v * 16 + d;
            if (v >= BLOCK_NUMBER_LIMIT) {
                throw new RpcException(
                        "block number beyond sanity bound 2^48: " + s);
            }
        }
        return v;
    }

    /** A JSON block number at intake: must be a JSON integer (a
     *  fractional literal is not a block number) within
     *  [0, BLOCK_NUMBER_LIMIT). */
    private static long strictJsonBlockNumber(Object v, String field)
            throws RpcException {
        if (!(v instanceof Long)) {
            throw new RpcException(field + ": not a JSON integer: " + v);
        }
        long n = (Long) v;
        if (n < 0 || n >= BLOCK_NUMBER_LIMIT) {
            throw new RpcException(
                    field + ": outside sanity range [0, 2^48): " + n);
        }
        return n;
    }

    /** The reported peer count at intake: a JSON integer within
     *  [0, MAX_PEERS]. */
    private static int strictPeerCount(Object v) throws RpcException {
        if (!(v instanceof Long)) {
            throw new RpcException("system_health.peers: not a JSON integer: " + v);
        }
        long n = (Long) v;
        if (n < 0 || n > MAX_PEERS) {
            throw new RpcException(
                    "system_health.peers: outside [0, " + MAX_PEERS + "]: " + n);
        }
        return (int) n;
    }

    private static byte[] strictHash32(String hex, String method)
            throws RpcException {
        final byte[] b;
        try {
            b = Hex.decodePrefixed(hex);
        } catch (IllegalArgumentException e) {
            throw new RpcException(method + ": malformed hash: " + e.getMessage());
        }
        if (b.length != 32) {
            throw new RpcException(method + ": not a 32-byte hash");
        }
        return b;
    }

    /**
     * Fetch one consistent observation, in the order the design memo
     * prescribes: syncState -> getBlockHash -> finalizedHead ->
     * getHeader -> health, then syncState once more to confirm the
     * best block did not move underneath the round. The timestamp is
     * taken when the round completes.
     *
     * Round budget: when the caller has opened a round with
     * beginRound() (the service does, so the follow-up peer-id
     * fetch shares the budget), this method participates in it and
     * leaves it open; otherwise it opens and closes its own.
     * Every value is intake-sanitized as it arrives (R-M03): a
     * malformed or absurd value fails the round cleanly, before
     * anything is signed or stored.
     */
    NodeObservation fetchObservation() throws RpcException, InconsistentObservation {
        boolean ownRound = roundStartNanos == 0;
        if (ownRound) {
            beginRound();
        }
        try {
            return fetchObservationRound();
        } finally {
            if (ownRound) {
                endRound();
            }
        }
    }

    private NodeObservation fetchObservationRound()
            throws RpcException, InconsistentObservation {
        Map<String, Object> sync1 = Json.asObject(call("system_syncState", params()));
        long currentBlock = strictJsonBlockNumber(
                sync1.get("currentBlock"), "system_syncState.currentBlock");
        long highestBlock = strictJsonBlockNumber(
                sync1.get("highestBlock"), "system_syncState.highestBlock");

        String bestHashHex = Json.asString(call("chain_getBlockHash", params(currentBlock)));
        byte[] bestHash = strictHash32(bestHashHex, "chain_getBlockHash");

        String finalizedHashHex = Json.asString(call("chain_getFinalizedHead", params()));
        strictHash32(finalizedHashHex, "chain_getFinalizedHead");
        Map<String, Object> header = Json.asObject(
                call("chain_getHeader", params(finalizedHashHex)));
        long finalizedNumber = parseHexBlockNumber(
                Json.asString(header.get("number")));
        if (finalizedNumber > currentBlock) {
            // Impossible on a real chain (finalized is a prefix of
            // best). Whatever answered is not believed; the slot
            // becomes a gap (audit M-02). v0.3 stored this and then
            // failed the whole journal at export self-check time.
            throw new InconsistentObservation(
                    "finalized block " + finalizedNumber
                            + " ahead of best block " + currentBlock);
        }

        Map<String, Object> health = Json.asObject(call("system_health", params()));
        int peers = strictPeerCount(health.get("peers"));
        boolean syncing = Json.asBool(health.get("isSyncing"));

        Map<String, Object> sync2 = Json.asObject(call("system_syncState", params()));
        long currentBlock2 = strictJsonBlockNumber(
                sync2.get("currentBlock"), "system_syncState.currentBlock");
        if (currentBlock2 != currentBlock) {
            throw new InconsistentObservation(
                    "best block moved during observation: "
                            + currentBlock + " -> " + currentBlock2);
        }

        DepinCore.Observation o = new DepinCore.Observation();
        o.timestampUnix = System.currentTimeMillis() / 1000L;
        o.bestBlockNumber = currentBlock;
        o.bestBlockHash = bestHash;
        o.observedPeers = peers;
        o.finalizedBlockNumber = finalizedNumber;

        NodeObservation out = new NodeObservation();
        out.observation = o;
        out.syncing = syncing;
        out.highestBlock = highestBlock;
        return out;
    }

    String fetchLocalPeerId() throws RpcException {
        return Json.asString(call("system_localPeerId", params()));
    }
}

/**
 * Plausibility state machine for accepted observations (audit
 * M-02, extended by re-audit R-M03). The loopback endpoint is
 * unauthenticated — any local process could answer on port 9944 —
 * so a single poisoned round must not be able to write absurd
 * values into the signed history, nor wedge all future
 * observations (v0.3 accepted a huge best number once, after which
 * the real node looked like a permanent "regression").
 *
 * The tracker holds the BASELINE: the last ACCEPTED observation's
 * (best, timestamp). The service seeds it from the journal tail at
 * start, so the rules bind across process restarts exactly as they
 * bind within a run (R-M03 extension a — the v0.4 jump check
 * silently restarted from the in-memory state only). Decisions:
 *  - finalized ahead of best: rejected, no state change (it is an
 *    inconsistency, not a regression, and must not consume the
 *    regression budget);
 *  - no baseline yet (empty journal): the first observation is
 *    ACCEPTED and flagged baselineInitializing in the decision —
 *    there is nothing to compare it against, but the acceptance is
 *    never silent;
 *  - best at or above the baseline: accepted when the forward jump
 *    is within max(MAX_BLOCKS_PER_SLOT, elapsedSlots *
 *    MAX_BLOCKS_PER_SLOT), elapsedSlots counted from the
 *    baseline's timestamp; the baseline advances and the
 *    regression counter resets;
 *  - best below the baseline (regression): rejected and counted.
 *    On the THIRD consecutive regression the new best is adopted
 *    as the baseline and the round is ACCEPTED (flagged
 *    baselineReset). A node that resyncs, or a baseline seeded
 *    from one stale value, therefore costs at most three rounds —
 *    never a permanent wedge (R-M03 extension b). Any accepted
 *    observation updates the baseline.
 * The machine is deterministic and free of I/O and clocks: callers
 * pass observations in, decisions come out; the harness pins the
 * full transition table.
 *
 * Note the division of labour: this machine decides whether an
 * observation is BELIEVED. Whether an accepted observation may be
 * APPENDED is the service's call — the bundle format requires
 * non-decreasing best across checkpoints, so a baselineReset
 * acceptance whose best is still below the journal tail's best is
 * held from the journal (observations keep being accepted against
 * the new baseline, and appends resume the moment best reaches
 * the recorded tail again) rather than written as a checkpoint
 * that would make every future export fail its self-check.
 */
final class ObservationPlausibility {

    /** One decision. reason is human-readable and always set for
     *  rejections; flags mark the two non-silent acceptances. */
    static final class Decision {
        final boolean accepted;
        final boolean baselineInitializing;
        final boolean baselineReset;
        final String reason;

        private Decision(boolean accepted, boolean baselineInitializing,
                         boolean baselineReset, String reason) {
            this.accepted = accepted;
            this.baselineInitializing = baselineInitializing;
            this.baselineReset = baselineReset;
            this.reason = reason;
        }
    }

    private boolean hasBaseline = false;
    private long baselineBest;
    private long baselineTs;
    private int consecutiveRegressions = 0;

    ObservationPlausibility() {}

    /** Seed from a persisted baseline (the journal tail): the
     *  first evaluate() then applies the normal rules instead of
     *  the baseline-initializing path. */
    static ObservationPlausibility seededWith(long best, long timestampUnix) {
        ObservationPlausibility p = new ObservationPlausibility();
        p.hasBaseline = true;
        p.baselineBest = best;
        p.baselineTs = timestampUnix;
        return p;
    }

    boolean hasBaseline() {
        return hasBaseline;
    }

    long baselineBest() {
        return baselineBest;
    }

    int consecutiveRegressions() {
        return consecutiveRegressions;
    }

    synchronized Decision evaluate(DepinCore.Observation o) {
        if (o.finalizedBlockNumber != null
                && o.finalizedBlockNumber > o.bestBlockNumber) {
            return new Decision(false, false, false,
                    "finalized " + o.finalizedBlockNumber
                            + " ahead of best " + o.bestBlockNumber);
        }
        if (!hasBaseline) {
            adopt(o);
            return new Decision(true, true, false, null);
        }
        if (o.bestBlockNumber >= baselineBest) {
            long elapsedSlots = Math.max(0L,
                    o.timestampUnix / DepinCore.SLOT_SEC
                            - baselineTs / DepinCore.SLOT_SEC);
            long limit = Math.max(RpcClient.MAX_BLOCKS_PER_SLOT,
                    elapsedSlots * RpcClient.MAX_BLOCKS_PER_SLOT);
            long jump = o.bestBlockNumber - baselineBest;
            if (jump > limit) {
                return new Decision(false, false, false,
                        "best jumped " + jump + " blocks in "
                                + elapsedSlots + " slot(s); limit is " + limit);
            }
            adopt(o);
            return new Decision(true, false, false, null);
        }
        // Regression below the baseline.
        consecutiveRegressions++;
        if (consecutiveRegressions >= 3) {
            long old = baselineBest;
            adopt(o);
            return new Decision(true, false, true,
                    "best regressed persistently (" + old + " -> "
                            + o.bestBlockNumber + "); adopted as the new baseline");
        }
        return new Decision(false, false, false,
                "best regressed " + baselineBest + " -> " + o.bestBlockNumber
                        + " (regression " + consecutiveRegressions + " of 3)");
    }

    private void adopt(DepinCore.Observation o) {
        hasBaseline = true;
        baselineBest = o.bestBlockNumber;
        baselineTs = o.timestampUnix;
        consecutiveRegressions = 0;
    }
}

/**
 * Segment policy for the recorded journal (re-audit M-02,
 * redesigned in v0.8). The plausibility machine above decides
 * whether an observation is BELIEVED; this class decides two
 * things about the RECORDED history it feeds. Both defences sit
 * at the INTAKE side — they bound what may be recorded — because
 * the v0.8 design makes recovery asymmetric: recorded, signed
 * history is never preserved, quarantined or restarted merely
 * because the live RPC view disagrees with it. The v0.7
 * poisoned-tail preservation rule is WITHDRAWN: the v0.7
 * re-audit (M-02) showed it could be inverted — a fake LOW view
 * (best=1, three times) healed the baseline downward and then
 * "preserved" the device's GENUINE history out of the live
 * journal. RPC disagreement now only ever HOLDS appends; the
 * only destructive recovery left is the identity/format
 * quarantine in JournalStore (the B4 class), which never
 * consults RPC at all.
 *
 * (a) Segment start (unchanged from v0.7): the FIRST checkpoint
 *     of a fresh segment (a new journal, or a journal emptied
 *     by quarantine) is recorded only after
 *     SEGMENT_START_PLAUSIBLE_READINGS consecutive ACCEPTED
 *     readings. A single poisoned first response can adopt the
 *     in-memory baseline, but it can no longer put a checkpoint
 *     on disk by itself: the second reading must also be
 *     plausible against the first. Any rejection resets the
 *     streak — "consecutive" is load-bearing.
 * (b) Advance cap (new in v0.8): a new checkpoint's best may
 *     exceed the RECORDED TAIL's best by at most
 *     cap_best(now) = tail_best
 *         + floor((now − tail_timestamp) / SLOT_SEC) × A + A,
 *     where A is MAX_TAIL_ADVANCE_BLOCKS_PER_SLOT, "now" is the
 *     candidate reading's own timestamp, and tail_timestamp is
 *     the recorded tail checkpoint's timestamp — persisted in
 *     the journal, never a boot time and never an unadopted RPC
 *     value (design review A4). The plausibility machine bounds
 *     a reading against the in-memory baseline, which baseline
 *     HEALING can move; the recorded tail cannot move, so this
 *     cap bounds how far a poisoned baseline can drag the
 *     recorded history in one step: a fake-high reading that
 *     slips past plausibility mid-segment is HELD at the tail,
 *     not recorded. Readings at or below the tail are not
 *     advances at all (regressions are held by the service, as
 *     before). Because the elapsed time is measured from the
 *     tail's own timestamp, a node catching up after downtime
 *     becomes admissible as wall time passes.
 *
 * Scope of these rules, stated plainly (claims discipline,
 * design review A4): they BOUND the damage a hostile or broken
 * RPC view can do to the recorded history; they do not PREVENT
 * fabrication within the cap by a sustained hostile RPC, and
 * the two segment-start readings come from the same source —
 * a consistency check, not independent corroboration.
 * Within-cap fabrication in signed history is detectable only
 * by the aggregation side's cross-check against the real
 * chain, never locally.
 * The class is deterministic and free of I/O: the service wires
 * the decisions, the harness pins the arithmetic and the streak.
 */
final class SegmentPolicy {
    /** Most blocks the recorded tail may advance per elapsed
     *  checkpoint slot (DepinCore.SLOT_SEC = 600 s). Derivation:
     *  this chain cannot produce blocks faster than roughly one
     *  per second even in theory — the intake plausibility bound
     *  (ObservationPlausibility.MAX_BLOCKS_PER_SLOT) uses the
     *  same figure — so one slot of real production is at most
     *  ~600 blocks, and at the chain's actual cadence (several
     *  seconds per block) it is ~100. The cap uses the same
     *  generous 6,000 blocks per slot: ten times the fastest
     *  conceivable production, so no honest chain movement is
     *  ever held, while a spoofed jump (e.g. a first response
     *  of 2^48-1) exceeds it by orders of magnitude. */
    static final long MAX_TAIL_ADVANCE_BLOCKS_PER_SLOT = 6000;
    /** Consecutive accepted readings required before a fresh
     *  segment records its first checkpoint. */
    static final int SEGMENT_START_PLAUSIBLE_READINGS = 2;

    private int plausibleStreak = 0;

    /** True when a candidate checkpoint may be appended after
     *  the recorded tail, under the A4 cap:
     *  cap_best(now) = tailBest + floor((now − tailTs) /
     *  SLOT_SEC) × A + A, with A =
     *  MAX_TAIL_ADVANCE_BLOCKS_PER_SLOT and "now" the
     *  candidate's timestamp. The elapsed time is measured from
     *  the recorded tail's OWN timestamp (persisted in the
     *  journal) — not from a boot time, and never from an
     *  unadopted RPC value — so the allowance grows with real
     *  wall time since the tail was recorded. A candidate at or
     *  below the tail is never an "advance" and always passes
     *  this check (the service holds regressions separately).
     *  Pure arithmetic, pinned by the harness. */
    static boolean tailAdvanceAllowed(long tailBest, long tailTs,
                                      long candBest, long candTs) {
        if (candBest <= tailBest) {
            return true;
        }
        long elapsedSlots = Math.max(0L,
                (candTs - tailTs) / DepinCore.SLOT_SEC);
        long allowance = elapsedSlots * MAX_TAIL_ADVANCE_BLOCKS_PER_SLOT
                + MAX_TAIL_ADVANCE_BLOCKS_PER_SLOT;
        return candBest - tailBest <= allowance;
    }

    /** Record one accepted reading while the segment is empty.
     *  Returns true once the streak reaches the required count
     *  (and for every further accepted reading until reset). */
    synchronized boolean noteAcceptedWhileSegmentEmpty() {
        plausibleStreak++;
        return plausibleStreak >= SEGMENT_START_PLAUSIBLE_READINGS;
    }

    /** A rejected reading breaks the streak: the segment-start
     *  readings must be consecutive. */
    synchronized void noteRejected() {
        plausibleStreak = 0;
    }

    /** A new segment begins (quarantine): the streak starts
     *  over. */
    synchronized void reset() {
        plausibleStreak = 0;
    }

    synchronized int plausibleStreak() {
        return plausibleStreak;
    }
}

/**
 * Service generation guard for the stop/start race (re-audit
 * M-04, v0.8). A tick that is already running when the service
 * is stopped can finish its RPC round AFTER onDestroy has shut
 * the executor down — and if the service is then restarted, the
 * stale tick's append could land inside the NEW generation's
 * journal session, writing a checkpoint chained to state the
 * new generation has not (re)loaded or, worse, a best below the
 * tail another writer already recorded. The guard makes that
 * interleaving impossible to miss: each tick captures the
 * generation when it STARTS; ObservationService.onDestroy calls
 * requestStop() BEFORE shutting the executor down, which sets
 * the stop flag and advances the generation; a restarted service
 * calls beginNewGeneration(). An append is allowed only while
 * the captured generation is still current AND no stop was
 * requested since; the stale tick then returns without writing.
 * Pure logic (no Android, no I/O) so the JVM harness pins the
 * transitions; JournalStore.append's own best-monotonicity
 * check is the second line of defence.
 */
final class ServiceGeneration {
    /** The one process-wide guard: service generations are a
     *  property of the process, not of any service instance. */
    static final ServiceGeneration PROCESS = new ServiceGeneration();

    private final java.util.concurrent.atomic.AtomicLong current =
            new java.util.concurrent.atomic.AtomicLong(0);
    private volatile boolean stopRequested = false;

    /** The generation a starting tick must capture. */
    long capture() {
        return current.get();
    }

    /** A stop was requested: every captured generation goes
     *  stale at once, and the flag latches until the next
     *  beginNewGeneration(). */
    void requestStop() {
        stopRequested = true;
        current.incrementAndGet();
    }

    /** A (re)started service begins a fresh generation; ticks
     *  captured before it are stale. */
    void beginNewGeneration() {
        stopRequested = false;
        current.incrementAndGet();
    }

    /** True only while gen is the live generation and no stop
     *  has been requested since it was captured. */
    boolean isCurrent(long gen) {
        return !stopRequested && gen == current.get();
    }
}
