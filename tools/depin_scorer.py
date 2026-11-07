"""Quantus DePIN aggregation scorer (SPEC v0.8, sections 8-11;
the bundle format remains "0.5" - v0.8 is a rules revision).

Takes proof-bundle submissions plus submission metadata and produces,
per node, a raw count contribution and an adjusted weight, with flags
and disqualification reasons. Implements the selected mitigation
package ("triple wall + confiscation of time"):

  * Wall of facts: only checkpoints whose contents are anchored to
    public chain facts (block number/hash progression, finalized lag
    gate) earn weight. Self-reported values (peer counts) never enter
    the weight; they are display / anomaly signals only.
  * Wall of time: weight is sqrt() of settled, gate-passing days
    (capped), with a coverage-squared decay folded into the settled
    days. The wall is built from participation duration alone: the
    GitHub account age is recorded as reference metadata only and
    never affects weight or eligibility (no entry barriers - SPEC
    v0.2 revision, 2026-11-07). Fresh identities stay light because
    the maturity curve is sublinear and closed clusters are capped,
    no matter how many of them there are.
  * Wall of mutual witness: mutual-observation edges are cross-checked
    between bundles. A closed cluster (members witness only each
    other) is discounted by capping each of its biconnected blocks
    at CLUSTER_CAP_FACTOR times the block's strongest member
    (block-local since v0.6; see the B3-F1 note below).
  * Confiscation of time: a spot check failed against an
    operator-supplied trusted expectation revokes the identity's
    entire history (weight 0, count 0). Nothing else disqualifies:
    see the v0.3 notes below.

v0.3 hardening (independent review, 2026-11-07):
  * C1: earned days come only from gate-passing checkpoint counts
    times the fixed slot (core.SLOT_SEC). A bundle's declared
    checkpoint interval never scales its own weight, for any format
    version.
  * C2: disqualification can no longer be framed onto a victim.
    An invalid bundle is simply rejected, unattributed - it never
    creates or damages a node entry. Re-submitting an identical
    bundle is idempotent (counted once, duplicates ignored).
    Disqualification requires signed evidence: a spot-check response
    that mismatches an operator-trusted expectation. Submission
    metadata (account, account age) is display-only and is never a
    disqualification basis. The old "one key, multiple device ids"
    rule is gone: device_id is derived from the public key, so the
    situation cannot occur structurally.
  * H3 (partial): closedness of a witness cluster is judged only on
    bidirectional (mutual) edges; a one-directional mention of an
    outsider no longer opens a cluster. Witness data is taken only
    from gate-passing checkpoints.
  * H4: the scoring time comes only from the trusted caller
    (scored_at_unix argument, or the current time). It is never
    derived from submission metadata, so a future-dated submission
    cannot skip the settlement wait.
  * H5: in v0.2+ bundles, a checkpoint without
    finalized_block_number is uncorroborated and earns no weight.
  * H7: spot-check expectations are read only from the operator's
    separate trusted channel (spot_expectations argument), never
    from the submission record. Without a trusted expectation a spot
    check is recorded as not evaluated - neither passed nor failed.
  * H9: each submission is processed in isolation; a malformed one
    lands in rejected_submissions and never aborts the batch.
  * M1: multiple valid bundles of one device are merged
    deterministically over non-overlapping checkpoint timestamps.

v0.4 hardening (independent review of v0.3, 2026-11-07):
  * C-01: spot-check responses must be owner-signed. Submissions
    carry spot_check records for a bundle (duplicates included);
    only a record whose Ed25519 signature verifies against the
    bundle's public key (core.verify_spot_response) is treated as
    the owner's response at all. Unsigned or badly signed records
    are ignored with a flag - they can never disqualify anyone -
    and a later valid response overrides an earlier invalid one.
    Disqualification now requires a signature-valid response that
    mismatches the operator-trusted expectation.
  * H-01: merged metrics deduplicate by slot index
    (timestamp // SLOT_SEC), not by exact timestamp, so copies of
    one day shifted by a few seconds can no longer multiply the
    settled time.
  * H-02: scoring accepts version "0.4" bundles only. Legacy
    bundles are rejected unattributed with the reason recorded;
    archival verification (allow_legacy) never feeds scoring.
  * H-03: witness-cluster components are built from mutual
    (bidirectional) edges only, and the closed-cluster cap applies
    to those components. A one-directional mention has no effect
    on any weight: it can neither merge clusters nor drag an
    honest participant into a capped component.

v0.5 hardening (independent re-audit of v0.4, 2026-11-07):
  * R-C01 / R-M05: spot-check protocol v2 (SPEC v0.5 section 11).
    target_seq is mandatory and signed together with a revision
    counter, so editing any field of a genuine record breaks its
    signature (the v0.4 absent/-1 ambiguity is gone), and among
    the owner's signature-valid records only the highest revision
    speaks - a replayed stale response loses regardless of
    submission order, and two different responses at the top
    revision are owner equivocation (failed). See
    evaluate_spot_records.
  * R-H01: Pass 1 deduplicates BEFORE full verification. Each
    submission goes through light structural sanity, a cheap
    bundle_hash recomputation, and the seen-status table; only a
    hash never seen before reaches core.verify_bundle (which runs
    the sequential chain). Re-submitting a public bundle K times
    no longer costs K chain verifications. Duplicates of a
    verified bundle still contribute their spot-check records.
  * R-H02: the closed-component cap no longer lets one member
    set the basis. For components of size >= 3 the cap basis is
    the SECOND-largest base weight; a unique strongest member
    above the basis is exempt (unscaled, outside the capped
    pool), so a farm that mutually links itself to one honest
    mature node can neither borrow that node's weight as its cap
    nor drag the node down. Residual (disclosed in SPEC section
    7): TWO independent mature nodes endorsing a group restore
    part of the laundering, because the second mature weight
    then legitimately becomes the basis.
    [Superseded in v0.6 by the block-local cap - see below.]
  * H-02 (continued): scoring accepts version "0.5" only.

v0.6 rules revision (adversarial battery against v0.5,
2026-11-07; the bundle format does not change):
  * B3-F1: the v0.5 cap pooled a whole closed component, so a
    farm bridging into an honest mutual GROUP diluted every
    non-strongest honest member (up to -86% in the battery)
    even though the farm itself stayed under the cap, and the
    unique-strongest exemption vanished on a tie. The cap is
    now BLOCK-LOCAL: each closed component is decomposed into
    vertex-biconnected blocks (Tarjan), each block is capped
    at CLUSTER_CAP_FACTOR times the strongest base weight
    among ALL of the block's members, and a member's scale is
    the MINIMUM factor over all blocks containing it. A
    single-edge bridge lives in its own size-2 block, which
    can never bind, so foreign mass no longer enters an
    honest group's pool at all. Documented residuals (SPEC
    v0.6 section 7): hub/star topologies are all size-2
    blocks and evade caps entirely; a mature node
    biconnected INTO a farm block (>= 2 independent mutual
    paths) still lends its weight to that block's cap basis.
    AMENDMENT (v0.6, before any production scoring): the
    first v0.6 draft assigned every member to exactly ONE
    block for accounting (a "counting assignment"), which
    reopened an articulation escape - a clique member
    bridging to an honest node was counted in the never-
    binding bridge block instead of its clique, escaping
    its own cluster's discount and shrinking the clique's
    counted sum. The min-factor rule above replaces the
    assignment: every block accounts for ALL its members,
    and belonging to looser structures never loosens the
    tightest discount a member belongs to.
  * Battery-2 parity nit: spot-check records must carry
    response/signature as lowercase canonical hex - the same
    discipline the bundle schema enforces on its hex fields.
    Uppercase or mixed-case hex makes the record "unsigned"
    (ignored, never disqualifying, never passing on its own).

v0.7 rules revision (independent re-audit of v0.6,
2026-11-07; the bundle format does not change):
  * H-01: the v0.6 dedupe keyed its seen-status on bundle_hash,
    which EXCLUDES the signature - so a signature-broken copy
    of a public bundle shared the genuine bundle's hash, and
    when the broken copy was processed first, the genuine one
    was discarded as "duplicate of a rejected bundle" without
    ever being verified (order-dependent exclusion of another
    participant). Verification is now TWO-STAGE (SPEC v0.7
    section 8): stage A authenticates each submission itself
    (schema, version policy, device binding, bundle_hash,
    signature - core.verify_bundle with verify_chain=False)
    and a failure is recorded ONLY against that exact
    submission (fingerprinted WITH its signature); stage B
    verifies the chain once per content key. A submission is
    accepted iff its own stage A passes AND its content key's
    stage B passes. Spot records are pooled only from accepted
    submissions (and their exact duplicates).
  * H-02: the stage-B cache is keyed by
    core.bundle_content_key, which excludes created_at_unix,
    so a created_at-only rewrap - a new bundle_hash and a fresh
    signature over the same chain - reuses the one chain
    verification instead of forcing a full re-verification per
    copy. Aggregation budgets bound what remains: at most
    MAX_SUBMISSIONS_PER_DEVICE distinct authenticated
    submissions per device per run, and at most
    MAX_CONTENT_KEYS_PER_RUN distinct chain verifications per
    run; excess submissions are rejected with an explicit
    reason, never silently.
    [The budget-as-rejection design was itself reopened by the
    v0.7 re-audit and replaced in v0.8 - see below.]
  * M-08: no behaviour change. The cap guarantee is restated
    exactly in SPEC v0.7 sections 7/9: per-node adjusted <=
    base, per-block member sums <= the block cap, global total
    <= sum of base weights - and NO farm-wide bound beyond the
    sum of base weights.
  * L-01: floating-point sums in scoring iterate in sorted
    order and use math.fsum, so the result is byte-identical
    across processes regardless of PYTHONHASHSEED.

v0.8 rules revision (independent re-audit of v0.7,
2026-11-07; the bundle format does not change):
  * H-01 (of v0.7): the v0.7 budgets were exclusion weapons -
    the global content-key cap counted FAILED keys too, so
    signed garbage could exhaust it and get later genuine
    submissions rejected; the per-device cap could be burned
    by replaying a victim's own published bundles, whose
    signatures are public. Both rejection budgets are GONE.
    What remains is a run-level safety valve with DEFERRAL
    semantics: at most MAX_CONTENT_KEYS_PER_RUN distinct
    canonical content keys are chain-verified per run, in a
    fairness order that does not depend on arrival order -
    carried-over keys first, in key order, then new keys
    round-robin across devices (design review A2: pure key
    order would let an attacker starve a victim's key forever
    by always presenting smaller keys). Submissions beyond the
    valve are reported as DEFERRED (deferred_submissions),
    never rejected, and the deferral is recorded nowhere
    against them; while anything is deferred the run is marked
    provisional (summary "complete": False - A3). There is no
    per-device intake cap at all. A submission is rejected only
    for its own stage-A failure or its content's stage-B
    failure; deterministic chain verdicts (pass or fail) are
    cached by key within the run, so the same garbage chain is
    verified once, while an interrupted verification is never
    cached as a failure - its key is deferred instead (A5).
  * H-02 (of v0.7): the content key was hashed from the RAW
    bundle dict, so representation variants the verifier
    treats as identical (witness_peer_hashes omitted vs an
    explicit empty list - 2^C variants over C checkpoints)
    each got their own key and their own full chain
    verification. core.bundle_content_key now keys the
    verifier's NORMALISED structure (the _validate_schema
    output - the single normalisation shared with
    verification), so every such variant collapses onto the
    one key of the chain it carries.
  * M-05: exact-duplicate spot records bypassed every count:
    N copies of one signed response entered the pool N times
    and were signature-verified N times. The pool now
    deduplicates by fingerprint at harvest time, before any
    verification: one pool entry, one verification. The
    fingerprint is the canonical hash of the ENTIRE record
    (design review A1): a copied signature on a rewritten body
    is a different record, verified - and ignored - on its own
    merits, so a forgery can never occupy a genuine record's
    slot and suppress it before verification.
  * L-01 (of v0.7): Python's json module accepts NaN/Infinity
    and silently keeps the last of duplicate keys; the Java
    parser rejects both. core.strict_json_loads now guards
    every bundle/spot intake path (the CLI loaders), so the
    verdicts match.
  * L-02: a node's spot_check summary was whatever its LAST
    processed bundle produced, so a disqualified node could
    report spot_check "passed" when the passing bundle was
    processed after the failing one. The summary is now a
    deterministic reduction over the per-bundle outcomes
    (failed > passed > unsigned > no_response >
    not_evaluated), computed over bundles in bundle_hash
    order: a disqualified node's spot_check is "failed",
    independent of submission order.

Standard library only.
"""

import math
import struct
import time

import depin_core as core

# --- scoring parameters (SPEC v0.8 section 8; keep in sync) ---
MAX_FINALIZED_LAG = 300            # blocks; gate per checkpoint
MIN_CONTINUITY_RATE = 0.80         # informational threshold (flag only)
COVERAGE_DECAY_EXPONENT = 2        # effective days scale by coverage^2
MATURITY_CAP_DAYS = 365.0          # days counted into sqrt() at most
SETTLEMENT_WAIT_DAYS = 7.0         # B4: only older checkpoints settle
CLUSTER_CAP_FACTOR = 2.0           # D2: closed cluster total cap
ANOMALY_MIN_GROUP = 3              # F4: group size for anomaly flags
MAX_CONTENT_KEYS_PER_RUN = 512     # v0.8 safety valve: distinct
                                   # canonical content keys chain-
                                   # verified per scoring run; keys
                                   # beyond it are DEFERRED to a
                                   # later run, never rejected (the
                                   # v0.7 rejection budgets were
                                   # removed in v0.8 - see header)

DOMAIN_SPOT = b"QDP1/spot/v0.2"
SECONDS_PER_DAY = 86400.0
SLOT_SEC = core.SLOT_SEC           # fixed slot: the only time unit scored
_HEX_DIGITS = set("0123456789abcdef")


# ------------------------------------------------------------------
# spot check (SPEC section 11; protocol v2 since v0.5, canonical
# hex discipline added in v0.6) - derivation and response check
# ------------------------------------------------------------------

def derive_spot_target_index(num_checkpoints, challenge_block_hash):
    """Deterministically derive the spot-checked checkpoint index from a
    future finalized block hash (unpredictable at submission time)."""
    if num_checkpoints < 1:
        raise ValueError("no checkpoints")
    digest = core.sha256(DOMAIN_SPOT + challenge_block_hash
                         + struct.pack(">Q", num_checkpoints))
    return int.from_bytes(digest, "big") % num_checkpoints


def spot_response_value(block_hash, block_body):
    """The data-derived value a node must return for a spot check: it can
    only be produced from the actual block data for the bound hash."""
    return core.sha256(DOMAIN_SPOT + b"/value" + block_hash + block_body)


def _is_exact_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _is_canonical_hex(value):
    """Lowercase canonical hex: a string of even length over
    [0-9a-f] only - the same discipline the bundle schema
    enforces on its hex fields (SPEC section 5). bytes.fromhex
    alone would also accept uppercase and embedded whitespace,
    which made the spot record the one place where two different
    encodings named the same bytes (adversarial battery 2,
    benign-encoding observation; closed in v0.6)."""
    return isinstance(value, str) and len(value) % 2 == 0 and \
        all(c in _HEX_DIGITS for c in value)


def parse_spot_record(bundle, record, challenge):
    """Parse and authenticate ONE spot-check record (protocol v2).

    A record is the owner's response only if it is well-formed
    (keys response, signature, target_seq, revision - the last two
    REQUIRED exact integers, target_seq >= 0, revision >= 0;
    response and signature as lowercase canonical hex, SPEC
    v0.6 section 11) and its Ed25519 signature verifies against
    the bundle's public key over the v0.5 spot-response message
    for the given challenge (core.verify_spot_response). Returns
    (parsed, None) with parsed = {"response": bytes,
    "target_seq": int, "revision": int} for an owner-signed
    record, or (None, reason) for anything else. A record that
    fails here is "unsigned" in the v0.4 sense: anyone could have
    attached it to a copy of the bundle, so it is ignored entirely
    and can never disqualify (C-01 / R-C01).
    """
    if not isinstance(record, dict):
        return None, "spot check record is not an object"
    if not _is_canonical_hex(record.get("response")) or \
            not _is_canonical_hex(record.get("signature")):
        return None, ("spot check response/signature is not "
                      "lowercase canonical hex")
    try:
        response = bytes.fromhex(record["response"])
        signature = bytes.fromhex(record["signature"])
        pubkey = bytes.fromhex(bundle["pubkey"])
        bundle_hash = bytes.fromhex(bundle["bundle_hash"])
    except (KeyError, TypeError, ValueError) as exc:
        return None, \
            "spot check record malformed or unsigned (%s)" % exc
    target_seq = record.get("target_seq")
    revision = record.get("revision")
    if not _is_exact_int(target_seq) or target_seq < 0:
        return None, ("spot check target_seq missing or invalid: "
                      "protocol v2 requires an integer >= 0")
    if not _is_exact_int(revision) or revision < 0:
        return None, ("spot check revision missing or invalid: "
                      "protocol v2 requires an integer >= 0")
    if not core.verify_spot_response(pubkey, bundle_hash, challenge,
                                     response, target_seq, signature,
                                     revision=revision):
        return None, "spot check response signature missing or invalid"
    return {"response": response, "target_seq": target_seq,
            "revision": revision}, None


def evaluate_spot_records(bundle, records, trusted_expectation):
    """Evaluate ALL spot-check records harvested for one bundle
    against a TRUSTED expectation (protocol v2, SPEC v0.5
    section 11).

    trusted_expectation comes only from the operator's separate
    channel (never from the submissions): keys
    challenge_block_hash (hex) and expected (hex, computed
    chain-side from the real block data).

    Returns (status, reason, unsigned_count). Statuses:
      "passed" / "failed": among the owner-signed records, the
        highest revision decides (R-M05: ordering is inside the
        signature, so submission order is irrelevant). Two
        different (response, target_seq) pairs at the highest
        revision are owner equivocation and "failed". Otherwise
        the chosen pair must match the derived target index and
        the trusted expected value; any mismatch is "failed" -
        the only outcome that may disqualify.
      "unsigned": records were submitted but none of them is
        owner-signed. Ignored entirely; never disqualifies.
      "no_response": no records at all.
      "not_evaluated": the trusted expectation itself is
        malformed.
    unsigned_count counts the records that failed authentication
    (for the caller's flag); they never influence the outcome.
    """
    checkpoints = bundle.get("checkpoints") or []
    try:
        challenge = bytes.fromhex(trusted_expectation["challenge_block_hash"])
        expected = bytes.fromhex(trusted_expectation["expected"])
    except (KeyError, TypeError, ValueError) as exc:
        return "not_evaluated", \
            "trusted spot expectation malformed (%s)" % exc, 0
    if len(challenge) != 32 or len(expected) != 32:
        return "not_evaluated", \
            "trusted spot expectation has bad lengths", 0
    if not records:
        return "no_response", "no spot check response submitted", 0
    valid = []
    unsigned_count = 0
    for record in records:
        parsed, _why = parse_spot_record(bundle, record, challenge)
        if parsed is None:
            unsigned_count += 1
        else:
            valid.append(parsed)
    if not valid:
        return "unsigned", \
            ("no owner-signed spot check record among %d submitted "
             "record(s); unsigned records are ignored and can "
             "never disqualify (R-C01)" % len(records)), \
            unsigned_count
    max_revision = max(p["revision"] for p in valid)
    top = [p for p in valid if p["revision"] == max_revision]
    pairs = {(p["response"], p["target_seq"]) for p in top}
    if len(pairs) > 1:
        return "failed", \
            ("spot check equivocation: %d distinct owner-signed "
             "responses at the highest revision %d"
             % (len(pairs), max_revision)), unsigned_count
    (response, target_seq), = pairs
    derived = derive_spot_target_index(len(checkpoints), challenge)
    if target_seq != derived:
        return "failed", ("spot check target mismatch: record says "
                          "%d, derivation gives %d"
                          % (target_seq, derived)), unsigned_count
    if response != expected:
        return "failed", \
            "spot check response does not match trusted expected " \
            "value", unsigned_count
    return "passed", "ok", unsigned_count


def _spot_record_fingerprint(bundle_hash, record):
    """Fingerprint of one spot-check record for pool dedupe
    (v0.8, M-05; fingerprint definition corrected by the v0.8
    design review, A1): the canonical hash of the ENTIRE record
    - every field, exactly as submitted. Only a byte-identical
    record collapses.

    The first v0.8 draft fingerprinted (bundle_hash + response
    signature). That is NOT safe: an attacker can copy a genuine
    record's signature onto a rewritten body (different
    response, same signature and revision); under a
    signature-only fingerprint the forgery occupies the genuine
    record's slot, and if it is harvested first the genuine
    correction is dropped as a "duplicate" BEFORE verification -
    the R-C01 failure mode returning through the dedupe. With
    the whole-record fingerprint the forgery is a distinct pool
    entry: it is verified on its own merits, fails its own
    signature check, and is ignored, while the genuine record is
    evaluated normally. Non-serialisable records fall back to
    repr so that even malformed exact duplicates collapse.
    """
    try:
        digest = core.sha256(core._canonical_json(record)).hex()
    except Exception:
        digest = "repr:" + repr(record)
    return ("record", bundle_hash, digest)


def _note_first_seen(rec, bundle, submitted_at_unix):
    """Record, per checkpoint_hash, the earliest submitted_at_unix
    among this run's ACCEPTED submissions containing that
    checkpoint (the first-seen anchor for _effective_ts).
    Submissions without a usable submitted_at_unix (missing, not
    an exact int, or <= 0 - the CLI default when the operator
    supplies none) contribute no anchor: their checkpoints stand
    on their recorded timestamps. Only accepted submissions
    anchor, because only their content enters the history; a
    rejected copy's metadata proves nothing about the content's
    arrival."""
    if not _is_exact_int(submitted_at_unix) or submitted_at_unix <= 0:
        return
    first_seen = rec["first_seen"]
    for cp in bundle["checkpoints"]:
        cp_hash = cp.get("checkpoint_hash")
        if isinstance(cp_hash, str):
            if cp_hash not in first_seen or \
                    submitted_at_unix < first_seen[cp_hash]:
                first_seen[cp_hash] = submitted_at_unix


# ------------------------------------------------------------------
# per-device merged metrics (M1)
# ------------------------------------------------------------------

def _gate_passes(version, cp):
    """Quality gate (H5): for v0.2+ bundles a checkpoint counts only
    if it carries a finalized_block_number within the lag bound - a
    missing value means uncorroborated, not exempt. (Scoring accepts
    only the current version; the legacy branches are kept so the
    rule stays total over verified inputs.)"""
    finalized = cp.get("finalized_block_number")
    if version in ("0.2", "0.3", "0.4", "0.5"):
        if finalized is None:
            return False
        return cp["best_block_number"] - finalized <= MAX_FINALIZED_LAG
    return True


def _effective_ts(cp, first_seen):
    """A checkpoint's EFFECTIVE timestamp for maturity and
    settlement (v0.8, design review - first-seen anchoring;
    formula corrected min -> max with the user's approval,
    2026-11-08): max(its recorded timestamp, the earliest
    submitted_at_unix among this run's accepted submissions
    that contain this checkpoint's content, identified by
    checkpoint_hash). The effective existence time of a
    checkpoint is the LATER of the time it claims to have been
    recorded and the time the aggregation first witnessed its
    content: a bundle alone prices no time at all, and
    back-computation from public block hashes defeats both
    the chain cost and any chain cross-check, so a history
    assembled today over old block hashes earns nothing until
    real time passes after its first submission. An honest
    submitter who submits promptly has first-seen ~= recorded
    time and is unaffected; an infrequent submitter's clock
    effectively starts at submission - that is the specified
    behaviour, not an accident. With no anchor (no usable
    submitted_at_unix), the recorded timestamp stands."""
    anchor = first_seen.get(cp["checkpoint_hash"])
    if anchor is None:
        return cp["timestamp_unix"]
    return max(cp["timestamp_unix"], anchor)


def _merged_metrics(bundles, first_seen=None):
    """Merge one device's verified bundles and compute metrics.

    bundles: list of bundle dicts (already verified). Merge is
    deterministic: bundles are ordered by (first timestamp,
    bundle_hash); their checkpoints are merged by SLOT index
    (timestamp_unix // SLOT_SEC), and on a slot collision the
    earlier bundle in that order wins, so one slot is never counted
    twice. Deduplication by slot - not by exact timestamp - is the
    H-01 fix (v0.4): copies of the same period shifted by a few
    seconds land in the same slots and collapse into one.

    Span and coverage are computed on EFFECTIVE timestamps
    (_effective_ts; first_seen maps checkpoint_hash -> earliest
    submitted_at_unix among this run's accepted submissions
    containing that checkpoint).
    """
    first_seen = first_seen or {}
    ordered = sorted(
        bundles,
        key=lambda b: (b["checkpoints"][0]["timestamp_unix"],
                       b["bundle_hash"]))
    merged = []
    seen_slots = set()
    for bundle in ordered:
        version = bundle["version"]
        for cp in bundle["checkpoints"]:
            slot = cp["timestamp_unix"] // SLOT_SEC
            if slot in seen_slots:
                continue
            seen_slots.add(slot)
            merged.append((version, cp))
    merged.sort(key=lambda item: item[1]["timestamp_unix"])
    effective = [_effective_ts(cp, first_seen) for _v, cp in merged]

    first_ts = min(effective)
    last_ts = max(effective)
    expected = int((last_ts - first_ts) // SLOT_SEC) + 1
    coverage = min(1.0, len(merged) / expected) if expected > 0 else 0.0

    return {
        "merged": merged,
        "effective": effective,
        "expected": expected,
        "coverage": coverage,
        "first_ts": first_ts,
        "last_ts": last_ts,
        # filled by _finalise_metrics (gate-passing checkpoints only)
        "gate_witness_hashes": set(),
    }


def _finalise_metrics(m, scored_at_unix):
    merged = m["merged"]
    gate_passing = 0
    settled_gate_passing = 0
    settle_cutoff = scored_at_unix - SETTLEMENT_WAIT_DAYS * SECONDS_PER_DAY
    for (version, cp), eff_ts in zip(merged, m["effective"]):
        if not _gate_passes(version, cp):
            continue
        gate_passing += 1
        m["gate_witness_hashes"].update(cp.get("witness_peer_hashes", []))
        if eff_ts <= settle_cutoff:
            settled_gate_passing += 1
    decay = m["coverage"] ** COVERAGE_DECAY_EXPONENT
    out = {
        "checkpoints": len(merged),
        "expected_checkpoints": m["expected"],
        "gate_passing_checkpoints": gate_passing,
        "coverage": m["coverage"],
        "raw_days": gate_passing * SLOT_SEC / SECONDS_PER_DAY,
        "settled_days":
            settled_gate_passing * SLOT_SEC / SECONDS_PER_DAY * decay,
        "first_timestamp_unix": m["first_ts"],
        "last_timestamp_unix": m["last_ts"],
    }
    return out


# ------------------------------------------------------------------
# mutual witness graph (H3: bidirectional edges only)
# ------------------------------------------------------------------

def _witness_graph(device_witness_hashes):
    """Build claimed and mutual participant adjacency.

    device_witness_hashes: {device_id: set of witness hash hex strings
    from gate-passing checkpoints only}.
    Returns (claimed, mutual): claimed[d] = participants d claims to
    have witnessed; mutual[d] = participants where the claim is
    bidirectional. Only mutual edges are valid evidence.
    """
    ids = sorted(device_witness_hashes)
    hash_of = {d: core.peer_hash(d).hex() for d in ids}
    claimed = {}
    for d in ids:
        hashes = device_witness_hashes[d]
        claimed[d] = {other for other in ids
                      if other != d and hash_of[other] in hashes}
    mutual = {d: {o for o in claimed[d] if d in claimed[o]} for d in ids}
    return claimed, mutual


def _mutual_components(mutual):
    """Connected components (size > 1) of the MUTUAL-witness graph.

    v0.4 (H-03): components are built from bidirectional edges
    only. The v0.3 code built components from the claimed
    (one-directional) graph and then tested closedness on mutual
    edges - a test that was structurally always true, so a single
    one-directional mention by an attacker merged honest mutual
    pairs into one capped component and halved their weights. A
    mutual component needs no separate closedness test: any mutual
    edge from a member to an outsider would put that outsider in
    the same component, so every mutual component is closed by
    construction, and one-directional mentions influence nothing.
    """
    ids = sorted(mutual)
    parent = {d: d for d in ids}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for a in ids:
        for b in mutual[a]:
            union(a, b)
    comps = {}
    for d in ids:
        comps.setdefault(find(d), []).append(d)
    return [sorted(v) for v in comps.values() if len(v) > 1]


def _biconnected_blocks(members, mutual):
    """Vertex-biconnected components (blocks) of the mutual graph
    induced on `members`, via Tarjan's articulation-point
    algorithm (SPEC v0.6 section 9).

    A block is a maximal subgraph that cannot be split by
    removing one vertex. Bridge edges form size-2 blocks of
    their own, so a farm hanging off an honest group by a single
    mutual edge shares no block - and therefore no cap pool -
    with that group (B3-F1).

    The DFS is ITERATIVE (production components can reach
    thousands of vertices; recursion limits must not matter) and
    deterministic: vertices and neighbours are processed in
    sorted device-id order. Returns a deterministically ordered
    list of frozensets. A member left uncovered (impossible for
    a mutual component, where every member has an edge, but kept
    total defensively) becomes a singleton block, which can
    never bind.
    """
    member_set = set(members)
    adjacency = {d: sorted(o for o in mutual.get(d, ())
                           if o in member_set and o != d)
                 for d in members}
    disc = {}
    low = {}
    edge_stack = []
    blocks = []
    clock = [0]

    def pop_block(stop_edge):
        block = set()
        while edge_stack:
            e = edge_stack.pop()
            block.add(e[0])
            block.add(e[1])
            if e == stop_edge:
                break
        if block:
            blocks.append(frozenset(block))

    for root in sorted(member_set):
        if root in disc:
            continue
        disc[root] = low[root] = clock[0]
        clock[0] += 1
        # Frames are [vertex, parent, next neighbour index].
        stack = [[root, None, 0]]
        while stack:
            frame = stack[-1]
            u, parent = frame[0], frame[1]
            if frame[2] < len(adjacency[u]):
                v = adjacency[u][frame[2]]
                frame[2] += 1
                if v == parent:
                    continue
                if v not in disc:
                    edge_stack.append((u, v))
                    disc[v] = low[v] = clock[0]
                    clock[0] += 1
                    stack.append([v, u, 0])
                elif disc[v] < disc[u]:
                    # Back edge to an ancestor: push it once
                    # (the descendant side owns it).
                    edge_stack.append((u, v))
                    low[u] = min(low[u], disc[v])
                # else: edge to a descendant - it is pushed as a
                # back edge when the descendant scans it.
            else:
                stack.pop()
                if parent is not None:
                    low[parent] = min(low[parent], low[u])
                    if low[u] >= disc[parent]:
                        pop_block((parent, u))
    covered = set()
    for b in blocks:
        covered |= b
    for d in sorted(member_set - covered):
        blocks.append(frozenset((d,)))
    blocks.sort(key=lambda b: tuple(sorted(b)))
    return blocks


# ------------------------------------------------------------------
# main entry point
# ------------------------------------------------------------------

def score_submissions(submissions, scored_at_unix=None, profile="production",
                      spot_expectations=None,
                      max_content_keys=MAX_CONTENT_KEYS_PER_RUN,
                      carried_over_keys=None):
    """Score a list of submissions.

    submissions: list of dicts with keys
      bundle (dict), account (str, display only), account_age_days
      (number, informational only - never used for weight,
      eligibility or disqualification), submitted_at_unix (int:
      the operator-side time this submission arrived; since v0.8
      it is also the first-seen anchor for maturity/settlement -
      a checkpoint's effective timestamp is max(its recorded
      timestamp, the earliest submitted_at_unix among this run's
      accepted submissions containing its content), i.e. the
      later of the claimed recording time and the first
      witnessed arrival; it is never
      used for eligibility or disqualification), and optionally
      spot_check (dict, the node's owner-signed spot-check
      response - see evaluate_spot_records).
    scored_at_unix: scoring time, supplied by the trusted caller.
      Defaults to the current time. It is NEVER derived from
      submission data (H4).
    profile: v0.4 parameter profile name for verification
      (verifier-side choice; production uses the default).
    spot_expectations: operator-trusted spot-check expectations,
      {bundle_hash_hex: {"challenge_block_hash": hex,
      "expected": hex}}, supplied through a separate channel from
      the submissions (H7). Without an entry for a bundle, its spot
      check is recorded as not evaluated.

    Only version "0.5" bundles are scored (H-02): legacy bundles
    are rejected unattributed, with the reason recorded.

    Verification is two-stage (v0.7, H-01/H-02): stage A
    authenticates each submission itself and its failure is
    recorded only against that submission; stage B verifies the
    chain once per content key (signature and created_at_unix
    excluded), shared by every re-signed copy of the same chain.

    The run-level safety valve (v0.8): at most max_content_keys
    distinct canonical content keys are chain-verified per run.
    Verification order is a fairness order, not arrival order
    (design review A2/A3): keys carried over from a previous
    run's deferrals (carried_over_keys) are verified FIRST, in
    key order - a deferred key can therefore not be starved
    forever by newly arriving smaller keys - and the remaining
    room is allocated to new keys round-robin across devices,
    so one device's flood cannot take the whole run either.
    Submissions whose keys fall beyond the valve are DEFERRED -
    reported under deferred_submissions, never rejected - and
    nothing about the deferral is recorded against them. While
    anything is deferred the run is PROVISIONAL
    (summary["complete"] is False): a deferral can change other
    nodes' weights (cluster caps), so an incomplete run's scores
    are not final. There is no per-device intake cap (the v0.7
    rejection budgets were removed: they could be exhausted by
    third parties and thereby exclude genuine submissions).
    max_content_keys=None lifts the valve.

    Returns a JSON-serialisable dict: {"scored_at_unix", "nodes":
    [...], "rejected_submissions": [...],
    "deferred_submissions": [...], "summary": {...}}.
    Disqualified nodes carry status "disqualified" and reasons (their
    whole history is revoked: weight and count are 0). Rejected
    submissions are unattributed: they never create or damage a node.
    Deferred submissions are untouched: a later run processes them
    exactly as if they had been submitted then.
    """
    if scored_at_unix is None:
        scored_at_unix = int(time.time())
    spot_expectations = spot_expectations or {}

    # Rejected and deferred entries are collected with their
    # submission index and emitted in index order at the end, so
    # the lists read in submission order even though outcomes are
    # resolved in phases (below).
    rejected_pairs = []
    deferred_pairs = []
    duplicates_ignored = 0
    # Two-stage verification state (v0.7 H-01/H-02; deferral
    # semantics v0.8):
    #   submission_outcomes: fingerprint of the EXACT submission
    #     (canonical JSON of the whole bundle, signature included)
    #     -> "accepted" / "rejected" / "deferred". An outcome is
    #     recorded against the submission itself, NEVER against
    #     the bundle_hash: the hash excludes the signature, so a
    #     signature-broken copy shares the genuine bundle's hash,
    #     and the v0.6 table - keyed by that hash - let the broken
    #     copy's rejection poison the genuine one whenever the
    #     broken copy was processed first (H-01).
    #   seen_fingerprints: every exact submission already taken
    #     into phase 1a, so an exact duplicate is linked to its
    #     twin instead of being processed twice (R-H01).
    #   chain_cache: canonical content key
    #     (core.bundle_content_key - computed from the verifier's
    #     normalised structure; signature, bundle_hash and
    #     created_at_unix excluded) -> (ok, errors) of the stage-B
    #     chain verification, for keys this run actually verified.
    #     Success AND failure verdicts are cached, so the same
    #     garbage chain is verified exactly once per run.
    #   deferred_keys: canonical content keys beyond this run's
    #     safety valve. Their submissions are deferred, not
    #     rejected, and the deferral is a property of this run
    #     only - it is recorded nowhere against the submission.
    submission_outcomes = {}
    seen_fingerprints = set()
    chain_cache = {}
    deferred_keys = set()
    devices = {}          # device_id -> working record
    order = []

    def device_record(bundle, sub):
        device_id = bundle["device_id"]
        if device_id not in devices:
            devices[device_id] = {
                "device_id": device_id,
                # Sanitised at the source (v0.9, F-02): the
                # account string is submitter-controlled and is
                # echoed into the node record verbatim.
                "account": core.sanitize_output_string(
                    sub.get("account")),
                "bundles": [],
                "spot_records": {},
                "spot_fingerprints": {},
                "first_seen": {},
            }
            order.append(device_id)
        return devices[device_id]

    def harvest_spot_record(rec, bundle_hash, record):
        """Add a spot-check record to a device's pool, dropping
        exact duplicates by fingerprint BEFORE any signature
        verification (v0.8, M-05): one pool entry per distinct
        response, however many copies were submitted."""
        fingerprint = _spot_record_fingerprint(bundle_hash, record)
        seen = rec["spot_fingerprints"].setdefault(bundle_hash, set())
        if fingerprint in seen:
            return
        seen.add(fingerprint)
        rec["spot_records"].setdefault(bundle_hash, []).append(record)

    # Pass 1: per-submission isolation and TWO-STAGE verification
    # (v0.7, H-01/H-02; dedupe-before-chain-work is R-H01,
    # inherited; deferral semantics v0.8), version policy,
    # spot-record harvest from accepted submissions only
    # (C2/H9, C-01).
    #
    # The pass runs in three phases so that WHICH chains get
    # verified cannot depend on arrival order (v0.8):
    #   Phase 1a (per submission, arrival order): (1) light
    #     structural sanity; (2) the cheap bundle_hash
    #     recomputation - a mismatch is rejected without any
    #     chain work; (3) the exact-submission table - a
    #     submission identical to one already processed
    #     (signature included) is linked to its twin and never
    #     processed again; (4) version policy; (5) stage A:
    #     authenticate THIS submission (core.verify_bundle with
    #     verify_chain=False) - a failure is recorded against
    #     this submission alone. Survivors are "unique pending"
    #     submissions carrying a canonical content key.
    #   Phase 1b: the distinct content keys are chain-verified
    #     in lexicographic key order, up to the run's safety
    #     valve (max_content_keys); keys beyond it are deferred.
    #     Stage B therefore verifies each distinct chain at most
    #     once per run, and the verified/deferred split is a
    #     function of the key SET, not of arrival order.
    #   Phase 1c (arrival order): each pending submission is
    #     resolved - deferred (its key was not verified),
    #     rejected (its chain failed stage B), or accepted (its
    #     own stage A passed AND its key's stage B passed) -
    #     and exact duplicates then inherit their twin's
    #     outcome.
    uniques = []          # pending submissions past stage A
    duplicate_refs = []   # (idx, sub, bundle, fingerprint)
    for idx, sub in enumerate(submissions):
        try:
            if not isinstance(sub, dict) or \
                    not isinstance(sub.get("bundle"), dict):
                rejected_pairs.append((idx, {
                    "index": idx,
                    "claimed_device_id": None,
                    "account": sub.get("account")
                    if isinstance(sub, dict) else None,
                    "reasons": ["submission malformed: no bundle object"],
                }))
                continue
            bundle = sub["bundle"]
            account = sub.get("account")
            claimed_id = bundle.get("device_id")
            # (1) light structural sanity: only what the steps below
            # need - a claimed 64-char lowercase hex bundle_hash and
            # a checkpoints list. Anything deeper is verify_bundle's
            # job, reached only for first-seen hashes.
            declared_hash = bundle.get("bundle_hash")
            if not isinstance(declared_hash, str) or \
                    len(declared_hash) != 64 or \
                    any(c not in _HEX_DIGITS for c in declared_hash) or \
                    not isinstance(bundle.get("checkpoints"), list):
                rejected_pairs.append((idx, {
                    "index": idx,
                    "claimed_device_id": claimed_id,
                    "account": account,
                    "reasons": ["submission malformed: bundle_hash "
                                "is not a 64-char lowercase hex "
                                "string or checkpoints is not a list"],
                }))
                continue
            # (2) cheap hash recomputation (one canonical-JSON
            # pass, no chain iterations).
            try:
                recomputed_hash = core.compute_bundle_hash(bundle).hex()
            except Exception as exc:
                rejected_pairs.append((idx, {
                    "index": idx,
                    "claimed_device_id": claimed_id,
                    "account": account,
                    "reasons": ["bundle hash could not be computed: "
                                "%s" % exc],
                }))
                continue
            if recomputed_hash != declared_hash:
                rejected_pairs.append((idx, {
                    "index": idx,
                    "claimed_device_id": claimed_id,
                    "account": account,
                    "reasons": ["invalid bundle: bundle_hash "
                                "recomputation mismatch"],
                }))
                continue
            bundle_hash = declared_hash
            # Fingerprint of the EXACT submission (the whole
            # bundle, signature and created_at_unix included, in
            # canonical form): two submissions share a fingerprint
            # iff they are the same submission, so an outcome
            # recorded here can never leak onto a different copy
            # of the same content (H-01).
            try:
                fingerprint = core.sha256(
                    core._canonical_json(bundle)).hex()
            except Exception as exc:
                rejected_pairs.append((idx, {
                    "index": idx,
                    "claimed_device_id": claimed_id,
                    "account": account,
                    "reasons": ["submission malformed: bundle is "
                                "not canonical-JSON serialisable: "
                                "%s" % exc],
                }))
                continue
            # (3) This exact submission was already seen in this
            # run: it is never processed twice (R-H01); it
            # inherits its twin's outcome after phase 1c - and an
            # accepted duplicate's spot-check record still joins
            # the bundle's pool, because dedupe must not swallow
            # a later genuine (owner-signed) response (C-01).
            if fingerprint in seen_fingerprints:
                duplicate_refs.append((idx, sub, bundle, fingerprint))
                continue
            seen_fingerprints.add(fingerprint)
            # (4) Version policy, per submission: scoring accepts
            # the current version only (H-02). A legacy bundle is
            # rejected unattributed with the reason recorded; it
            # never creates or damages a node, and archival
            # verification never feeds back into scoring. Legacy
            # bundles reach neither stage.
            if bundle.get("version") != core.VERSION:
                submission_outcomes[fingerprint] = "rejected"
                rejected_pairs.append((idx, {
                    "index": idx,
                    "claimed_device_id": claimed_id,
                    "account": account,
                    "reasons": ["bundle version %r is not scored: "
                                "scoring accepts version %s only "
                                "(legacy bundles are archival-only)"
                                % (bundle.get("version"), core.VERSION)],
                }))
                continue
            # (5) Stage A: authenticate THIS submission - schema,
            # version policy, device binding, bundle_hash and
            # signature (verify_bundle with verify_chain=False).
            # A failure is recorded ONLY against this fingerprint:
            # a signature-broken copy is rejected on its own and
            # the genuine copy is judged by its own signature,
            # in either submission order (H-01). Rejected,
            # unattributed: an unauthenticated bundle says
            # nothing trustworthy about the identity it claims,
            # so it must never disqualify anyone (C2).
            ok_a, errors_a = core.verify_bundle(
                bundle, profile=profile, verify_chain=False)
            if not ok_a:
                submission_outcomes[fingerprint] = "rejected"
                rejected_pairs.append((idx, {
                    "index": idx,
                    "claimed_device_id": claimed_id,
                    "account": account,
                    "reasons": ["invalid bundle: %s"
                                % "; ".join(errors_a[:3])],
                }))
                continue
            # (6) Stage A passed: this submission is
            # authenticated. Its chain is verified in phase 1b,
            # once per canonical content key. A created_at-only
            # rewrap has a new bundle_hash and a fresh signature
            # but the SAME content key, so it shares the one
            # chain verification (H-02); representation variants
            # share it too, because the key is computed from the
            # verifier's normalised structure (v0.8). Whether
            # this submission is accepted, rejected (its chain
            # fails stage B) or deferred (its key falls beyond
            # this run's safety valve) is decided in phase 1c.
            content_key = core.bundle_content_key(
                bundle, profile=profile)
            uniques.append({
                "index": idx,
                "sub": sub,
                "bundle": bundle,
                "fingerprint": fingerprint,
                "claimed_id": claimed_id,
                "account": account,
                "content_key": content_key,
            })
        except Exception as exc:  # one bad submission never aborts all
            rejected_pairs.append((idx, {
                "index": idx,
                "claimed_device_id": None,
                "account": None,
                "reasons": ["submission processing error: %s" % exc],
            }))

    # Phase 1b: stage B - verify each distinct canonical content
    # key at most once, up to the run's safety valve, in the
    # fairness order (design review A2): carried-over keys
    # first, in key order; then new keys round-robin across
    # devices (devices in device_id order, each device's keys
    # in key order, one key per device per round). Neither the
    # verified set nor the deferred set depends on arrival
    # order. The representative bundle for a key is its first
    # pending submission; every bundle under one key normalises
    # to the same chain (that is what the key means), so any
    # representative verifies the same content.
    #
    # Failure caching (design review A5): a verdict RETURNED by
    # the verifier - pass or fail - is a deterministic property
    # of the content and is cached by key for the rest of this
    # run, so the same garbage chain costs one verification per
    # run however many signed copies arrive. An EXCEPTION is
    # not a verdict: an interrupted verification (timeout,
    # environment failure) is non-deterministic, is never cached
    # as a failure, and its key is treated as unverified -
    # deferred, not rejected. The cache lives within this run
    # only; carrying verdicts across runs is the pilot layer's
    # responsibility, keyed to the rules generation (SPEC
    # version).
    representatives = {}
    for pending in uniques:
        representatives.setdefault(
            pending["content_key"], pending["bundle"])
    carried_set = set(carried_over_keys) if carried_over_keys \
        else set()
    quota = None if max_content_keys is None \
        else max(0, max_content_keys)
    selected = []
    for key in sorted(k for k in representatives
                      if k in carried_set):
        if quota is not None and len(selected) >= quota:
            break
        selected.append(key)
    if quota is None or len(selected) < quota:
        new_by_device = {}
        for key, rep_bundle in representatives.items():
            if key not in carried_set:
                new_by_device.setdefault(
                    rep_bundle["device_id"], []).append(key)
        for device_keys in new_by_device.values():
            device_keys.sort()
        device_order = sorted(new_by_device)
        positions = {d: 0 for d in device_order}
        while quota is None or len(selected) < quota:
            progressed = False
            for d in device_order:
                if quota is not None and len(selected) >= quota:
                    break
                if positions[d] < len(new_by_device[d]):
                    selected.append(new_by_device[d][positions[d]])
                    positions[d] += 1
                    progressed = True
            if not progressed:
                break
    interrupted_keys = set()
    for key in selected:
        try:
            chain_cache[key] = core.verify_bundle_chain(
                representatives[key], profile=profile)
        except Exception:
            interrupted_keys.add(key)
    deferred_keys = set(representatives) - set(chain_cache)

    # Phase 1c: resolve the pending submissions in arrival order.
    for pending in uniques:
        idx = pending["index"]
        sub = pending["sub"]
        bundle = pending["bundle"]
        if pending["content_key"] in deferred_keys:
            # Deferred, NOT rejected (v0.8): the key was not
            # verified in this run - either the run's valve was
            # exhausted by higher-priority keys, or its
            # verification was interrupted (which is never
            # recorded as a failure). Nothing is recorded
            # against the submission; a later run processes it
            # as if freshly submitted, and carried-over keys go
            # first there.
            submission_outcomes[pending["fingerprint"]] = "deferred"
            if pending["content_key"] in interrupted_keys:
                reason = ("deferred: chain verification was "
                          "interrupted in this run (not a verdict "
                          "on the submission); NOT rejected - "
                          "resubmit it to a later run")
            else:
                reason = ("deferred: this run's chain "
                          "verification safety valve (%s "
                          "distinct content keys) was exhausted; "
                          "the submission was not verified in "
                          "this run and is NOT rejected - "
                          "resubmit it to a later run"
                          % max_content_keys)
            deferred_pairs.append((idx, {
                "index": idx,
                "claimed_device_id": pending["claimed_id"],
                "account": pending["account"],
                "reasons": [reason],
            }))
            continue
        ok_b, errors_b = chain_cache[pending["content_key"]]
        if not ok_b:
            # The chain itself is invalid. The rejection is
            # recorded against this submission (and, via the
            # content-key cache, shared by every copy of this
            # chain - the chain verdict is a pure function of
            # the content, so sharing it cannot misattribute
            # anything).
            submission_outcomes[pending["fingerprint"]] = "rejected"
            rejected_pairs.append((idx, {
                "index": idx,
                "claimed_device_id": pending["claimed_id"],
                "account": pending["account"],
                "reasons": ["invalid bundle: %s"
                            % "; ".join(errors_b[:3])],
            }))
            continue
        # Accepted: this submission authenticated AND its chain
        # verified. Only accepted submissions (and their exact
        # duplicates, below) contribute spot records and bundles
        # to scoring.
        submission_outcomes[pending["fingerprint"]] = "accepted"
        rec = device_record(bundle, sub)
        _note_first_seen(rec, bundle, sub.get("submitted_at_unix"))
        if sub.get("spot_check") is not None:
            harvest_spot_record(
                rec, bundle["bundle_hash"], sub["spot_check"])
        rec["bundles"].append(bundle)

    # Exact duplicates inherit their twin's outcome. Counted
    # once, never re-processed (R-H01); an accepted duplicate's
    # spot-check record still joins the bundle's pool (C-01),
    # deduplicated by fingerprint like any other record (M-05).
    for idx, sub, bundle, fingerprint in duplicate_refs:
        outcome = submission_outcomes.get(fingerprint)
        if outcome == "accepted":
            duplicates_ignored += 1
            rec = device_record(bundle, sub)
            _note_first_seen(rec, bundle, sub.get("submitted_at_unix"))
            if sub.get("spot_check") is not None:
                harvest_spot_record(
                    rec, bundle["bundle_hash"], sub["spot_check"])
        elif outcome == "deferred":
            deferred_pairs.append((idx, {
                "index": idx,
                "claimed_device_id": bundle.get("device_id"),
                "account": sub.get("account"),
                "reasons": ["deferred: exact duplicate of a "
                            "submission deferred by this run's "
                            "chain verification safety valve; "
                            "not rejected"],
            }))
        else:
            rejected_pairs.append((idx, {
                "index": idx,
                "claimed_device_id": bundle.get("device_id"),
                "account": sub.get("account"),
                "reasons": ["duplicate of a rejected bundle "
                            "(not re-verified)"],
            }))

    # Result records are sanitised as they are finalised
    # (v0.9, F-02): claimed_device_id and account are
    # submitter-controlled strings echoed verbatim, and a lone
    # surrogate among them (admitted by the JSON parser) cannot
    # be encoded as UTF-8 - left raw, it would raise
    # UnicodeEncodeError when the caller serialises the report
    # and destroy the whole run's output. Sanitising here, at
    # the single point every rejected/deferred record passes
    # through, keeps the records themselves clean for any
    # consumer, not just careful writers.
    rejected = [core.sanitize_output_record(entry)
                for _i, entry in sorted(
                    rejected_pairs, key=lambda pair: pair[0])]
    deferred = [core.sanitize_output_record(entry)
                for _i, entry in sorted(
                    deferred_pairs, key=lambda pair: pair[0])]

    # Pass 2: spot checks against operator-trusted expectations only.
    disqualify = {}       # device_id -> list of reasons
    spot_status = {}      # device_id -> status string

    def dq(device_id, reason):
        disqualify.setdefault(device_id, []).append(reason)

    flags = {d: [] for d in order}
    # The node's spot_check summary is a DETERMINISTIC reduction
    # over its per-bundle outcomes (v0.8, L-02): the strongest
    # outcome wins - failed > passed > unsigned > no_response >
    # not_evaluated - and bundles are visited in bundle_hash
    # order. The v0.7 summary was whatever the LAST processed
    # bundle produced, so a node disqualified by a failing bundle
    # could report spot_check "passed" when a passing bundle was
    # processed after it; under the reduction, disqualification
    # by spot check always yields spot_check "failed", in any
    # submission order.
    _SPOT_PRIORITY = {"failed": 0, "passed": 1, "unsigned": 2,
                      "no_response": 3, "not_evaluated": 4}
    for d in order:
        rec = devices[d]
        outcomes = []
        for bundle in sorted(rec["bundles"],
                             key=lambda b: b["bundle_hash"]):
            bundle_hash = bundle["bundle_hash"]
            trusted = spot_expectations.get(bundle_hash)
            records = rec["spot_records"].get(bundle_hash, [])
            if trusted is None:
                if records:
                    outcomes.append("not_evaluated")
                    flags[d].append(
                        "spot_check_not_evaluated: submission carried "
                        "a spot check record but no operator-trusted "
                        "expectation was supplied (submission-carried "
                        "values are never trusted)")
                continue
            # Protocol v2 (R-C01 / R-M05): only owner-signed
            # records are responses at all; among them the highest
            # signed revision decides, independent of submission
            # order. Unsigned or tampered records are counted for
            # the flag and otherwise ignored - they can never
            # disqualify anyone.
            outcome, reason, unsigned_count = evaluate_spot_records(
                bundle, records, trusted)
            if unsigned_count:
                flags[d].append(
                    "spot_check_unsigned_ignored: %d unsigned or "
                    "badly-signed spot check record(s) ignored; "
                    "only owner-signed responses are evaluated "
                    "(R-C01)" % unsigned_count)
            if outcome == "failed":
                dq(d, "spot check failed: %s" % reason)
            if outcome == "not_evaluated":
                flags[d].append(
                    "spot_check_not_evaluated: %s" % reason)
            elif outcome == "no_response":
                flags[d].append(
                    "spot_check_no_response: a trusted expectation "
                    "exists but no response was submitted")
            outcomes.append(outcome)
        spot_status[d] = min(
            outcomes, key=lambda o: _SPOT_PRIORITY[o], default=None)

    # Pass 3: merged metrics, anomaly flags, weights (C1/M1).
    live = [d for d in order if d not in disqualify]
    metrics = {}
    device_witness_hashes = {}
    for d in live:
        m = _merged_metrics(devices[d]["bundles"],
                            first_seen=devices[d]["first_seen"])
        metrics[d] = _finalise_metrics(m, scored_at_unix)
        metrics[d]["bundles_merged"] = len(devices[d]["bundles"])
        device_witness_hashes[d] = m["gate_witness_hashes"]
        devices[d]["merged"] = m["merged"]

    by_start = {}
    by_peer_pattern = {}
    for d in live:
        merged = devices[d]["merged"]
        by_start.setdefault(merged[0][1]["timestamp_unix"], []).append(d)
        pattern = tuple(cp["observed_peers"] for _v, cp in merged)
        by_peer_pattern.setdefault(pattern, []).append(d)
    for ts, group in by_start.items():
        if len(group) >= ANOMALY_MIN_GROUP:
            for d in group:
                flags[d].append(
                    "synchronized_start: %d nodes share first checkpoint "
                    "timestamp %d" % (len(group), ts))
    for pattern, group in by_peer_pattern.items():
        if len(group) >= ANOMALY_MIN_GROUP:
            for d in group:
                flags[d].append(
                    "identical_peer_pattern: %d nodes share the same "
                    "observed_peers sequence" % len(group))

    weights = {}
    for d in live:
        m = metrics[d]
        # Time wall: participation maturity only, from fixed slots.
        weights[d] = math.sqrt(min(m["settled_days"], MATURITY_CAP_DAYS))
        if m["coverage"] < MIN_CONTINUITY_RATE:
            flags[d].append(
                "low_continuity: coverage %.3f below %.2f"
                % (m["coverage"], MIN_CONTINUITY_RATE))
        if m["last_timestamp_unix"] > \
                scored_at_unix - SETTLEMENT_WAIT_DAYS * SECONDS_PER_DAY:
            flags[d].append(
                "settlement_pending: latest checkpoints are inside the "
                "%g-day settlement wait" % SETTLEMENT_WAIT_DAYS)

    # Pass 4: closed-cluster caps over mutual-edge components
    # (H3, rebuilt in v0.4 / H-03; cap basis redesigned in v0.5 /
    # R-H02; made BLOCK-LOCAL in v0.6 / B3-F1). Components come
    # from mutual edges only and are closed by construction;
    # one-directional mentions play no role anywhere in this
    # pass.
    #
    # Cap rule (SPEC v0.6 section 9, as amended): decompose
    # each closed component into vertex-biconnected blocks
    # (Tarjan). There is NO counting assignment: every block
    # accounts for ALL of its members. A block's factor is
    # 1.0 when the full sum of its members' base weights fits
    # under its cap - CLUSTER_CAP_FACTOR x the strongest base
    # weight among ALL its members - and cap / sum otherwise.
    # A member's scale is the MINIMUM factor over all blocks
    # containing it (1.0 when it sits in no binding block):
    # a node's weight is discounted by the tightest cluster
    # it belongs to, and belonging to additional looser
    # structures never loosens that discount. A size-2 block
    # can never bind (cap = 2 x max >= both bases), so bridge
    # edges - the only connection between a bridged farm and
    # an honest group - never drag the group into the farm's
    # pool, never lend the group's weight to the farm's cap,
    # and never let a bridged member escape its own block's
    # accounting.
    #
    # Amendment history: the first v0.6 draft counted every
    # member in exactly ONE of its blocks (the one minimising
    # the strongest other member). A randomized bridge check
    # then showed the articulation escape: a farm clique
    # member bridging to an honest node was counted in the
    # never-binding size-2 bridge block instead of its
    # clique, so it kept its full base outside the clique's
    # cap AND the clique's counted sum shrank (farm total
    # 8.0 -> 10.77 in the check), and symmetrically an honest
    # member could escape its own cluster's discount via a
    # bridge. The min-factor rule removes the assignment
    # entirely; regression tests pin single-bridge invariance
    # in both directions, deterministically and randomized.
    #
    # Why not a component-wide pool (v0.5)? The adversarial
    # battery (B3-F1) bridged a farm into an honest mutual
    # group with ONE mutual edge and diluted every
    # non-strongest honest member by up to 86%: the pool was
    # component-global, so foreign mass set the honest
    # members' scale factor. Earlier still, v0.4's basis (the
    # strongest member) let a bridged farm borrow the honest
    # node's weight as its cap (farm 2.0000 -> 21.1561, honest
    # 13.4164 -> 5.6768); the block-local rule keeps the v0.5
    # outcome on that attack (farm 2.0000, honest untouched)
    # AND removes the dilution (regression tests pin both).
    _claimed, mutual = _witness_graph(device_witness_hashes)
    clusters_capped = 0
    for comp in _mutual_components(mutual):
        blocks = _biconnected_blocks(comp, mutual)
        block_factors = []
        for block in blocks:
            cap = CLUSTER_CAP_FACTOR * max(weights[u] for u in block)
            # L-01: fsum over a SORTED member order - a frozenset's
            # iteration order depends on the process hash seed, and
            # float addition is not associative, so a plain sum()
            # could differ in the last bits between runs.
            block_total = math.fsum(weights[u] for u in sorted(block))
            if block_total > cap and block_total > 0:
                factor = cap / block_total
                clusters_capped += 1
            else:
                factor = 1.0
            block_factors.append((block, factor))
        for d in comp:
            own = [(factor, block) for block, factor in block_factors
                   if d in block]
            if not own:
                continue
            scale, tightest = min(
                own, key=lambda fb: (fb[0], tuple(sorted(fb[1]))))
            if scale < 1.0:
                weights[d] *= scale
                flags[d].append(
                    "closed_cluster_discount: closed "
                    "mutual-witness cluster of %d: tightest block "
                    "of %d capped at %.1fx its strongest member's "
                    "weight (scale %.4f)"
                    % (len(comp), len(tightest),
                       CLUSTER_CAP_FACTOR, scale))

    # Assemble output.
    nodes_out = []
    for d in sorted(order):
        rec = devices[d]
        if d in disqualify:
            nodes_out.append({
                "device_id": d,
                "account": rec["account"],
                "status": "disqualified",
                "raw_count": 0,
                "adjusted_weight": 0.0,
                "flags": flags.get(d, []),
                "disqualify_reasons": disqualify[d],
                "spot_check": spot_status.get(d),
                "metrics": None,
            })
        else:
            nodes_out.append({
                "device_id": d,
                "account": rec["account"],
                "status": "ok",
                "raw_count": 1,
                "adjusted_weight": weights[d],
                "flags": flags[d],
                "disqualify_reasons": [],
                "spot_check": spot_status.get(d),
                "metrics": metrics[d],
            })
    return {
        "scored_at_unix": scored_at_unix,
        "nodes": nodes_out,
        "rejected_submissions": rejected,
        "deferred_submissions": deferred,
        "summary": {
            "raw_node_count": sum(n["raw_count"] for n in nodes_out),
            "total_adjusted_weight": math.fsum(
                n["adjusted_weight"] for n in nodes_out),
            "disqualified_count": len(disqualify),
            "closed_clusters_capped": clusters_capped,
            "duplicates_ignored": duplicates_ignored,
            "rejected_count": len(rejected),
            "deferred_count": len(deferred),
            # Provisional marking (design review A3): while any
            # submission is deferred the run is incomplete and
            # its scores are not final - a deferred node can
            # change other nodes' cluster caps.
            "complete": len(deferred) == 0,
            "content_keys_verified": len(chain_cache),
            "content_keys_deferred": len(deferred_keys),
        },
    }
