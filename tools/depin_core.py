"""Quantus DePIN proof format - core generation and verification.

Implements SPEC.md v0.5. Legacy bundles (v0.1 / v0.2 / v0.3 / v0.4)
are verified only when the caller explicitly passes
allow_legacy=True (archival use); the default verification path
accepts the current version only. Standard library only.

v0.5 changes over v0.4 (independent re-audit of v0.4,
2026-11-07):
  * R-C01 / R-M05: the spot-response protocol is version 2. The
    v0.4 message encoded an absent target_seq as i64(-1), which is
    byte-identical to an explicit target_seq of -1 - while the
    scorer treated the two differently, so a third party could add
    "target_seq": -1 to the owner's genuine signed response and
    turn it into disqualifying evidence without touching the
    signature (R-C01); and with no ordering inside the signature, a
    replayed stale response could override a correction (R-M05).
    In v0.5 target_seq is MANDATORY (an integer >= 0) and a signed
    revision counter (u64) is part of the message under the v0.5
    domain. The scorer keeps only the highest-revision valid
    responses (see depin_scorer).
  * Version policy: "0.4" joins the legacy set. The v0.5 chain
    seed, checkpoint hash and bundle hash use fresh domains with
    byte layouts unchanged from v0.4.
  * compute_bundle_hash() is public: the scorer recomputes the
    (cheap) bundle hash and deduplicates BEFORE any full
    verification, so duplicate submissions never re-run the chain
    (R-H01, scorer side).

v0.4 hardening over v0.3 (independent review of v0.3,
2026-11-07):
  * H-02: version policy. verify_bundle rejects legacy versions by
    default; scoring never accepts them (see depin_scorer). The old
    compatibility rule let freshly minted legacy bundles bypass the
    fixed parameter table, the identity-bound chain and the quality
    gate.
  * H-01 (core side): the v0.4 chain seed additionally binds the
    checkpoint's slot index (timestamp // SLOT_SEC), its finalized
    block number and its observed peer count, so a computed chain
    segment belongs to exactly one slot of one observation.
  * H-05: fail-fast verification order - schema, version policy,
    bundle_hash (a mismatch stops verification immediately), then
    signature (a failure stops it), and only then checkpoint hashes
    and the sequential-chain recomputation.
  * C-01 (core side): spot-check responses are authenticated. A
    response counts as the bundle owner's only when it carries an
    Ed25519 signature by the bundle key over the v0.4 spot-response
    domain message (sign_spot_response / verify_spot_response).
  * L-02: the schema range of finalized_block_number now matches
    its i64 encoding (max 2**63 - 1), so a signed input can no
    longer crash verification with a struct error.

v0.3 hardening over v0.2 (independent review, 2026-11-07):
  * C1: checkpoint interval and chain iteration count are no longer
    participant-chosen. They are fixed by a versioned parameter table
    (PARAM_PROFILES below, mirrored in SPEC section 4). A v0.3 bundle
    whose params differ from the active profile fails verification.
  * H2 (partial): the v0.3 chain seed binds the device public key and
    a network identifier, so chain work cannot be replayed across
    identities or networks.
  * H8/H9/M2: strict schema validation (types, required fields,
    canonical lowercase hex, integer ranges, count caps) runs before
    any recomputation; the bundle signature is verified before the
    expensive sequential-chain recomputation; hex is canonical form
    (lowercase, no whitespace) and comparisons are on bytes.
v0.2 additions over v0.1 (kept): optional ``finalized_block_number``
and ``witness_peer_hashes`` checkpoint fields, hashed under the v0.2
checkpoint domain. v0.1 bundles are verified with the original v0.1
encoding, unchanged.
"""

import hashlib
import json
import struct

import ed25519_rfc8032 as ed

FORMAT = "quantus-depin-proof"
VERSION = "0.5"
SUPPORTED_VERSIONS = ("0.1", "0.2", "0.3", "0.4", "0.5")
LEGACY_VERSIONS = ("0.1", "0.2", "0.3", "0.4")

DOMAIN_SEED = b"QDP1/seed/v0.1"
DOMAIN_SEED_V03 = b"QDP1/seed/v0.3"
DOMAIN_SEED_V04 = b"QDP1/seed/v0.4"
DOMAIN_SEED_V05 = b"QDP1/seed/v0.5"
DOMAIN_CKPT = b"QDP1/ckpt/v0.1"
DOMAIN_CKPT_V02 = b"QDP1/ckpt/v0.2"
DOMAIN_CKPT_V03 = b"QDP1/ckpt/v0.3"
DOMAIN_CKPT_V04 = b"QDP1/ckpt/v0.4"
DOMAIN_CKPT_V05 = b"QDP1/ckpt/v0.5"
DOMAIN_BUNDLE = b"QDP1/bundle/v0.1"
DOMAIN_BUNDLE_V03 = b"QDP1/bundle/v0.3"
DOMAIN_BUNDLE_V04 = b"QDP1/bundle/v0.4"
DOMAIN_BUNDLE_V05 = b"QDP1/bundle/v0.5"
DOMAIN_PEER = b"QDP1/peer/v0.2"
DOMAIN_SPOT_RESP_V05 = b"QDP1/spot-resp/v0.5"

ZERO32 = b"\x00" * 32

# Network identifier bound into the v0.3 chain seed. It names the
# network context this proof system serves; deployments serving a
# different network must use a different identifier so chains can
# never be replayed across networks.
NETWORK_ID = b"quantus"

# Fixed slot length (seconds) of one checkpoint. Scoring derives
# earned days only from gate-passing checkpoint counts times this
# slot (SPEC v0.3 section 8); a bundle's declared interval never
# scales its own weight.
SLOT_SEC = 600

# --- versioned parameter table (SPEC v0.5 section 4) ---
# A v0.3+ bundle must carry exactly the parameters of ONE profile, and
# the profile is chosen by the verifier/operator context, never by
# the participant's input beyond the bundle itself (both profiles use
# the same slot; only the chain work differs). "test" exists so the
# test suite stays fast; production verification uses "production"
# and must not enable "test".
PARAM_PROFILES = {
    "production": {"interval_sec": SLOT_SEC, "iterations": 1_000_000},
    "test": {"interval_sec": SLOT_SEC, "iterations": 50},
}

# Legacy (v0.1 / v0.2) defaults, kept for building historical-format
# bundles in tests. Their declared params are accepted for format
# verification (compatibility), but never trusted by scoring.
DEFAULT_ITERATIONS = 1_000_000
DEFAULT_INTERVAL_SEC = SLOT_SEC

# --- schema / resource caps (H8/H9) ---
MAX_CHECKPOINTS = 200_000
MAX_WITNESSES_PER_CHECKPOINT = 512
MAX_LEGACY_ITERATIONS_PER_CHECKPOINT = 5_000_000
# Total sequential-chain work a legacy bundle may demand of the
# verifier. v0.3 bundles are bounded by MAX_CHECKPOINTS times the
# fixed profile iterations instead (full recomputation of very long
# production bundles remains a known limitation, SPEC section 7).
MAX_LEGACY_TOTAL_ITERATIONS = 200_000_000

_TOP_LEVEL_KEYS = {
    "format", "version", "device_id", "pubkey", "created_at_unix",
    "params", "checkpoints", "bundle_hash", "signature",
}
_PARAM_KEYS = {
    "hash", "signature", "iterations_per_checkpoint",
    "checkpoint_interval_sec",
}
_CKPT_BASE_KEYS = {
    "seq", "timestamp_unix", "best_block_number", "best_block_hash",
    "observed_peers", "iterations", "prev_checkpoint_hash",
    "chain_state", "checkpoint_hash",
}
_CKPT_V02_KEYS = _CKPT_BASE_KEYS | {
    "finalized_block_number", "witness_peer_hashes",
}
_HEX_DIGITS = set("0123456789abcdef")


def sha256(data):
    return hashlib.sha256(data).digest()


def device_id_from_pubkey(pubkey):
    return "qdp1-" + sha256(pubkey)[:12].hex()


def peer_hash(peer_id):
    """Hash a peer identifier (device_id or libp2p peer ID) for witness lists.

    Bundles carry only this hash, never the raw identifier (SPEC v0.2
    section 9). The aggregator rebuilds the correspondence by hashing
    the identifiers of known participants. The domain string is kept
    stable across format versions: it names the hashing scheme, not
    the bundle version.
    """
    if isinstance(peer_id, str):
        peer_id = peer_id.encode("utf-8")
    return sha256(DOMAIN_PEER + peer_id)


def sequential_chain(prev_state, block_hash, seq, block_number, iterations):
    """Advance the sequential hash chain for one checkpoint interval.

    v0.1 / v0.2 seed: binds the previous chain state and the latest
    block hash, so the segment cannot be computed before that block
    exists.
    """
    seed = sha256(
        DOMAIN_SEED
        + prev_state
        + block_hash
        + struct.pack(">Q", seq)
        + struct.pack(">Q", block_number)
    )
    state = seed
    for _ in range(iterations):
        state = sha256(state)
    return state


def sequential_chain_v03(prev_state, block_hash, seq, block_number,
                         iterations, pubkey):
    """v0.3 chain segment: the seed additionally binds the device
    public key and the network identifier, so a computed chain is
    valid for exactly one identity on one network (H2 mitigation)."""
    seed = sha256(
        DOMAIN_SEED_V03
        + pubkey
        + NETWORK_ID
        + prev_state
        + block_hash
        + struct.pack(">Q", seq)
        + struct.pack(">Q", block_number)
    )
    state = seed
    for _ in range(iterations):
        state = sha256(state)
    return state


def _sequential_chain_bound(domain, prev_state, block_hash, seq,
                            block_number, iterations, pubkey, slot,
                            finalized_block_number, peers):
    """Shared seed layout of the v0.4 / v0.5 chain segment: the
    seed binds, in order, the version domain, the device public
    key, the network identifier, the previous chain state, the
    observed block hash, seq, block number, the checkpoint's slot
    index (timestamp // SLOT_SEC), its finalized block number
    (i64, -1 when absent) and its observed peer count. Binding the
    slot means a computed segment cannot be re-timestamped into a
    different slot (H-01), and binding finalized/peers means the
    segment belongs to one specific observation record."""
    fin = -1 if finalized_block_number is None \
        else int(finalized_block_number)
    seed = sha256(
        domain
        + pubkey
        + NETWORK_ID
        + prev_state
        + block_hash
        + struct.pack(">Q", seq)
        + struct.pack(">Q", block_number)
        + struct.pack(">Q", slot)
        + struct.pack(">q", fin)
        + struct.pack(">I", peers)
    )
    state = seed
    for _ in range(iterations):
        state = sha256(state)
    return state


def sequential_chain_v04(prev_state, block_hash, seq, block_number,
                         iterations, pubkey, slot,
                         finalized_block_number, peers):
    """v0.4 chain segment (SPEC v0.4 section 4, shared contract
    with the Android implementation - do not change the byte
    layout). Kept so v0.4 bundles remain verifiable for archives."""
    return _sequential_chain_bound(
        DOMAIN_SEED_V04, prev_state, block_hash, seq, block_number,
        iterations, pubkey, slot, finalized_block_number, peers)


def sequential_chain_v05(prev_state, block_hash, seq, block_number,
                         iterations, pubkey, slot,
                         finalized_block_number, peers):
    """v0.5 chain segment: seed inputs identical to v0.4, under
    the v0.5 domain (SPEC v0.5 section 4; shared contract with the
    Android implementation - do not change the byte layout)."""
    return _sequential_chain_bound(
        DOMAIN_SEED_V05, prev_state, block_hash, seq, block_number,
        iterations, pubkey, slot, finalized_block_number, peers)


def _ckpt_base_enc(seq, timestamp_unix, block_number, block_hash, peers,
                   prev_checkpoint_hash, iterations, chain_state):
    return (
        struct.pack(">Q", seq)
        + struct.pack(">q", timestamp_unix)
        + struct.pack(">Q", block_number)
        + block_hash
        + struct.pack(">I", peers)
        + prev_checkpoint_hash
        + struct.pack(">Q", iterations)
        + chain_state
    )


def checkpoint_hash(seq, timestamp_unix, block_number, block_hash, peers,
                    prev_checkpoint_hash, iterations, chain_state):
    """v0.1 checkpoint hash (original encoding, kept for compatibility)."""
    return sha256(DOMAIN_CKPT + _ckpt_base_enc(
        seq, timestamp_unix, block_number, block_hash, peers,
        prev_checkpoint_hash, iterations, chain_state))


def _ckpt_hash_v02enc(domain, seq, timestamp_unix, block_number,
                      block_hash, peers, prev_checkpoint_hash, iterations,
                      chain_state, finalized_block_number,
                      witness_peer_hashes):
    """Shared v0.2-style encoding: base fields, then finalized number
    as i64 (-1 when absent), witness count as u32, and the witness
    hashes concatenated in sorted order. Absent optional fields
    therefore have exactly one canonical encoding."""
    fin = -1 if finalized_block_number is None else int(finalized_block_number)
    witnesses = sorted(witness_peer_hashes)
    enc = _ckpt_base_enc(
        seq, timestamp_unix, block_number, block_hash, peers,
        prev_checkpoint_hash, iterations, chain_state)
    enc += struct.pack(">q", fin)
    enc += struct.pack(">I", len(witnesses))
    for w in witnesses:
        enc += w
    return sha256(domain + enc)


def checkpoint_hash_v02(seq, timestamp_unix, block_number, block_hash,
                        peers, prev_checkpoint_hash, iterations,
                        chain_state, finalized_block_number,
                        witness_peer_hashes):
    """v0.2 checkpoint hash."""
    return _ckpt_hash_v02enc(
        DOMAIN_CKPT_V02, seq, timestamp_unix, block_number, block_hash,
        peers, prev_checkpoint_hash, iterations, chain_state,
        finalized_block_number, witness_peer_hashes)


def checkpoint_hash_v03(seq, timestamp_unix, block_number, block_hash,
                        peers, prev_checkpoint_hash, iterations,
                        chain_state, finalized_block_number,
                        witness_peer_hashes):
    """v0.3 checkpoint hash: v0.2 field encoding under the v0.3
    domain, so hashes can never be confused across format versions."""
    return _ckpt_hash_v02enc(
        DOMAIN_CKPT_V03, seq, timestamp_unix, block_number, block_hash,
        peers, prev_checkpoint_hash, iterations, chain_state,
        finalized_block_number, witness_peer_hashes)


def checkpoint_hash_v04(seq, timestamp_unix, block_number, block_hash,
                        peers, prev_checkpoint_hash, iterations,
                        chain_state, finalized_block_number,
                        witness_peer_hashes):
    """v0.4 checkpoint hash: the v0.2-style field encoding (base
    fields, finalized as i64, witness count as u32, sorted witness
    hashes) under the v0.4 domain only (shared contract - the
    encoding itself is unchanged from v0.3)."""
    return _ckpt_hash_v02enc(
        DOMAIN_CKPT_V04, seq, timestamp_unix, block_number, block_hash,
        peers, prev_checkpoint_hash, iterations, chain_state,
        finalized_block_number, witness_peer_hashes)


def checkpoint_hash_v05(seq, timestamp_unix, block_number, block_hash,
                        peers, prev_checkpoint_hash, iterations,
                        chain_state, finalized_block_number,
                        witness_peer_hashes):
    """v0.5 checkpoint hash: the same field encoding as v0.4
    under the v0.5 domain (shared contract - only the domain
    differs)."""
    return _ckpt_hash_v02enc(
        DOMAIN_CKPT_V05, seq, timestamp_unix, block_number, block_hash,
        peers, prev_checkpoint_hash, iterations, chain_state,
        finalized_block_number, witness_peer_hashes)


# ------------------------------------------------------------------
# spot-check response authentication, protocol v2
# (C-01 + R-C01 + R-M05, SPEC v0.5 section 11)
# ------------------------------------------------------------------

def _spot_fields_valid(target_seq, revision):
    """Protocol v2 field rules, shared by signing and verification:
    target_seq is a mandatory exact integer in [0, 2**63) and
    revision an exact integer in [0, 2**64). Booleans are not
    integers here. In v0.4 an absent target_seq was encoded as -1,
    byte-identical to an explicit -1, which let a third party
    rewrite the meaning of a genuine signed record (R-C01); v2
    removes the absent encoding entirely."""
    if not isinstance(target_seq, int) \
            or isinstance(target_seq, bool) \
            or target_seq < 0 or target_seq >= 2**63:
        return False
    if not isinstance(revision, int) \
            or isinstance(revision, bool) \
            or revision < 0 or revision >= 2**64:
        return False
    return True


def spot_response_message(bundle_hash, challenge_block_hash, response,
                          target_seq, revision=0):
    """The exact byte string a spot-check response signature
    covers (protocol v2): DOMAIN_SPOT_RESP_V05 || bundle_hash[32]
    || challenge[32] || response[32] || target_seq as i64be ||
    revision as u64be. Every field is mandatory and bound, so
    adding or altering any record field breaks the signature, and
    the revision counter authenticates the ordering between an
    owner's successive responses (R-M05). Shared contract with the
    Android implementation - do not change."""
    return (
        DOMAIN_SPOT_RESP_V05
        + bundle_hash
        + challenge_block_hash
        + response
        + struct.pack(">q", target_seq)
        + struct.pack(">Q", revision)
    )


def sign_spot_response(seed, bundle_hash, challenge_block_hash,
                       response, target_seq, revision=0):
    """Sign a spot-check response with the device identity key
    (protocol v2). All hash/response arguments are 32-byte values.
    Raises ValueError on a missing, negative or non-integer
    target_seq or a negative revision: such a response is invalid
    by construction and must never be produced."""
    for name, value in (("bundle_hash", bundle_hash),
                        ("challenge_block_hash", challenge_block_hash),
                        ("response", response)):
        if len(value) != 32:
            raise ValueError("%s must be 32 bytes" % name)
    if not _spot_fields_valid(target_seq, revision):
        raise ValueError(
            "target_seq must be an integer >= 0 and revision an "
            "integer >= 0 (protocol v2: target_seq is mandatory)")
    return ed.sign(seed, spot_response_message(
        bundle_hash, challenge_block_hash, response, target_seq,
        revision))


def verify_spot_response(pubkey, bundle_hash, challenge_block_hash,
                         response, target_seq, signature, revision=0):
    """Verify a spot-check response signature against the bundle
    owner's public key (protocol v2). Returns False (never raises)
    for malformed inputs - including a missing/invalid target_seq
    or revision: an unverifiable response is simply not the
    owner's."""
    if len(pubkey) != 32 or len(bundle_hash) != 32 or \
            len(challenge_block_hash) != 32 or len(response) != 32 or \
            len(signature) != 64:
        return False
    if not _spot_fields_valid(target_seq, revision):
        return False
    return ed.verify(pubkey, spot_response_message(
        bundle_hash, challenge_block_hash, response, target_seq,
        revision), signature)


def _canonical_json(obj):
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _reject_json_constant(name):
    raise ValueError(
        "strict JSON: constant %s is not accepted (NaN/Infinity "
        "are not JSON)" % name)


def _object_without_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(
                "strict JSON: duplicate object key %r" % (key,))
        obj[key] = value
    return obj


def strict_json_loads(text):
    """Parse JSON text under the intake discipline (v0.8, L-01):
    the non-JSON constants NaN / Infinity / -Infinity are refused
    (Python's json module accepts them by default and produces
    floats no other implementation admits), and duplicate object
    keys are refused (the default keeps the last value silently,
    so one text could mean different things to different
    parsers). The Android implementation's parser already rejects
    both forms; this loader makes the Python intake verdict match
    it for bundle and spot-check JSON. Raises ValueError on any
    violation (json.JSONDecodeError is a ValueError subclass).
    """
    return json.loads(
        text,
        parse_constant=_reject_json_constant,
        object_pairs_hook=_object_without_duplicate_keys)


def sanitize_output_string(value):
    """Make a submitter-controlled string safe to echo into a
    result document (v0.9, F-02). Python's json parser admits
    lone UTF-16 surrogates (e.g. a device_id that is the JSON
    string "\\ud800"); such a string cannot be encoded as UTF-8,
    so echoing it into a report written with ensure_ascii=False
    raises UnicodeEncodeError and destroys the whole output.
    Lone surrogates - the only code points a Python str can
    hold that UTF-8 cannot encode - are replaced with U+FFFD;
    every other character is preserved exactly. Non-strings
    pass through unchanged."""
    if not isinstance(value, str):
        return value
    try:
        value.encode("utf-8")
        return value
    except UnicodeEncodeError:
        pass
    return "".join(
        "\ufffd" if 0xD800 <= ord(ch) <= 0xDFFF else ch
        for ch in value)


def sanitize_output_record(entry):
    """Apply sanitize_output_string to every string field (and
    every string in list fields, e.g. "reasons") of a result
    record, returning a new dict. Used where rejected/deferred
    submission records are finalised, so a poisoned echoed value
    can never reach a serialised report (v0.9, F-02)."""
    out = {}
    for key, value in entry.items():
        if isinstance(value, list):
            out[key] = [sanitize_output_string(v) for v in value]
        else:
            out[key] = sanitize_output_string(value)
    return out


def _bundle_domain(version):
    if version == "0.5":
        return DOMAIN_BUNDLE_V05
    if version == "0.4":
        return DOMAIN_BUNDLE_V04
    if version == "0.3":
        return DOMAIN_BUNDLE_V03
    return DOMAIN_BUNDLE


def compute_bundle_hash(bundle):
    """Recompute a bundle's bundle_hash from its contents: the
    version's bundle domain over the canonical JSON of every field
    except bundle_hash and signature. This is a single cheap pass
    (no chain work), which is exactly why the scorer can afford to
    recompute it for every submission and deduplicate BEFORE any
    full verification (R-H01). Raises on non-serialisable input;
    callers that accept untrusted input must guard the call."""
    core = {
        k: v for k, v in bundle.items()
        if k not in ("bundle_hash", "signature")
    }
    version = bundle.get("version")
    return sha256(_bundle_domain(version) + _canonical_json(core))


def _bundle_hash(bundle_without_signature):
    return compute_bundle_hash(bundle_without_signature)


def _canonical_content(norm, profile):
    """The canonical content of an already-normalised bundle
    (the `norm` dict produced by _validate_schema): everything
    that determines the checkpoint chain, in a fixed key set
    with hex fields rendered as lowercase hex text. Fields the
    chain does not depend on - signature, bundle_hash,
    created_at_unix - are absent by construction.

    This is THE canonical form for content keying (v0.8): it is
    built from the verifier's own normalised structure, so any
    two raw bundles the verifier cannot distinguish (an omitted
    optional field vs its explicit empty/default form, object
    key order, hex case is already excluded by the schema) map
    to the same content. There is deliberately no second
    normalisation anywhere: _validate_schema is the single
    source, shared by verification and keying.
    """
    checkpoints = []
    for cp in norm["checkpoints"]:
        checkpoints.append({
            "seq": cp["seq"],
            "timestamp_unix": cp["timestamp_unix"],
            "best_block_number": cp["best_block_number"],
            "best_block_hash": cp["best_block_hash"].hex(),
            "observed_peers": cp["observed_peers"],
            "iterations": cp["iterations"],
            "prev_checkpoint_hash": cp["prev_checkpoint_hash"].hex(),
            "chain_state": cp["chain_state"].hex(),
            "checkpoint_hash": cp["checkpoint_hash"].hex(),
            "finalized_block_number": cp["finalized_block_number"],
            "witness_peer_hashes":
                [w.hex() for w in cp["witness_peer_hashes"]],
        })
    return {
        "profile": profile,
        "format": FORMAT,
        "version": norm["version"],
        "device_id": norm["device_id"],
        "pubkey": norm["pubkey"].hex(),
        "iterations_per_checkpoint": norm["iterations"],
        "checkpoint_interval_sec": norm["interval_sec"],
        "checkpoints": checkpoints,
    }


def bundle_content_key(bundle, profile="production"):
    """The bundle's content key (v0.7; canonicalised in v0.8,
    SPEC v0.8 section 8): a hash of everything that determines
    the checkpoint chain - format, version, device_id, public
    key, params and the full checkpoint list (including the
    prev_checkpoint_hash linkage) - under the verification
    profile. It deliberately EXCLUDES the signature, bundle_hash
    and created_at_unix: none of them affects the chain
    (bundle_hash is excluded because it covers created_at_unix),
    so a re-signed or created_at-rewrapped copy of the same
    chain shares the genuine bundle's content key and therefore
    its single chain verification (H-02).

    v0.8 (H-02, second round): the key is computed from the
    verifier's NORMALISED checkpoint structure
    (_canonical_content over the _validate_schema output), not
    from the raw submitted dict. The v0.7 key hashed the raw
    dict, so representation variants the verifier treats as
    identical - `witness_peer_hashes` omitted vs an explicit
    empty list, forking 2^C keys over C checkpoints - each
    forced their own full chain verification even though only
    one chain existed. Keying the normalised form collapses
    every such variant onto the single key of the chain it
    actually carries.

    Raises ValueError for a schema-invalid bundle (callers run
    stage-A authentication first, so a key is only ever computed
    for bundles that passed it)."""
    errors, norm = _validate_schema(bundle, profile)
    if norm is None:
        raise ValueError(
            "content key is undefined for a schema-invalid "
            "bundle: %s" % "; ".join(errors[:3]))
    return sha256(_canonical_json(
        _canonical_content(norm, profile))).hex()


def build_bundle(seed, observations, iterations=None,
                 interval_sec=None, created_at_unix=None,
                 version=VERSION, profile="production"):
    """Build and sign a proof bundle.

    observations: list of dicts with keys timestamp_unix, best_block_number,
    best_block_hash (hex), observed_peers. Must be in chronological order;
    timestamps strictly increasing and block numbers non-decreasing,
    matching what the verifier will require.

    v0.2+ observations may additionally carry:
      finalized_block_number (int, optional)
      witness_peers (list of peer identifier strings, optional) - stored
        in the bundle only as sorted SHA-256 hashes
    With version="0.1" the v0.2 fields are ignored and a plain v0.1
    bundle is produced.

    For versions "0.3" / "0.4" / "0.5" the interval and iteration
    count come from the named parameter profile (PARAM_PROFILES);
    passing different iterations/interval_sec values is an error -
    participants cannot choose the parameters that determine
    earned time (C1). Legacy versions keep the historical
    free-parameter behaviour (they exist so tests and archives can
    still produce historical-format bundles; verifiers reject them
    by default).
    """
    if version not in SUPPORTED_VERSIONS:
        raise ValueError("unsupported version: %r" % (version,))
    if not observations:
        raise ValueError("at least one observation is required")

    if version in ("0.3", "0.4", "0.5"):
        if profile not in PARAM_PROFILES:
            raise ValueError("unknown parameter profile: %r" % (profile,))
        prof = PARAM_PROFILES[profile]
        if iterations is not None and iterations != prof["iterations"]:
            raise ValueError(
                "iterations are fixed by profile %r (%d), got %r"
                % (profile, prof["iterations"], iterations))
        if interval_sec is not None and interval_sec != prof["interval_sec"]:
            raise ValueError(
                "interval is fixed by profile %r (%d), got %r"
                % (profile, prof["interval_sec"], interval_sec))
        iterations = prof["iterations"]
        interval_sec = prof["interval_sec"]
    else:
        if iterations is None:
            iterations = DEFAULT_ITERATIONS
        if interval_sec is None:
            interval_sec = DEFAULT_INTERVAL_SEC
    if iterations < 1:
        raise ValueError("iterations must be >= 1")

    pubkey = ed.publickey_from_seed(seed)
    checkpoints = []
    prev_state = ZERO32
    prev_ckpt_hash = ZERO32
    prev_ts = None
    prev_block_number = None

    for seq, obs in enumerate(observations):
        ts = int(obs["timestamp_unix"])
        block_number = int(obs["best_block_number"])
        block_hash = bytes.fromhex(obs["best_block_hash"])
        if len(block_hash) != 32:
            raise ValueError("best_block_hash must be 32 bytes")
        peers = int(obs["observed_peers"])
        if prev_ts is not None and ts <= prev_ts:
            raise ValueError("timestamps must be strictly increasing")
        if prev_block_number is not None and block_number < prev_block_number:
            raise ValueError("best_block_number must be non-decreasing")

        finalized = None
        if version in ("0.2", "0.3", "0.4", "0.5"):
            finalized = obs.get("finalized_block_number")
            if finalized is not None:
                finalized = int(finalized)
                if finalized < 0 or finalized > block_number or \
                        finalized > 2**63 - 1:
                    raise ValueError(
                        "finalized_block_number must be within "
                        "[0, min(best_block_number, 2**63 - 1)]")
        if version == "0.5":
            state = sequential_chain_v05(
                prev_state, block_hash, seq, block_number, iterations,
                pubkey, ts // SLOT_SEC, finalized, peers)
        elif version == "0.4":
            state = sequential_chain_v04(
                prev_state, block_hash, seq, block_number, iterations,
                pubkey, ts // SLOT_SEC, finalized, peers)
        elif version == "0.3":
            state = sequential_chain_v03(prev_state, block_hash, seq,
                                         block_number, iterations,
                                         pubkey)
        else:
            state = sequential_chain(prev_state, block_hash, seq,
                                     block_number, iterations)
        cp = {
            "seq": seq,
            "timestamp_unix": ts,
            "best_block_number": block_number,
            "best_block_hash": block_hash.hex(),
            "observed_peers": peers,
            "iterations": iterations,
            "prev_checkpoint_hash": prev_ckpt_hash.hex(),
            "chain_state": state.hex(),
        }
        if version in ("0.2", "0.3", "0.4", "0.5"):
            if finalized is not None:
                cp["finalized_block_number"] = finalized
            witness_hashes = sorted(
                {peer_hash(p) for p in obs.get("witness_peers", [])})
            if witness_hashes:
                cp["witness_peer_hashes"] = [w.hex() for w in witness_hashes]
            witness_bytes = [bytes.fromhex(h)
                             for h in cp.get("witness_peer_hashes", [])]
            if version == "0.5":
                ck_hash = checkpoint_hash_v05(
                    seq, ts, block_number, block_hash, peers,
                    prev_ckpt_hash, iterations, state, finalized,
                    witness_bytes)
            elif version == "0.4":
                ck_hash = checkpoint_hash_v04(
                    seq, ts, block_number, block_hash, peers,
                    prev_ckpt_hash, iterations, state, finalized,
                    witness_bytes)
            elif version == "0.3":
                ck_hash = checkpoint_hash_v03(
                    seq, ts, block_number, block_hash, peers,
                    prev_ckpt_hash, iterations, state, finalized,
                    witness_bytes)
            else:
                ck_hash = checkpoint_hash_v02(
                    seq, ts, block_number, block_hash, peers,
                    prev_ckpt_hash, iterations, state, finalized,
                    witness_bytes)
        else:
            ck_hash = checkpoint_hash(seq, ts, block_number, block_hash,
                                      peers, prev_ckpt_hash, iterations,
                                      state)
        cp["checkpoint_hash"] = ck_hash.hex()
        checkpoints.append(cp)
        prev_state = state
        prev_ckpt_hash = ck_hash
        prev_ts = ts
        prev_block_number = block_number

    if created_at_unix is None:
        created_at_unix = checkpoints[-1]["timestamp_unix"]

    bundle = {
        "format": FORMAT,
        "version": version,
        "device_id": device_id_from_pubkey(pubkey),
        "pubkey": pubkey.hex(),
        "created_at_unix": int(created_at_unix),
        "params": {
            "hash": "SHA-256",
            "signature": "Ed25519",
            "iterations_per_checkpoint": iterations,
            "checkpoint_interval_sec": interval_sec,
        },
        "checkpoints": checkpoints,
    }
    b_hash = _bundle_hash(bundle)
    bundle["bundle_hash"] = b_hash.hex()
    bundle["signature"] = ed.sign(
        seed, _bundle_domain(version) + b_hash).hex()
    return bundle


# ------------------------------------------------------------------
# strict schema validation (H8/H9/M2) - runs before any recomputation
# ------------------------------------------------------------------

def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _parse_canonical_hex(value, nbytes, field, errors):
    """Parse a hex field that must be in canonical form: a string of
    exactly 2*nbytes lowercase hex digits, no whitespace (M2). Returns
    bytes, or None after recording an error."""
    if not isinstance(value, str):
        errors.append("%s: not a string" % field)
        return None
    if len(value) != 2 * nbytes:
        errors.append("%s: hex length %d != %d"
                      % (field, len(value), 2 * nbytes))
        return None
    if any(c not in _HEX_DIGITS for c in value):
        errors.append("%s: hex not in canonical lowercase form" % field)
        return None
    return bytes.fromhex(value)


def _check_int(value, field, lo, hi, errors):
    if not _is_int(value):
        errors.append("%s: not an integer" % field)
        return None
    if value < lo or value > hi:
        errors.append("%s: %d outside [%d, %d]" % (field, value, lo, hi))
        return None
    return value


def _validate_schema(bundle, profile):
    """Validate structure strictly and normalise fields to bytes/ints.

    Returns (errors, norm). norm is None when errors is non-empty.
    No hashing or signature work happens here (H8 ordering).
    """
    errors = []

    def fail(msg):
        errors.append(msg)

    if not isinstance(bundle, dict):
        return ["bundle is not a JSON object"], None
    extra = set(bundle) - _TOP_LEVEL_KEYS
    if extra:
        fail("unknown top-level fields: %s" % sorted(extra))
    missing = _TOP_LEVEL_KEYS - set(bundle)
    if missing:
        fail("missing top-level fields: %s" % sorted(missing))
        return errors, None
    if bundle.get("format") != FORMAT:
        fail("format mismatch")
    version = bundle.get("version")
    if version not in SUPPORTED_VERSIONS:
        fail("version mismatch or unsupported: %r" % (version,))
        return errors, None

    device_id = bundle.get("device_id")
    if not isinstance(device_id, str) or \
            not device_id.startswith("qdp1-") or \
            len(device_id) != 29 or \
            any(c not in _HEX_DIGITS for c in device_id[5:]):
        fail("device_id malformed")
    pubkey = _parse_canonical_hex(bundle.get("pubkey"), 32, "pubkey",
                                   errors)
    created_at = _check_int(bundle.get("created_at_unix"),
                            "created_at_unix", 0, 2**63 - 1, errors)

    params = bundle.get("params")
    if not isinstance(params, dict):
        fail("params missing or not an object")
        return errors, None
    extra = set(params) - _PARAM_KEYS
    if extra:
        fail("unknown params fields: %s" % sorted(extra))
    if params.get("hash") != "SHA-256":
        fail("params.hash must be 'SHA-256'")
    if params.get("signature") != "Ed25519":
        fail("params.signature must be 'Ed25519'")
    iterations = _check_int(params.get("iterations_per_checkpoint"),
                            "params.iterations_per_checkpoint",
                            1, 2**63 - 1, errors)
    interval = _check_int(params.get("checkpoint_interval_sec"),
                          "params.checkpoint_interval_sec",
                          1, 2**63 - 1, errors)
    if version in ("0.3", "0.4", "0.5"):
        if profile not in PARAM_PROFILES:
            fail("unknown parameter profile: %r" % (profile,))
            return errors, None
        prof = PARAM_PROFILES[profile]
        if iterations is not None and iterations != prof["iterations"]:
            fail("params.iterations_per_checkpoint %r does not match "
                 "the fixed profile %r (%d)"
                 % (iterations, profile, prof["iterations"]))
        if interval is not None and interval != prof["interval_sec"]:
            fail("params.checkpoint_interval_sec %r does not match "
                 "the fixed profile %r (%d)"
                 % (interval, profile, prof["interval_sec"]))
    elif iterations is not None and \
            iterations > MAX_LEGACY_ITERATIONS_PER_CHECKPOINT:
        fail("params.iterations_per_checkpoint exceeds legacy cap %d"
             % MAX_LEGACY_ITERATIONS_PER_CHECKPOINT)

    raw_checkpoints = bundle.get("checkpoints")
    if not isinstance(raw_checkpoints, list) or not raw_checkpoints:
        fail("checkpoints missing or empty")
        return errors, None
    if len(raw_checkpoints) > MAX_CHECKPOINTS:
        fail("too many checkpoints: %d > %d"
             % (len(raw_checkpoints), MAX_CHECKPOINTS))
        return errors, None

    allowed_ckpt_keys = _CKPT_V02_KEYS \
        if version in ("0.2", "0.3", "0.4", "0.5") else _CKPT_BASE_KEYS
    norm_checkpoints = []
    total_iterations = 0
    for idx, cp in enumerate(raw_checkpoints):
        tag = "checkpoint[%d]" % idx
        if not isinstance(cp, dict):
            fail("%s: not an object" % tag)
            return errors, None
        extra = set(cp) - allowed_ckpt_keys
        if extra:
            fail("%s: unknown fields: %s" % (tag, sorted(extra)))
        missing = _CKPT_BASE_KEYS - set(cp)
        if missing:
            fail("%s: missing fields: %s" % (tag, sorted(missing)))
            return errors, None
        n = {}
        n["seq"] = _check_int(cp.get("seq"), tag + ".seq",
                              0, MAX_CHECKPOINTS, errors)
        n["timestamp_unix"] = _check_int(
            cp.get("timestamp_unix"), tag + ".timestamp_unix",
            0, 2**63 - 1, errors)
        n["best_block_number"] = _check_int(
            cp.get("best_block_number"), tag + ".best_block_number",
            0, 2**64 - 1, errors)
        n["best_block_hash"] = _parse_canonical_hex(
            cp.get("best_block_hash"), 32, tag + ".best_block_hash",
            errors)
        n["observed_peers"] = _check_int(
            cp.get("observed_peers"), tag + ".observed_peers",
            0, 2**32 - 1, errors)
        n["iterations"] = _check_int(
            cp.get("iterations"), tag + ".iterations",
            1, 2**63 - 1, errors)
        if n["iterations"] is not None:
            total_iterations += n["iterations"]
            if iterations is not None and n["iterations"] != iterations:
                fail("%s: iterations != params.iterations_per_checkpoint"
                     % tag)
        n["prev_checkpoint_hash"] = _parse_canonical_hex(
            cp.get("prev_checkpoint_hash"), 32,
            tag + ".prev_checkpoint_hash", errors)
        n["chain_state"] = _parse_canonical_hex(
            cp.get("chain_state"), 32, tag + ".chain_state", errors)
        n["checkpoint_hash"] = _parse_canonical_hex(
            cp.get("checkpoint_hash"), 32, tag + ".checkpoint_hash",
            errors)
        n["finalized_block_number"] = None
        n["witness_peer_hashes"] = []
        if version in ("0.2", "0.3", "0.4", "0.5"):
            if "finalized_block_number" in cp:
                # L-02 (v0.4): the checkpoint-hash encoding packs
                # this field as i64, so the schema range must stop
                # at 2**63 - 1; the old u64 bound let a signed input
                # through to a struct.error during recomputation.
                n["finalized_block_number"] = _check_int(
                    cp.get("finalized_block_number"),
                    tag + ".finalized_block_number",
                    0, 2**63 - 1, errors)
            raw_w = cp.get("witness_peer_hashes", [])
            if not isinstance(raw_w, list):
                fail("%s: witness_peer_hashes not a list" % tag)
            elif len(raw_w) > MAX_WITNESSES_PER_CHECKPOINT:
                fail("%s: too many witness hashes: %d > %d"
                     % (tag, len(raw_w), MAX_WITNESSES_PER_CHECKPOINT))
            else:
                witnesses = []
                for w in raw_w:
                    parsed = _parse_canonical_hex(
                        w, 32, tag + ".witness_peer_hashes[]", errors)
                    if parsed is not None:
                        witnesses.append(parsed)
                if witnesses != sorted(witnesses) or \
                        len(set(witnesses)) != len(witnesses):
                    fail("%s: witness_peer_hashes not sorted/unique"
                         % tag)
                n["witness_peer_hashes"] = witnesses
        norm_checkpoints.append(n)

    if version not in ("0.3", "0.4", "0.5") and \
            total_iterations > MAX_LEGACY_TOTAL_ITERATIONS:
        fail("total chain iterations %d exceeds verifier budget %d"
             % (total_iterations, MAX_LEGACY_TOTAL_ITERATIONS))

    bundle_hash = _parse_canonical_hex(bundle.get("bundle_hash"), 32,
                                        "bundle_hash", errors)
    signature = _parse_canonical_hex(bundle.get("signature"), 64,
                                      "signature", errors)
    if errors:
        return errors, None
    norm = {
        "version": version,
        "device_id": device_id,
        "pubkey": pubkey,
        "created_at_unix": created_at,
        "iterations": iterations,
        "interval_sec": interval,
        "checkpoints": norm_checkpoints,
        "bundle_hash": bundle_hash,
        "signature": signature,
    }
    return errors, norm


def verify_bundle(bundle, profile="production", allow_legacy=False,
                  verify_chain=True):
    """Verify a proof bundle.

    By default only the current format version (VERSION, "0.5") is
    accepted. Legacy bundles (v0.1 / v0.2 / v0.3 / v0.4) are
    verified only when allow_legacy=True is passed explicitly - an
    archival operation that must never feed scoring (H-02, SPEC
    v0.5 section 12). profile names the parameter profile a
    v0.3+ bundle must match (verifier-side choice; production
    verification uses the default). Returns (ok, errors).

    Order (H8, fail-fast since v0.4 / H-05): strict schema
    validation, version policy, device_id binding, then the
    bundle_hash recomputation - a mismatch stops verification
    immediately - then the signature - a failure stops it too - and
    only then per-checkpoint hashes and linkage and the expensive
    sequential-chain recomputation. A forged or tampered bundle is
    therefore rejected before it can make the verifier burn chain
    work, even when its signature (over the original hash) is a
    genuine, publicly known one.

    verify_chain=False (v0.7) stops right after the signature
    check: stage-A authentication. The result then judges THIS
    exact submission - its schema, version, device binding,
    bundle_hash and signature - and says nothing about the
    checkpoint chain. The scorer authenticates every submission
    this way (a failure is recorded against that submission
    alone, H-01) and runs the chain separately through
    verify_bundle_chain, once per content key (H-02). Other
    callers should keep the default.
    """
    errors, norm = _validate_schema(bundle, profile)
    if norm is None:
        return False, errors
    version = norm["version"]
    pubkey = norm["pubkey"]

    def fail(msg):
        errors.append(msg)

    if version != VERSION and not allow_legacy:
        fail("bundle version %r is a legacy version: verification "
             "accepts version %s by default; pass allow_legacy=True "
             "only for archival verification (H-02)" % (version, VERSION))
        return False, errors

    if norm["device_id"] != device_id_from_pubkey(pubkey):
        fail("device_id does not match pubkey")

    # Fail-fast (H-05): the bundle hash authenticates every field.
    # If it does not recompute, nothing else in the bundle can be
    # trusted and no further work - in particular no chain
    # recomputation - is spent on it.
    if _bundle_hash(bundle) != norm["bundle_hash"]:
        fail("bundle_hash recomputation mismatch")
        return False, errors
    if not ed.verify(pubkey,
                     _bundle_domain(version) + norm["bundle_hash"],
                     norm["signature"]):
        fail("signature verification failed")
        return False, errors

    if not verify_chain:
        # Stage-A authentication only (v0.7): everything above -
        # schema, version policy, device binding, bundle_hash,
        # signature - has been checked; the checkpoint chain has
        # NOT. See the verify_bundle docstring.
        return (len(errors) == 0), errors

    _verify_chain_loops(norm, errors)
    return (len(errors) == 0), errors


def _verify_chain_loops(norm, errors):
    """Checkpoint-hash/linkage checks and the sequential-chain
    recomputation: the steps of verify_bundle that come after
    authentication, appending any problems to `errors`.

    Assumes the bundle has already been authenticated (schema,
    bundle_hash and signature checked) and takes the normalised
    form from _validate_schema. Shared by verify_bundle and
    verify_bundle_chain so the two can never drift apart.
    """
    version = norm["version"]
    pubkey = norm["pubkey"]

    def fail(msg):
        errors.append(msg)

    checkpoints = norm["checkpoints"]
    prev_ckpt_hash = ZERO32
    prev_ts = None
    prev_block_number = None
    for idx, cp in enumerate(checkpoints):
        tag = "checkpoint[%d]" % idx
        if cp["seq"] != idx:
            fail("%s: seq %r != expected %d (missing or reordered)"
                 % (tag, cp["seq"], idx))
        if cp["prev_checkpoint_hash"] != prev_ckpt_hash:
            fail("%s: prev_checkpoint_hash linkage broken" % tag)
        if prev_ts is not None and cp["timestamp_unix"] <= prev_ts:
            fail("%s: timestamp not strictly increasing" % tag)
        if prev_block_number is not None and \
                cp["best_block_number"] < prev_block_number:
            fail("%s: best_block_number decreased" % tag)
        finalized = cp["finalized_block_number"]
        if finalized is not None and finalized > cp["best_block_number"]:
            fail("%s: finalized_block_number outside "
                 "[0, best_block_number]" % tag)
        if version == "0.5":
            recomputed_hash = checkpoint_hash_v05(
                idx, cp["timestamp_unix"], cp["best_block_number"],
                cp["best_block_hash"], cp["observed_peers"],
                prev_ckpt_hash, cp["iterations"], cp["chain_state"],
                finalized, cp["witness_peer_hashes"])
        elif version == "0.4":
            recomputed_hash = checkpoint_hash_v04(
                idx, cp["timestamp_unix"], cp["best_block_number"],
                cp["best_block_hash"], cp["observed_peers"],
                prev_ckpt_hash, cp["iterations"], cp["chain_state"],
                finalized, cp["witness_peer_hashes"])
        elif version == "0.3":
            recomputed_hash = checkpoint_hash_v03(
                idx, cp["timestamp_unix"], cp["best_block_number"],
                cp["best_block_hash"], cp["observed_peers"],
                prev_ckpt_hash, cp["iterations"], cp["chain_state"],
                finalized, cp["witness_peer_hashes"])
        elif version == "0.2":
            recomputed_hash = checkpoint_hash_v02(
                idx, cp["timestamp_unix"], cp["best_block_number"],
                cp["best_block_hash"], cp["observed_peers"],
                prev_ckpt_hash, cp["iterations"], cp["chain_state"],
                finalized, cp["witness_peer_hashes"])
        else:
            recomputed_hash = checkpoint_hash(
                idx, cp["timestamp_unix"], cp["best_block_number"],
                cp["best_block_hash"], cp["observed_peers"],
                prev_ckpt_hash, cp["iterations"], cp["chain_state"])
        if recomputed_hash != cp["checkpoint_hash"]:
            fail("%s: checkpoint_hash recomputation mismatch" % tag)
        prev_ckpt_hash = cp["checkpoint_hash"]
        prev_ts = cp["timestamp_unix"]
        prev_block_number = cp["best_block_number"]
    if errors:
        # Checkpoint-level inconsistencies are already decisive;
        # do not spend chain recomputation on them (H-05).
        return

    # Sequential chain recomputation (most expensive) last, reached
    # only by bundles that passed every cheaper check.
    prev_state = ZERO32
    for idx, cp in enumerate(checkpoints):
        tag = "checkpoint[%d]" % idx
        if version == "0.5":
            recomputed_state = sequential_chain_v05(
                prev_state, cp["best_block_hash"], idx,
                cp["best_block_number"], cp["iterations"], pubkey,
                cp["timestamp_unix"] // SLOT_SEC,
                cp["finalized_block_number"], cp["observed_peers"])
        elif version == "0.4":
            recomputed_state = sequential_chain_v04(
                prev_state, cp["best_block_hash"], idx,
                cp["best_block_number"], cp["iterations"], pubkey,
                cp["timestamp_unix"] // SLOT_SEC,
                cp["finalized_block_number"], cp["observed_peers"])
        elif version == "0.3":
            recomputed_state = sequential_chain_v03(
                prev_state, cp["best_block_hash"], idx,
                cp["best_block_number"], cp["iterations"], pubkey)
        else:
            recomputed_state = sequential_chain(
                prev_state, cp["best_block_hash"], idx,
                cp["best_block_number"], cp["iterations"])
        if recomputed_state != cp["chain_state"]:
            fail("%s: sequential chain recomputation mismatch" % tag)
            break
        prev_state = cp["chain_state"]


def verify_bundle_chain(bundle, profile="production"):
    """Stage-B chain verification (v0.7, SPEC v0.7 section 8).

    Runs ONLY the checkpoint-hash/linkage checks and the
    sequential-chain recomputation - the expensive part of
    verify_bundle - for a bundle the caller has already
    authenticated (stage A: verify_bundle with
    verify_chain=False). The scorer runs this once per content
    key (bundle_content_key) and shares the result across every
    authenticated submission carrying that chain, so a
    created_at-only rewrap cannot force a second chain
    verification (H-02). The key and this verification read the
    SAME normalised form (the _validate_schema output), so the
    cached verdict always belongs to the chain the key names
    (v0.8). Returns (ok, errors).
    """
    errors, norm = _validate_schema(bundle, profile)
    if norm is None:
        return False, errors
    _verify_chain_loops(norm, errors)
    return (len(errors) == 0), errors
