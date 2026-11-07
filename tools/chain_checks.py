#!/usr/bin/env python3
"""Chain cross-checks for the Quantus DePIN aggregation pipeline.

STATUS: NOT IMPLEMENTED.

Two checks belong here and are deliberately left as stubs. They are
NOT performed anywhere in the current pipeline, and no output of this
project should be read as if they were:

1. Best-block existence / consistency check
   For every checkpoint, confirm against a Quantus node RPC that the
   claimed (best_block_number, best_block_hash) pair exists on the
   real chain and that the finalized block number is consistent.
   Without this, a bundle only proves internal consistency of a
   signed observation record (SPEC v0.3 section 7) -- the block
   hashes inside it have not been compared with the actual chain.

2. Spot-check expectation computation
   Compute the expected spot-check response value from real chain
   data (the block body bound to a checkpoint), so the scorer can
   compare it with a participant's response. Until this exists, spot
   checks can only be evaluated when an operator supplies expected
   values through the separate trusted channel supported by the
   scorer (SPEC v0.3 section 11); otherwise they are recorded as
   "not evaluated".

Both stubs return a machine-readable "not_implemented" status so
callers can surface the gap honestly instead of silently skipping it.
"""

NOT_IMPLEMENTED = "not_implemented"


def check_best_blocks(bundle):
    """NOT IMPLEMENTED: verify checkpoint block hashes against a node RPC."""
    return {
        "check": "best_block_existence",
        "status": NOT_IMPLEMENTED,
        "detail": (
            "No RPC cross-check is performed. Checkpoint block "
            "numbers/hashes are taken from the signed bundle as-is."
        ),
    }


def compute_spot_expectation(bundle, challenge_block_hash):
    """NOT IMPLEMENTED: derive the expected spot-check value from chain data."""
    return {
        "check": "spot_check_expectation",
        "status": NOT_IMPLEMENTED,
        "detail": (
            "Expected spot-check values are not computed from chain "
            "data. Spot checks are evaluated only against "
            "operator-supplied expectations, or recorded as not "
            "evaluated."
        ),
    }


def chain_check_report(bundles):
    """Summarise the (unimplemented) chain checks for a set of bundles."""
    return {
        "status": NOT_IMPLEMENTED,
        "checks": [
            check_best_blocks(bundles[0]) if bundles else {
                "check": "best_block_existence",
                "status": NOT_IMPLEMENTED,
                "detail": "No bundles to check.",
            },
            {
                "check": "spot_check_expectation",
                "status": NOT_IMPLEMENTED,
                "detail": (
                    "Expected spot-check values are not computed "
                    "from chain data."
                ),
            },
        ],
    }
