#!/usr/bin/env python3
"""Cross-implementation check between this Java app and the Python
reference implementation of the DePIN proof format (current format
v0.5; the reference is the source of truth for what "current" is —
this script reads core.VERSION rather than assuming it).

Sections:
  A. Current format, both directions:
     1. Python builds a bundle -> Java verifies it (test +
        production profiles).
     2. Java builds a bundle -> Python verifies it via depin_cli.py
        (test + production profiles).
     3. For identical inputs, both builders must produce the
        identical bundle_hash and signature (Ed25519 is
        deterministic and the canonical JSON must match
        byte-for-byte).
  B. Legacy parity: Python builds v0.4 and v0.3 bundles. The Java
     verifier accepts each ONLY under its matching legacy profile;
     both verifiers' default (current-format) paths reject them;
     the reference accepts them with allow_legacy=True (sanity
     that they are genuinely valid legacy bundles).
  C. Reject set (audit R-M01): mutations of a valid current-format
     bundle — witness ordering / duplicates / cap, JSON null in a
     typed field, out-of-range integers, and text-level grammar
     violations ("seq":00, a fractional integer) — must be judged
     INVALID by BOTH implementations.

Run via tests/run-tests.sh --cross (sets DEPIN_COMPANION_TEST_CP to
the compiled harness classes). Standard library only.
"""

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEPIN_SRC = os.path.normpath(os.path.join(HERE, "..", "..", "tools"))
sys.path.insert(0, DEPIN_SRC)

import depin_core as core  # noqa: E402

_java_on_path = shutil.which("java")
JAVA_HOME = os.environ.get(
    "JAVA_HOME",
    os.path.dirname(os.path.dirname(_java_on_path)) if _java_on_path
    else "")
JAVA = os.path.join(JAVA_HOME, "bin", "java") if JAVA_HOME else "java"
CP = os.environ["DEPIN_COMPANION_TEST_CP"]
SEED = bytes(range(1, 33))
SEED_HEX = SEED.hex()
CURRENT = core.VERSION

FAILURES = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ((" :: " + detail) if detail and not ok else ""))
    if not ok:
        FAILURES.append(name)


def synthetic_observations(count, witnesses=False):
    obs = []
    for i in range(count):
        number = 350000 + i * 100
        o = {
            "timestamp_unix": 1762000000 + i * 600,
            "best_block_number": number,
            "best_block_hash": hashlib.sha256(
                ("quantus-synthetic-block-%d" % number).encode()).hexdigest(),
            "observed_peers": 8 + (i % 5),
            "finalized_block_number": number - 10,
        }
        if witnesses:
            o["witness_peers"] = ["peer-alpha", "peer-beta"]
        obs.append(o)
    return obs


def java_run(main_class, *args):
    return subprocess.run(
        [JAVA, "-cp", CP, "app.quantusnode.depin." + main_class, *args],
        capture_output=True, text=True)


def java_verify(bundle_path, iterations, version=None):
    args = [bundle_path, str(iterations)]
    if version is not None:
        args.append(version)
    r = java_run("BundleVerifyMain", *args)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def python_cli_verify(bundle_path, profile):
    r = subprocess.run(
        [sys.executable, os.path.join(DEPIN_SRC, "depin_cli.py"),
         "verify", "--bundle", bundle_path, "--profile", profile],
        capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def python_verify_dict(bundle, profile="test", allow_legacy=False):
    ok, _errors = core.verify_bundle(
        bundle, profile=profile, allow_legacy=allow_legacy)
    return ok


def write_bundle(tmp, name, bundle):
    path = os.path.join(tmp, name)
    with open(path, "w") as f:
        json.dump(bundle, f, indent=2)
        f.write("\n")
    return path


def section_a(tmp):
    obs8 = synthetic_observations(8)
    obs2 = synthetic_observations(2)
    obs_path = os.path.join(tmp, "obs8.json")
    with open(obs_path, "w") as f:
        json.dump(obs8, f)
    obs2_path = os.path.join(tmp, "obs2.json")
    with open(obs2_path, "w") as f:
        json.dump(obs2, f)

    # --- direction 1: Python builds -> Java verifies ---
    for profile, obs, iters in (("test", obs8, 50),
                                ("production", obs2, 1_000_000)):
        bundle = core.build_bundle(SEED, obs, profile=profile)
        path = write_bundle(tmp, "py-%s.json" % profile, bundle)
        ok, detail = java_verify(path, iters, CURRENT)
        check("python->java verify (%s)" % profile, ok, detail)

    # --- direction 2 + 3: Java builds -> Python verifies, and the
    # deterministic outputs must equal the Python builder's ---
    for profile, obs, opath, iters in (
            ("test", obs8, obs_path, 50),
            ("production", obs2, obs2_path, 1_000_000)):
        out_path = os.path.join(tmp, "java-%s.json" % profile)
        r = java_run("BundleGenMain", SEED_HEX, opath, str(iters), out_path)
        check("java gen runs (%s)" % profile, r.returncode == 0,
              (r.stdout + r.stderr).strip())
        if r.returncode != 0:
            continue
        ok, detail = python_cli_verify(out_path, profile)
        check("java->python CLI verify (%s)" % profile, ok, detail)
        with open(out_path) as f:
            java_bundle = json.load(f)
        py_bundle = core.build_bundle(SEED, obs, profile=profile)
        check("bundle_hash identical (%s)" % profile,
              java_bundle["bundle_hash"] == py_bundle["bundle_hash"],
              "%s != %s" % (java_bundle["bundle_hash"], py_bundle["bundle_hash"]))
        check("signature identical (%s)" % profile,
              java_bundle["signature"] == py_bundle["signature"])


def section_b(tmp):
    obs = synthetic_observations(4)
    for legacy in ("0.4", "0.3"):
        bundle = core.build_bundle(SEED, obs, profile="test", version=legacy)
        path = write_bundle(tmp, "py-legacy-%s.json" % legacy, bundle)
        ok, detail = java_verify(path, 50, legacy)
        check("legacy %s: java verifies under its legacy profile" % legacy,
              ok, detail)
        ok, detail = java_verify(path, 50, CURRENT)
        check("legacy %s: java current profile rejects" % legacy, not ok)
        check("legacy %s: python default rejects" % legacy,
              not python_verify_dict(bundle, profile="test"))
        check("legacy %s: python allow_legacy accepts (sanity)" % legacy,
              python_verify_dict(bundle, profile="test", allow_legacy=True))


def section_c(tmp):
    base = core.build_bundle(
        SEED, synthetic_observations(4, witnesses=True), profile="test")
    base_path = write_bundle(tmp, "reject-base.json", base)
    ok, detail = java_verify(base_path, 50, CURRENT)
    check("reject set: unmutated witness bundle valid in java", ok, detail)
    check("reject set: unmutated witness bundle valid in python",
          python_verify_dict(base))

    def mutated(name, fn):
        b = copy.deepcopy(base)
        fn(b)
        path = write_bundle(tmp, "reject-%s.json" % name, b)
        okj, _ = java_verify(path, 50, CURRENT)
        okp = python_verify_dict(b)
        check("reject set: %s invalid in java" % name, not okj)
        check("reject set: %s invalid in python" % name, not okp)

    def reverse_witnesses(b):
        w = b["checkpoints"][0]["witness_peer_hashes"]
        w.reverse()

    def duplicate_witness(b):
        w = b["checkpoints"][0]["witness_peer_hashes"]
        w[1] = w[0]

    def too_many_witnesses(b):
        ws = sorted(
            hashlib.sha256(("witness-%d" % i).encode()).hexdigest()
            for i in range(513))
        b["checkpoints"][0]["witness_peer_hashes"] = ws

    def null_finalized(b):
        b["checkpoints"][0]["finalized_block_number"] = None

    def negative_seq(b):
        b["checkpoints"][0]["seq"] = -1

    def negative_timestamp(b):
        b["checkpoints"][0]["timestamp_unix"] = -5

    def negative_best(b):
        b["checkpoints"][0]["best_block_number"] = -1

    mutated("witness-reversed", reverse_witnesses)
    mutated("witness-duplicate", duplicate_witness)
    mutated("witness-513", too_many_witnesses)
    mutated("finalized-null", null_finalized)
    mutated("seq-negative", negative_seq)
    mutated("timestamp-negative", negative_timestamp)
    mutated("best-negative", negative_best)

    # Text-level grammar violations: neither side may even parse
    # these into an acceptable bundle.
    text = json.dumps(base)
    for name, old, new in (
            ("seq-leading-zero", '"seq": 0', '"seq": 00'),
            ("peers-fractional",
             '"observed_peers": 8', '"observed_peers": 8.0')):
        if old not in text:
            check("reject set: %s mutation applicable" % name, False,
                  "pattern %r not found" % old)
            continue
        bad_text = text.replace(old, new, 1)
        path = os.path.join(tmp, "reject-%s.json" % name)
        with open(path, "w") as f:
            f.write(bad_text)
        okj, _ = java_verify(path, 50, CURRENT)
        check("reject set: %s invalid in java" % name, not okj)
        try:
            parsed = json.loads(bad_text)
            okp = python_verify_dict(parsed)
        except Exception:
            okp = False
        check("reject set: %s invalid in python" % name, not okp)


def main():
    tmp = tempfile.mkdtemp(prefix="depin-crosscheck-")
    print("reference (python) current format: %s" % CURRENT)
    section_a(tmp)
    section_b(tmp)
    section_c(tmp)
    print("----")
    if FAILURES:
        print("crosscheck FAILED: %s" % ", ".join(FAILURES))
        return 1
    print("crosscheck OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
