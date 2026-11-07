"""Pure-Python Ed25519 (RFC 8032) - standard library only.

Implemented with extended twisted-Edwards coordinates (add-2008-hwcd /
dbl-2008-hwcd) so signing and verification are fast enough for a
prototype without any third-party dependency. Correctness is pinned by
the RFC 8032 test vectors in tests/test_depin.py.

Prototype use only: not constant-time, not side-channel hardened.
"""

import hashlib

_q = 2**255 - 19
_l = 2**252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, _q - 2, _q)


_d = (-121665 * _inv(121666)) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1) % _q
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = x * _I % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = (4 * _inv(5)) % _q
_Bx = _xrecover(_By)
_B = (_Bx, _By, 1, (_Bx * _By) % _q)
_IDENTITY = (0, 1, 1, 0)


def _point_add(P, Q):
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = (Y1 - X1) * (Y2 - X2) % _q
    Bv = (Y1 + X1) * (Y2 + X2) % _q
    C = 2 * _d * T1 * T2 % _q
    D = 2 * Z1 * Z2 % _q
    E = (Bv - A) % _q
    F = (D - C) % _q
    G = (D + C) % _q
    H = (Bv + A) % _q
    return (E * F % _q, G * H % _q, F * G % _q, E * H % _q)


def _point_double(P):
    X1, Y1, Z1, _T1 = P
    A = X1 * X1 % _q
    Bv = Y1 * Y1 % _q
    C = 2 * Z1 * Z1 % _q
    D = (-A) % _q
    E = ((X1 + Y1) * (X1 + Y1) - A - Bv) % _q
    G = (D + Bv) % _q
    F = (G - C) % _q
    H = (D - Bv) % _q
    return (E * F % _q, G * H % _q, F * G % _q, E * H % _q)


def _scalarmult(P, e):
    Q = _IDENTITY
    for bit in bin(e)[2:]:
        Q = _point_double(Q)
        if bit == "1":
            Q = _point_add(Q, P)
    return Q


def _point_equal(P, Q):
    X1, Y1, Z1, _ = P
    X2, Y2, Z2, _ = Q
    return (X1 * Z2 - X2 * Z1) % _q == 0 and (Y1 * Z2 - Y2 * Z1) % _q == 0


def _encode_point(P):
    X, Y, Z, _T = P
    zinv = _inv(Z)
    x = X * zinv % _q
    y = Y * zinv % _q
    b = bytearray(y.to_bytes(32, "little"))
    if x & 1:
        b[31] |= 0x80
    return bytes(b)


def _decode_point(s):
    if len(s) != 32:
        raise ValueError("encoded point must be 32 bytes")
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    sign = (s[31] >> 7) & 1
    if y >= _q:
        raise ValueError("y out of range")
    x = _xrecover(y)
    # RFC 8032 decoding: when x == 0 the sign bit must be 0. This check
    # must run BEFORE the parity flip below: flipping 0 gives _q, which
    # is congruent to 0 modulo _q and would silently accept the
    # non-canonical "negative zero" encoding (v0.3 hardening, H6).
    if x == 0 and sign == 1:
        raise ValueError("invalid sign bit for x=0")
    if (x & 1) != sign:
        x = _q - x
    if (-x * x + y * y - 1 - _d * x * x * y * y) % _q != 0:
        raise ValueError("point not on curve")
    return (x, y, 1, x * y % _q)


def _is_small_order(P):
    """True iff P lies in the small-order (torsion) subgroup.

    Points of order 1, 2, 4 or 8 satisfy [8]P == identity. Accepting
    such a point as a public key (or as R) makes verification
    forgeable, so verify() rejects them (v0.3 hardening, H6).
    """
    return _point_equal(_scalarmult(P, 8), _IDENTITY)


def _hint(data):
    return int.from_bytes(hashlib.sha512(data).digest(), "little")


def _expand_seed(seed):
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a_bytes = bytearray(h[:32])
    a_bytes[0] &= 248
    a_bytes[31] &= 63
    a_bytes[31] |= 64
    a = int.from_bytes(a_bytes, "little")
    return a, h[32:]


def publickey_from_seed(seed):
    """Derive the 32-byte Ed25519 public key from a 32-byte seed."""
    a, _prefix = _expand_seed(seed)
    return _encode_point(_scalarmult(_B, a))


def sign(seed, msg):
    """Return the 64-byte Ed25519 signature of msg under seed."""
    a, prefix = _expand_seed(seed)
    pk = _encode_point(_scalarmult(_B, a))
    r = _hint(prefix + msg) % _l
    R_enc = _encode_point(_scalarmult(_B, r))
    k = _hint(R_enc + pk + msg) % _l
    S = (r + k * a) % _l
    return R_enc + S.to_bytes(32, "little")


def verify(pk, msg, sig):
    """Return True iff sig is a valid Ed25519 signature of msg under pk."""
    if len(pk) != 32 or len(sig) != 64:
        return False
    try:
        R = _decode_point(sig[:32])
        A = _decode_point(pk)
    except ValueError:
        return False
    if _is_small_order(A) or _is_small_order(R):
        # Weak keys (identity / small-order public keys) and small-order
        # R values are rejected outright: signatures under them can be
        # forged without the secret (v0.3 hardening, H6).
        return False
    S = int.from_bytes(sig[32:], "little")
    if S >= _l:
        return False
    k = _hint(sig[:32] + pk + msg) % _l
    return _point_equal(_scalarmult(_B, S), _point_add(R, _scalarmult(A, k)))
