package app.quantusnode.depin;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Ed25519 (RFC 8032) in pure Java, standard library only.
 *
 * This is a straight port of the Python reference implementation
 * (ed25519_rfc8032.py): extended twisted-Edwards coordinates
 * (add-2008-hwcd / dbl-2008-hwcd), the same seed expansion, the same
 * deterministic nonce derivation, and the same verification rules —
 * including the v0.3 hardening (small-order public keys and R values
 * are rejected, and the non-canonical x=0 sign-bit encoding is
 * refused at decode time). Correctness is pinned by the RFC 8032
 * test vectors and by byte-equality with the Python implementation
 * in the JVM harness (tests/).
 *
 * Not constant-time; like the reference, this is prototype code.
 * On Android the seed never leaves the app's encrypted storage and
 * signing happens once per bundle export and key setup.
 */
final class Ed25519 {
    private Ed25519() {}

    private static final BigInteger Q =
            BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger L =
            BigInteger.ONE.shiftLeft(252).add(
                    new BigInteger("27742317777372353535851937790883648493"));
    private static final BigInteger D;
    private static final BigInteger I;
    private static final BigInteger[] B;
    private static final BigInteger[] IDENTITY = {
            BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO};

    static {
        BigInteger inv121666 = BigInteger.valueOf(121666).modInverse(Q);
        D = BigInteger.valueOf(-121665).multiply(inv121666).mod(Q);
        I = BigInteger.TWO.modPow(Q.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), Q);
        BigInteger by = BigInteger.valueOf(4)
                .multiply(BigInteger.valueOf(5).modInverse(Q)).mod(Q);
        BigInteger bx = xRecover(by);
        B = new BigInteger[]{bx, by, BigInteger.ONE, bx.multiply(by).mod(Q)};
    }

    private static BigInteger xRecover(BigInteger y) {
        BigInteger y2 = y.multiply(y).mod(Q);
        BigInteger xx = y2.subtract(BigInteger.ONE)
                .multiply(D.multiply(y2).add(BigInteger.ONE).modInverse(Q)).mod(Q);
        BigInteger x = xx.modPow(Q.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), Q);
        if (!x.multiply(x).subtract(xx).mod(Q).equals(BigInteger.ZERO)) {
            x = x.multiply(I).mod(Q);
        }
        if (x.testBit(0)) {
            x = Q.subtract(x);
        }
        return x;
    }

    private static BigInteger[] pointAdd(BigInteger[] p, BigInteger[] q) {
        BigInteger x1 = p[0], y1 = p[1], z1 = p[2], t1 = p[3];
        BigInteger x2 = q[0], y2 = q[1], z2 = q[2], t2 = q[3];
        BigInteger a = y1.subtract(x1).multiply(y2.subtract(x2)).mod(Q);
        BigInteger b = y1.add(x1).multiply(y2.add(x2)).mod(Q);
        BigInteger c = BigInteger.TWO.multiply(D).multiply(t1).multiply(t2).mod(Q);
        BigInteger d = BigInteger.TWO.multiply(z1).multiply(z2).mod(Q);
        BigInteger e = b.subtract(a).mod(Q);
        BigInteger f = d.subtract(c).mod(Q);
        BigInteger g = d.add(c).mod(Q);
        BigInteger h = b.add(a).mod(Q);
        return new BigInteger[]{
                e.multiply(f).mod(Q), g.multiply(h).mod(Q),
                f.multiply(g).mod(Q), e.multiply(h).mod(Q)};
    }

    private static BigInteger[] pointDouble(BigInteger[] p) {
        BigInteger x1 = p[0], y1 = p[1], z1 = p[2];
        BigInteger a = x1.multiply(x1).mod(Q);
        BigInteger b = y1.multiply(y1).mod(Q);
        BigInteger c = BigInteger.TWO.multiply(z1).multiply(z1).mod(Q);
        BigInteger d = a.negate().mod(Q);
        BigInteger e = x1.add(y1).multiply(x1.add(y1)).subtract(a).subtract(b).mod(Q);
        BigInteger g = d.add(b).mod(Q);
        BigInteger f = g.subtract(c).mod(Q);
        BigInteger h = d.subtract(b).mod(Q);
        return new BigInteger[]{
                e.multiply(f).mod(Q), g.multiply(h).mod(Q),
                f.multiply(g).mod(Q), e.multiply(h).mod(Q)};
    }

    private static BigInteger[] scalarMult(BigInteger[] p, BigInteger e) {
        BigInteger[] q = IDENTITY.clone();
        int bits = e.bitLength();
        for (int i = bits - 1; i >= 0; i--) {
            q = pointDouble(q);
            if (e.testBit(i)) {
                q = pointAdd(q, p);
            }
        }
        return q;
    }

    private static boolean pointEqual(BigInteger[] p, BigInteger[] q) {
        BigInteger left1 = p[0].multiply(q[2]).subtract(q[0].multiply(p[2])).mod(Q);
        BigInteger left2 = p[1].multiply(q[2]).subtract(q[1].multiply(p[2])).mod(Q);
        return left1.equals(BigInteger.ZERO) && left2.equals(BigInteger.ZERO);
    }

    private static byte[] encodePoint(BigInteger[] p) {
        BigInteger zInv = p[2].modInverse(Q);
        BigInteger x = p[0].multiply(zInv).mod(Q);
        BigInteger y = p[1].multiply(zInv).mod(Q);
        byte[] b = toLittleEndian32(y);
        if (x.testBit(0)) {
            b[31] |= (byte) 0x80;
        }
        return b;
    }

    private static BigInteger[] decodePoint(byte[] s) {
        if (s.length != 32) {
            throw new IllegalArgumentException("encoded point must be 32 bytes");
        }
        BigInteger y = fromLittleEndian(s).and(
                BigInteger.ONE.shiftLeft(255).subtract(BigInteger.ONE));
        int sign = (s[31] >> 7) & 1;
        if (y.compareTo(Q) >= 0) {
            throw new IllegalArgumentException("y out of range");
        }
        BigInteger x = xRecover(y);
        // RFC 8032: when x == 0 the sign bit must be 0; check before
        // the parity flip (mirrors the reference, H6).
        if (x.equals(BigInteger.ZERO) && sign == 1) {
            throw new IllegalArgumentException("invalid sign bit for x=0");
        }
        if ((x.testBit(0) ? 1 : 0) != sign) {
            x = Q.subtract(x);
        }
        BigInteger x2 = x.multiply(x).mod(Q);
        BigInteger y2 = y.multiply(y).mod(Q);
        BigInteger check = x2.negate().add(y2).subtract(BigInteger.ONE)
                .subtract(D.multiply(x2).multiply(y2)).mod(Q);
        if (!check.equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("point not on curve");
        }
        return new BigInteger[]{x, y, BigInteger.ONE, x.multiply(y).mod(Q)};
    }

    private static boolean isSmallOrder(BigInteger[] p) {
        return pointEqual(scalarMult(p, BigInteger.valueOf(8)), IDENTITY);
    }

    // ---------------- key expansion ----------------

    private static final class Expanded {
        BigInteger a;
        byte[] prefix;
        byte[] pubkey;
    }

    private static Expanded expandSeed(byte[] seed) {
        if (seed.length != 32) {
            throw new IllegalArgumentException("seed must be 32 bytes");
        }
        byte[] h = sha512(seed);
        byte[] aBytes = new byte[32];
        System.arraycopy(h, 0, aBytes, 0, 32);
        aBytes[0] &= (byte) 248;
        aBytes[31] &= (byte) 63;
        aBytes[31] |= (byte) 64;
        Expanded out = new Expanded();
        out.a = fromLittleEndian(aBytes);
        out.prefix = new byte[32];
        System.arraycopy(h, 32, out.prefix, 0, 32);
        return out;
    }

    static byte[] publickeyFromSeed(byte[] seed) {
        Expanded ex = expandSeed(seed);
        return encodePoint(scalarMult(B, ex.a));
    }

    static byte[] sign(byte[] seed, byte[] msg) {
        Expanded ex = expandSeed(seed);
        byte[] pk = encodePoint(scalarMult(B, ex.a));
        BigInteger r = hint(concat(ex.prefix, msg)).mod(L);
        byte[] rEnc = encodePoint(scalarMult(B, r));
        BigInteger k = hint(concat(rEnc, pk, msg)).mod(L);
        BigInteger s = r.add(k.multiply(ex.a)).mod(L);
        byte[] out = new byte[64];
        System.arraycopy(rEnc, 0, out, 0, 32);
        System.arraycopy(toLittleEndian32(s), 0, out, 32, 32);
        return out;
    }

    static boolean verify(byte[] pk, byte[] msg, byte[] sig) {
        if (pk.length != 32 || sig.length != 64) {
            return false;
        }
        BigInteger[] rPoint;
        BigInteger[] aPoint;
        try {
            byte[] rEnc = new byte[32];
            System.arraycopy(sig, 0, rEnc, 0, 32);
            rPoint = decodePoint(rEnc);
            aPoint = decodePoint(pk);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (isSmallOrder(aPoint) || isSmallOrder(rPoint)) {
            return false;
        }
        byte[] sBytes = new byte[32];
        System.arraycopy(sig, 32, sBytes, 0, 32);
        BigInteger s = fromLittleEndian(sBytes);
        if (s.compareTo(L) >= 0) {
            return false;
        }
        byte[] rEnc = new byte[32];
        System.arraycopy(sig, 0, rEnc, 0, 32);
        BigInteger k = hint(concat(rEnc, pk, msg)).mod(L);
        return pointEqual(scalarMult(B, s),
                pointAdd(rPoint, scalarMult(aPoint, k)));
    }

    // ---------------- helpers ----------------

    private static BigInteger hint(byte[] data) {
        return fromLittleEndian(sha512(data));
    }

    private static byte[] sha512(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] out = new byte[total];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }

    private static BigInteger fromLittleEndian(byte[] b) {
        byte[] be = new byte[b.length];
        for (int i = 0; i < b.length; i++) {
            be[i] = b[b.length - 1 - i];
        }
        return new BigInteger(1, be);
    }

    private static byte[] toLittleEndian32(BigInteger v) {
        byte[] be = v.toByteArray();
        byte[] out = new byte[32];
        for (int i = 0; i < 32; i++) {
            int src = be.length - 1 - i;
            out[i] = (src >= 0) ? be[src] : 0;
        }
        return out;
    }

    static String selfDescription() {
        return "Ed25519/RFC8032 pure-Java " + StandardCharsets.UTF_8.name();
    }
}
