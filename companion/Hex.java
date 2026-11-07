package app.quantusnode.depin;

/** Lowercase hex codec. Encoding always produces the canonical form
 *  the SPEC requires (lowercase, no whitespace, fixed length). */
final class Hex {
    private static final char[] DIGITS = "0123456789abcdef".toCharArray();

    private Hex() {}

    static String encode(byte[] data) {
        char[] out = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            int v = data[i] & 0xff;
            out[2 * i] = DIGITS[v >>> 4];
            out[2 * i + 1] = DIGITS[v & 0x0f];
        }
        return new String(out);
    }

    static byte[] decode(String s) {
        if (s == null || (s.length() & 1) != 0) {
            throw new IllegalArgumentException("bad hex string");
        }
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(s.charAt(2 * i), 16);
            int lo = Character.digit(s.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("bad hex string");
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    /**
     * Canonical-form decode: ONLY lowercase [0-9a-f] is accepted.
     * The lenient decode() above accepts uppercase (Character.digit
     * is case-insensitive), which made this implementation accept
     * bundles the Python reference rejects (audit M-01: canonical
     * hex is part of the format). All bundle / journal verification
     * paths must use this decoder.
     */
    static byte[] decodeCanonical(String s) {
        if (s == null || (s.length() & 1) != 0) {
            throw new IllegalArgumentException("bad hex string");
        }
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = lowerDigit(s.charAt(2 * i));
            int lo = lowerDigit(s.charAt(2 * i + 1));
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("non-canonical hex string");
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static int lowerDigit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    }

    /** True when s is canonical lowercase hex of exactly n bytes. */
    static boolean isCanonicalHex(String s, int bytes) {
        if (s == null || s.length() != bytes * 2) return false;
        for (int i = 0; i < s.length(); i++) {
            if (lowerDigit(s.charAt(i)) < 0) return false;
        }
        return true;
    }

    /** Strip an optional 0x prefix (RPC responses carry one). */
    static String strip0x(String s) {
        if (s != null && (s.startsWith("0x") || s.startsWith("0X"))) {
            return s.substring(2);
        }
        return s;
    }

    static byte[] decodePrefixed(String s) {
        return decode(strip0x(s));
    }
}
