package app.quantusnode.depin;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Minimal JSON support, standard library only.
 *
 * Data model: Map&lt;String,Object&gt; / List&lt;Object&gt; / String /
 * Long (integral numbers) / Double (non-integral) / Boolean / null.
 *
 * Two writers:
 *  - canonical(): byte-compatible with the Python reference
 *    implementation's json.dumps(sort_keys=True,
 *    separators=(",",":"), ensure_ascii=False) for the value shapes
 *    the proof format uses (ASCII strings, integers, nested
 *    objects/arrays). This is what bundle_hash is computed over.
 *  - pretty(): 2-space indented export format (formatting only;
 *    verifiers parse JSON, so layout carries no meaning).
 *
 * The parser is a small recursive-descent reader used for RPC
 * responses, the checkpoint journal and bundle re-import in tests.
 *
 * v0.7 strictness (re-audit of v0.6):
 *  - M-03: the grammar is ASCII-only, matching the Python
 *    reference's verdicts on the same raw text. Number digits are
 *    ASCII 0-9 ONLY: the previous reader scanned with
 *    Character.isDigit (which accepts e.g. Arabic-Indic digits)
 *    and Long.parseLong then happily decoded them, so a bundle
 *    whose "seq" was written with U+0660 parsed here as 0 while
 *    the reference rejected it. Unicode escapes likewise: exactly
 *    four ASCII hex digits, decoded by hand — Integer.parseInt
 *    accepted a leading '+' ("\"+066" became 'f'), which the
 *    reference rejects. Unescaped control characters (< 0x20)
 *    inside strings are rejected, as the reference rejects them.
 *  - M-06: nesting is capped at MAX_DEPTH. The recursive parser
 *    previously had no depth bound, so a header line carrying a
 *    deeply nested array in an unknown field drove it into
 *    StackOverflowError — an Error, not a RuntimeException — which
 *    escaped the journal store's quarantine path entirely.
 */
final class Json {
    private Json() {}

    // ---------------- canonical writer ----------------

    static String canonical(Object value) {
        StringBuilder sb = new StringBuilder();
        writeCanonical(value, sb);
        return sb.toString();
    }

    static byte[] canonicalBytes(Object value) {
        return canonical(value).getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static void writeCanonical(Object v, StringBuilder sb) {
        if (v == null) {
            sb.append("null");
        } else if (v instanceof String) {
            writeString((String) v, sb);
        } else if (v instanceof Boolean) {
            sb.append(((Boolean) v) ? "true" : "false");
        } else if (v instanceof Long || v instanceof Integer) {
            sb.append(v.toString());
        } else if (v instanceof Double || v instanceof Float) {
            double d = ((Number) v).doubleValue();
            if (d == Math.rint(d) && Math.abs(d) < 9.0e15) {
                sb.append(Long.toString((long) d));
            } else {
                sb.append(v.toString());
            }
        } else if (v instanceof Map) {
            // Python sorts keys by code point; all keys in this
            // system are ASCII, so natural String order matches.
            TreeMap<String, Object> sorted = new TreeMap<>();
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                sorted.put((String) e.getKey(), e.getValue());
            }
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : sorted.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                writeString(e.getKey(), sb);
                sb.append(':');
                writeCanonical(e.getValue(), sb);
            }
            sb.append('}');
        } else if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object item : (List<?>) v) {
                if (!first) sb.append(',');
                first = false;
                writeCanonical(item, sb);
            }
            sb.append(']');
        } else {
            throw new IllegalArgumentException("not JSON-writable: " + v.getClass());
        }
    }

    private static void writeString(String s, StringBuilder sb) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }

    // ---------------- pretty writer ----------------

    static String pretty(Object value) {
        StringBuilder sb = new StringBuilder();
        writePretty(value, sb, 0);
        sb.append('\n');
        return sb.toString();
    }

    private static void writePretty(Object v, StringBuilder sb, int depth) {
        if (v instanceof Map) {
            Map<?, ?> m = (Map<?, ?>) v;
            if (m.isEmpty()) { sb.append("{}"); return; }
            sb.append("{\n");
            int i = 0;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                indent(sb, depth + 1);
                writeString((String) e.getKey(), sb);
                sb.append(": ");
                writePretty(e.getValue(), sb, depth + 1);
                if (++i < m.size()) sb.append(',');
                sb.append('\n');
            }
            indent(sb, depth);
            sb.append('}');
        } else if (v instanceof List) {
            List<?> list = (List<?>) v;
            if (list.isEmpty()) { sb.append("[]"); return; }
            sb.append("[\n");
            for (int i = 0; i < list.size(); i++) {
                indent(sb, depth + 1);
                writePretty(list.get(i), sb, depth + 1);
                if (i + 1 < list.size()) sb.append(',');
                sb.append('\n');
            }
            indent(sb, depth);
            sb.append(']');
        } else {
            writeCanonical(v, sb);
        }
    }

    private static void indent(StringBuilder sb, int depth) {
        for (int i = 0; i < depth; i++) sb.append("  ");
    }

    // ---------------- parser ----------------

    static Object parse(String text) {
        Parser p = new Parser(text);
        Object v = p.readValue();
        p.skipWs();
        if (!p.atEnd()) {
            throw new IllegalArgumentException("trailing characters in JSON");
        }
        return v;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> parseObject(String text) {
        Object v = parse(text);
        if (!(v instanceof Map)) {
            throw new IllegalArgumentException("expected a JSON object");
        }
        return (Map<String, Object>) v;
    }

    /** Maximum container nesting the parser accepts (M-06).
     *  Every structure this system reads — bundles, journal
     *  lines, RPC responses — nests at most a handful of levels;
     *  64 is generous headroom and keeps the recursive reader's
     *  stack use trivially bounded. */
    static final int MAX_DEPTH = 64;

    private static boolean isAsciiDigit(char c) {
        return c >= '0' && c <= '9';
    }

    private static int asciiHexValue(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    private static final class Parser {
        private final String s;
        private int pos;

        Parser(String s) { this.s = s; }

        boolean atEnd() { return pos >= s.length(); }

        void skipWs() {
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++;
                else break;
            }
        }

        private char peek() {
            if (atEnd()) throw new IllegalArgumentException("unexpected end of JSON");
            return s.charAt(pos);
        }

        Object readValue() {
            return readValue(0);
        }

        private Object readValue(int depth) {
            if (depth > MAX_DEPTH) {
                throw new IllegalArgumentException(
                        "JSON nesting deeper than " + MAX_DEPTH);
            }
            skipWs();
            char c = peek();
            switch (c) {
                case '{': return readObject(depth);
                case '[': return readArray(depth);
                case '"': return readString();
                case 't': expect("true"); return Boolean.TRUE;
                case 'f': expect("false"); return Boolean.FALSE;
                case 'n': expect("null"); return null;
                default: return readNumber();
            }
        }

        private void expect(String literal) {
            if (!s.startsWith(literal, pos)) {
                throw new IllegalArgumentException("bad literal at " + pos);
            }
            pos += literal.length();
        }

        private Map<String, Object> readObject(int depth) {
            Map<String, Object> map = new LinkedHashMap<>();
            pos++; // {
            skipWs();
            if (peek() == '}') { pos++; return map; }
            while (true) {
                skipWs();
                String key = readString();
                skipWs();
                if (peek() != ':') throw new IllegalArgumentException("expected ':'");
                pos++;
                // F-06 (v0.9): duplicate keys are a parse error,
                // matching the Python reference and SPEC section
                // 8. The previous last-wins put() silently read
                // {"seq": 99, "seq": 0} as seq 0 — the two
                // implementations disagreed on the same signed
                // bytes. Keys are compared AFTER string decoding,
                // so an escaped spelling of the same key is a
                // duplicate too. This system's own writers build
                // objects from maps and never emit duplicates.
                if (map.containsKey(key)) {
                    throw new IllegalArgumentException(
                            "duplicate key in object: " + key);
                }
                map.put(key, readValue(depth + 1));
                skipWs();
                char c = peek();
                if (c == ',') { pos++; continue; }
                if (c == '}') { pos++; return map; }
                throw new IllegalArgumentException("expected ',' or '}'");
            }
        }

        private List<Object> readArray(int depth) {
            List<Object> list = new ArrayList<>();
            pos++; // [
            skipWs();
            if (peek() == ']') { pos++; return list; }
            while (true) {
                list.add(readValue(depth + 1));
                skipWs();
                char c = peek();
                if (c == ',') { pos++; continue; }
                if (c == ']') { pos++; return list; }
                throw new IllegalArgumentException("expected ',' or ']'");
            }
        }

        private String readString() {
            if (peek() != '"') throw new IllegalArgumentException("expected string");
            pos++;
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (atEnd()) throw new IllegalArgumentException("unterminated string");
                char c = s.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    if (atEnd()) throw new IllegalArgumentException("bad escape");
                    char e = s.charAt(pos++);
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u': {
                            // M-03: exactly four ASCII hex digits,
                            // decoded by hand. Integer.parseInt
                            // accepted a leading '+' or '-' sign,
                            // so the escape "+066" silently became 'f'
                            // here while the reference rejected
                            // the text outright.
                            if (pos + 4 > s.length()) {
                                throw new IllegalArgumentException("bad \\u escape");
                            }
                            int v = 0;
                            for (int i = 0; i < 4; i++) {
                                int d = asciiHexValue(s.charAt(pos + i));
                                if (d < 0) {
                                    throw new IllegalArgumentException(
                                            "bad \\u escape");
                                }
                                v = v * 16 + d;
                            }
                            sb.append((char) v);
                            pos += 4;
                            break;
                        }
                        default:
                            throw new IllegalArgumentException("bad escape \\" + e);
                    }
                } else if (c < 0x20) {
                    // M-03: a raw control character inside a
                    // string is not JSON; the reference rejects
                    // it, so parity requires rejecting it here.
                    throw new IllegalArgumentException(
                            "unescaped control character in string");
                } else {
                    sb.append(c);
                }
            }
        }

        /**
         * Strict JSON number grammar (audit R-M01, parity round 2):
         *   number = [ '-' ] int [ frac ] [ exp ]
         *   int    = '0' | digit1-9 *digit     (no leading zeros)
         *   frac   = '.' 1*digit               ("1." is malformed)
         *   exp    = ('e'|'E') ['+'|'-'] 1*digit
         * The previous reader accepted "00", "01", "1." and "1e",
         * all of which the Python reference's parser rejects, so a
         * bundle the reference refuses could pass here. A leading
         * '+' or '.' never reaches this method as a number start
         * ('+' falls through readValue into here with no digits,
         * '.' likewise) and NaN / Infinity literals are not part of
         * the grammar at all — all are rejected below.
         *
         * Digits are ASCII 0-9 ONLY (M-03): Character.isDigit also
         * accepts Arabic-Indic and other Unicode decimal digits,
         * and Long.parseLong decodes those too, so the previous
         * reader turned a "seq" written with U+0660 into the
         * integer 0 — a verdict the Python reference never reaches
         * (it rejects the raw text). With ASCII-only scanning the
         * token simply fails to parse, exactly as there.
         */
        private Object readNumber() {
            int start = pos;
            if (!atEnd() && s.charAt(pos) == '-') pos++;
            // int part
            if (atEnd() || !isAsciiDigit(s.charAt(pos))) {
                throw new IllegalArgumentException("bad number at " + start);
            }
            if (s.charAt(pos) == '0') {
                pos++;
                if (!atEnd() && isAsciiDigit(s.charAt(pos))) {
                    throw new IllegalArgumentException(
                            "leading zero in number at " + start);
                }
            } else {
                while (!atEnd() && isAsciiDigit(s.charAt(pos))) pos++;
            }
            boolean fractional = false;
            if (!atEnd() && s.charAt(pos) == '.') {
                fractional = true;
                pos++;
                if (atEnd() || !isAsciiDigit(s.charAt(pos))) {
                    throw new IllegalArgumentException(
                            "fraction requires digits at " + start);
                }
                while (!atEnd() && isAsciiDigit(s.charAt(pos))) pos++;
            }
            if (!atEnd() && (s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) {
                fractional = true;
                pos++;
                if (!atEnd() && (s.charAt(pos) == '+' || s.charAt(pos) == '-')) pos++;
                if (atEnd() || !isAsciiDigit(s.charAt(pos))) {
                    throw new IllegalArgumentException(
                            "exponent requires digits at " + start);
                }
                while (!atEnd() && isAsciiDigit(s.charAt(pos))) pos++;
            }
            String text = s.substring(start, pos);
            if (!fractional) {
                try {
                    return Long.parseLong(text);
                } catch (NumberFormatException overflow) {
                    return Double.parseDouble(text);
                }
            }
            return Double.parseDouble(text);
        }
    }

    // ---------------- typed accessors ----------------

    @SuppressWarnings("unchecked")
    static Map<String, Object> asObject(Object v) {
        if (!(v instanceof Map)) {
            throw new IllegalArgumentException("expected object, got " + v);
        }
        return (Map<String, Object>) v;
    }

    @SuppressWarnings("unchecked")
    static List<Object> asArray(Object v) {
        if (!(v instanceof List)) {
            throw new IllegalArgumentException("expected array, got " + v);
        }
        return (List<Object>) v;
    }

    static long asLong(Object v) {
        if (v instanceof Number) return ((Number) v).longValue();
        throw new IllegalArgumentException("expected number, got " + v);
    }

    static String asString(Object v) {
        if (v instanceof String) return (String) v;
        throw new IllegalArgumentException("expected string, got " + v);
    }

    static boolean asBool(Object v) {
        if (v instanceof Boolean) return (Boolean) v;
        throw new IllegalArgumentException("expected boolean, got " + v);
    }
}
