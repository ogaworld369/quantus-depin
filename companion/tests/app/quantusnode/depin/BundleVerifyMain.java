package app.quantusnode.depin;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;

/**
 * Test-only CLI: verify a bundle file with this Java
 * implementation. Usage: BundleVerifyMain <bundleJson> <iterations>
 * [formatVersion]
 * The optional format version ("0.5" default; "0.4" / "0.3" select
 * the legacy profiles) lets the cross-check exercise the
 * parameterized verifier against reference-built legacy bundles.
 * Exit 0 = valid, 1 = invalid (a bundle that cannot even be parsed
 * is invalid, matching the reference CLI's behaviour).
 */
public final class BundleVerifyMain {
    public static void main(String[] args) throws Exception {
        String text = Files.readString(
                new File(args[0]).toPath(), StandardCharsets.UTF_8);
        int iterations = Integer.parseInt(args[1]);
        DepinCore.FormatProfile fmt = DepinCore.CURRENT;
        if (args.length > 2) {
            switch (args[2]) {
                case "0.5": fmt = DepinCore.FMT_V05; break;
                case "0.4": fmt = DepinCore.FMT_V04; break;
                case "0.3": fmt = DepinCore.FMT_V03; break;
                default:
                    System.out.println("INVALID: unknown format version " + args[2]);
                    System.exit(1);
            }
        }
        final Map<String, Object> bundle;
        try {
            bundle = Json.parseObject(text);
        } catch (RuntimeException e) {
            System.out.println("INVALID: unparseable: " + e.getMessage());
            System.exit(1);
            return;
        }
        List<String> errors = DepinCore.verifyBundle(fmt, bundle, iterations, true);
        if (errors.isEmpty()) {
            System.out.println("VALID");
            return;
        }
        System.out.println("INVALID:");
        for (String e : errors) {
            System.out.println("  - " + e);
        }
        System.exit(1);
    }
}
