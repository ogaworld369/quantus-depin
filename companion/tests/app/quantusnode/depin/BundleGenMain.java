package app.quantusnode.depin;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Test-only CLI: build a current-format (v0.5) bundle from a seed and an observations
 * JSON file, exactly like the Python reference's build_bundle, so the
 * cross-check can compare outputs byte-for-byte (bundle_hash and
 * signature are deterministic).
 *
 * Usage: BundleGenMain <seedHex> <observationsJson> <iterations> <outFile>
 * Observations JSON: array of {timestamp_unix, best_block_number,
 * best_block_hash, observed_peers, finalized_block_number?,
 * witness_peer_hashes?} (witness values are 32-byte hashes, hex).
 * created_at_unix follows the reference default: the last
 * checkpoint's timestamp.
 */
public final class BundleGenMain {
    public static void main(String[] args) throws Exception {
        byte[] seed = Hex.decode(args[0]);
        String obsText = Files.readString(
                new File(args[1]).toPath(), StandardCharsets.UTF_8);
        int iterations = Integer.parseInt(args[2]);
        List<Object> raw = Json.asArray(Json.parse(obsText));
        List<DepinCore.Observation> obs = new ArrayList<>();
        for (Object o : raw) {
            Map<String, Object> m = Json.asObject(o);
            DepinCore.Observation ob = new DepinCore.Observation();
            ob.timestampUnix = Json.asLong(m.get("timestamp_unix"));
            ob.bestBlockNumber = Json.asLong(m.get("best_block_number"));
            ob.bestBlockHash = Hex.decode(Json.asString(m.get("best_block_hash")));
            ob.observedPeers = (int) Json.asLong(m.get("observed_peers"));
            Object fin = m.get("finalized_block_number");
            ob.finalizedBlockNumber = (fin == null) ? null : Json.asLong(fin);
            Object wit = m.get("witness_peer_hashes");
            if (wit != null) {
                ob.witnessPeerHashes = new ArrayList<>();
                for (Object w : Json.asArray(wit)) {
                    ob.witnessPeerHashes.add(Hex.decode(Json.asString(w)));
                }
            }
            obs.add(ob);
        }
        Map<String, Object> bundle = DepinCore.buildBundle(seed, obs, iterations, -1);
        Files.writeString(new File(args[3]).toPath(),
                Json.pretty(bundle), StandardCharsets.UTF_8);
        System.out.println("bundle_hash: " + bundle.get("bundle_hash"));
        System.out.println("signature:   " + bundle.get("signature"));
        System.out.println("device_id:   " + bundle.get("device_id"));
    }
}
