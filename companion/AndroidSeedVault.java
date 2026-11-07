package app.quantusnode.depin;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Android implementation of SeedVault: an Android-Keystore AES-256
 * key (generated in the Keystore, non-exportable) wraps the Ed25519
 * seed; the wrapped form is a small JSON file in app-private
 * storage. Backup and device transfer are disabled in the manifest
 * and data-extraction rules, so this file never leaves the device
 * through platform backup channels.
 *
 * Seed lifetime (L-01, completed by re-audit R-L01): this class
 * keeps NO plaintext seed cache — there is deliberately no seed
 * field at all. Every loadOrCreateSeed() call unwraps the seed
 * fresh from the Keystore-wrapped file and hands the caller the
 * only copy, which the caller zeroes immediately after use.
 * Checkpoints are 600 s apart, so the unwrap cost is irrelevant;
 * the v0.4 design cached the seed for the process lifetime (the
 * audit's L-01 was only partially fixed by zeroing call sites —
 * the vault's own copy survived until lock()), and the re-audit
 * flagged exactly that remainder.
 */
final class AndroidSeedVault implements SeedVault {
    // v2 alias: v0.1.0 generated the v1 key with
    // setRandomizedEncryptionRequired(true), which KeyMint pairs
    // with a ban on caller-supplied IVs — and AesGcmSeedBox always
    // supplies its own IV, so every v1 wrap was rejected
    // (CALLER_NONCE_PROHIBITED) and no identity.enc could ever have
    // been produced under v1. KeyGenParameterSpec is immutable once
    // a key exists, so fixing the flag in code alone would NOT heal
    // a device that already created the v1 key; the key must be
    // regenerated under a new alias (see keystoreKey()).
    private static final String KEY_ALIAS = "depin_companion_seed_wrap_v2";
    private static final String LEGACY_KEY_ALIAS_V1 = "depin_companion_seed_wrap_v1";
    private static final String FILE_NAME = "identity.enc";

    private final File file;

    AndroidSeedVault(Context context) {
        this.file = new File(context.getFilesDir(), FILE_NAME);
    }

    private SecretKey keystoreKey() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        // Best-effort removal of the unusable v1 key. It is only
        // deleted while no identity.enc exists: in that state the
        // v1 key provably never wrapped a seed (all its wraps were
        // rejected), so nothing can depend on it. If a wrapped file
        // somehow exists, the legacy key is left untouched.
        try {
            if (!file.exists() && ks.containsAlias(LEGACY_KEY_ALIAS_V1)) {
                ks.deleteEntry(LEGACY_KEY_ALIAS_V1);
            }
        } catch (Exception ignored) {
            // Cleanup must never block key loading.
        }
        KeyStore.Entry entry = ks.getEntry(KEY_ALIAS, null);
        if (entry instanceof KeyStore.SecretKeyEntry) {
            return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        }
        KeyGenerator gen = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        gen.init(new KeyGenParameterSpec.Builder(
                        KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                // Must stay paired with the caller-IV design of
                // AesGcmSeedBox; see SeedVault's pinned constant.
                .setRandomizedEncryptionRequired(
                        SeedVault.KEYSTORE_RANDOMIZED_ENCRYPTION_REQUIRED)
                .build());
        return gen.generateKey();
    }

    /**
     * Unwrap and return the stored seed, or generate, wrap and
     * store a new one. EVERY call decrypts on demand (R-L01):
     * nothing is cached in this class, and the returned array is
     * the caller's only copy — callers zero it in a finally block
     * immediately after use. Synchronized so two concurrent
     * first-run callers cannot race the create-and-store path.
     */
    @Override
    public synchronized byte[] loadOrCreateSeed() throws Exception {
        SecretKey key = keystoreKey();
        if (file.exists()) {
            String text;
            try (FileInputStream in = new FileInputStream(file)) {
                byte[] buf = new byte[(int) file.length()];
                int off = 0;
                int n;
                while ((n = in.read(buf, off, buf.length - off)) > 0) {
                    off += n;
                }
                text = new String(buf, 0, off, StandardCharsets.UTF_8);
            }
            Map<String, Object> stored = Json.parseObject(text);
            AesGcmSeedBox.Wrapped wrapped = new AesGcmSeedBox.Wrapped(
                    Base64.decode(Json.asString(stored.get("iv")), Base64.NO_WRAP),
                    Base64.decode(Json.asString(stored.get("ct")), Base64.NO_WRAP));
            byte[] seed = AesGcmSeedBox.unwrap(key, wrapped);
            if (seed.length != 32) {
                java.util.Arrays.fill(seed, (byte) 0);
                throw new IllegalStateException("stored seed has wrong length");
            }
            return seed;
        }
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        AesGcmSeedBox.Wrapped wrapped = AesGcmSeedBox.wrap(key, seed);
        Map<String, Object> stored = new LinkedHashMap<>();
        stored.put("format", "quantus-depin-identity-enc");
        stored.put("version", 1L);
        stored.put("iv", Base64.encodeToString(wrapped.iv, Base64.NO_WRAP));
        stored.put("ct", Base64.encodeToString(wrapped.ciphertext, Base64.NO_WRAP));
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(Json.pretty(stored).getBytes(StandardCharsets.UTF_8));
        }
        return seed;
    }

    @Override
    public byte[] publicKey() throws Exception {
        byte[] seed = loadOrCreateSeed();
        try {
            return Ed25519.publickeyFromSeed(seed);
        } finally {
            // R-L01: the seed copy obtained just to derive the
            // public key is zeroed here, not left to the caller.
            java.util.Arrays.fill(seed, (byte) 0);
        }
    }

    /**
     * Emergency wipe hook, kept for the existing call sites
     * (service destroy, post-signing cleanup). Since R-L01 there
     * is no plaintext cache or wrapped-material reference held by
     * this class, so there is nothing left to destroy; the wrapped
     * file and the Keystore key are the identity itself and are
     * never deleted here.
     */
    synchronized void lock() {
        // No state to wipe — see the class doc.
    }
}
