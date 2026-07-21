package com.mario.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * Provably-fair primitive, shared by the enclave (which generates + commits) and the game
 * client (which re-derives to audit). Keep this the SINGLE source of truth so both sides
 * compute byte-identical outcomes — it takes only primitives (no proto types).
 *
 * <ul>
 *   <li>{@code commit(serverSeed)} = hex {@code SHA-256(serverSeed)} — published at round open,
 *       bound in the attestation doc, before any outcome is known.</li>
 *   <li>{@link Stream} = deterministic counter-mode HMAC-SHA256 DRBG keyed by {@code serverSeed}
 *       over {@code clientSeed || params}: {@code block_i = HMAC(serverSeed, context || i)}.
 *       Neither party alone controls the result (server picks serverSeed and commits it; client
 *       picks clientSeed). At settle the enclave reveals {@code serverSeed}; the client checks
 *       {@code SHA-256(serverSeed) == commit} and replays the same Stream to recompute the outcome.</li>
 * </ul>
 */
public final class Fairness {

    public static final int SEED_BYTES = 32;
    private static final HexFormat HEX = HexFormat.of();

    private Fairness() {
    }

    /** Hex SHA-256 of the server seed — the public commitment. */
    public static String commit(byte[] serverSeed) {
        return HEX.formatHex(sha256(serverSeed));
    }

    /** Constant-time-ish check that a revealed seed matches a prior commit. */
    public static boolean commitMatches(byte[] serverSeed, String commit) {
        return commit != null && commit.equalsIgnoreCase(commit(serverSeed));
    }

    /** A deterministic fairness stream for one round. */
    public static Stream stream(byte[] serverSeed, byte[] clientSeed, byte[] params) {
        return new Stream(serverSeed, concat(nz(clientSeed), nz(params)));
    }

    /** Counter-mode HMAC-SHA256 byte stream: block_i = HMAC(serverSeed, context || i_be64). */
    public static final class Stream {
        private final byte[] key;      // serverSeed
        private final byte[] context;  // clientSeed || params
        private long counter = 0;
        private byte[] buf = new byte[0];
        private int pos = 0;

        Stream(byte[] key, byte[] context) {
            this.key = key.clone();
            this.context = context;
        }

        private void refill() {
            buf = hmac(key, concat(context, longBytes(counter++)));
            pos = 0;
        }

        public int nextByte() {
            if (pos >= buf.length) {
                refill();
            }
            return buf[pos++] & 0xFF;
        }

        private long nextU32() {
            long v = 0;
            for (int i = 0; i < 4; i++) {
                v = (v << 8) | nextByte();
            }
            return v;
        }

        /** Uniform int in [0, bound) via rejection sampling (no modulo bias). */
        public int nextInt(int bound) {
            if (bound <= 0) {
                throw new IllegalArgumentException("bound must be > 0");
            }
            long span = 1L << 32;
            long limit = span - (span % bound); // largest multiple of bound <= 2^32
            long x;
            do {
                x = nextU32();
            } while (x >= limit);
            return (int) (x % bound);
        }
    }

    // ---- helpers ---------------------------------------------------------

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    static byte[] hmac(byte[] key, byte[] msg) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(msg);
        } catch (Exception e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    private static byte[] longBytes(long v) {
        byte[] b = new byte[8];
        for (int i = 7; i >= 0; i--) {
            b[i] = (byte) (v & 0xFF);
            v >>>= 8;
        }
        return b;
    }

    private static byte[] nz(byte[] a) {
        return a == null ? new byte[0] : a;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(a.length + b.length);
        out.writeBytes(a);
        out.writeBytes(b);
        return out.toByteArray();
    }
}
