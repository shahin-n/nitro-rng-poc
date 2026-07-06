package com.mario.random.internal.strategies;

import com.mario.random.internal.EntropySource;
import com.mario.random.internal.InternalRandomStrategy;

import java.util.Objects;

public final class ChaCha20RandomStrategy implements InternalRandomStrategy {

    // 32-byte key, 12-byte nonce
    private final byte[] key = new byte[32];
    private final byte[] nonce = new byte[12];

    // ChaCha20 state
    private final int[] engineState = new int[16];
    private final int[] workingState = new int[16];

    // Output buffer
    private final byte[] buffer = new byte[64];
    private int bufferPos = buffer.length;

    private int blockCounter = 0;
    private boolean initialized = false;

    @Override
    public synchronized int nextInt(int bound, EntropySource entropy) {
        Objects.requireNonNull(entropy, "entropy");
        if (bound <= 0) {
            throw new IllegalArgumentException("bound must be > 0");
        }
        ensureSeeded(entropy);

        // Rejection sampling to avoid modulo bias
        int r;
        int m = bound - 1;
        if ((bound & m) == 0) {
            // power of two
            return (nextInt32() & m);
        }
        int u;
        do {
            u = nextInt32() >>> 1; // make it non-negative
            r = u % bound;
        } while (u - r + m < 0);
        return r;
    }

    @Override
    public synchronized boolean nextBoolean(EntropySource entropy) {
        Objects.requireNonNull(entropy, "entropy");
        ensureSeeded(entropy);
        return (nextByte() & 0x01) != 0;
    }

    @Override
    public synchronized double nextDouble(EntropySource entropy) {
        Objects.requireNonNull(entropy, "entropy");
        ensureSeeded(entropy);
        // 53 random bits -> [0,1)
        long l = nextLongInternal() >>> 11;
        return l * 0x1.0p-53;
    }

    @Override
    public synchronized long nextLong(EntropySource entropy) {
        Objects.requireNonNull(entropy, "entropy");
        ensureSeeded(entropy);
        return nextLongInternal();
    }

    @Override
    public synchronized void reseed(EntropySource entropy) {
        Objects.requireNonNull(entropy, "entropy");

        // Build 32-byte key from four longs
        long s1 = entropy.getCompositeSeed();
        long s2 = entropy.getSeed();
        long s3 = entropy.getCompositeSeed() ^ entropy.getNanoTime();
        long s4 = entropy.getSeed()
                ^ (((long) entropy.getThreadCount()) << 32)
                ^ entropy.getCpuCores();

        longToBytesLE(s1, key, 0);
        longToBytesLE(s2, key, 8);
        longToBytesLE(s3, key, 16);
        longToBytesLE(s4, key, 24);

        // 12-byte nonce from time + seed mix
        long n1 = entropy.getNanoTime();
        long n2 = entropy.getSeed();

        longToBytesLE(n1, nonce, 0); // first 8 bytes
        // last 4 bytes from n2 (low 32 bits)
        int v = (int) n2;
        nonce[8]  = (byte) (v);
        nonce[9]  = (byte) (v >>> 8);
        nonce[10] = (byte) (v >>> 16);
        nonce[11] = (byte) (v >>> 24);

        blockCounter = 0;
        bufferPos = buffer.length;
        initialized = true;
    }

    // ---------------- internal helpers ----------------

    private void ensureSeeded(EntropySource entropy) {
        if (!initialized) {
            reseed(entropy);
        }
    }

    private int nextInt32() {
        int b0 = nextByte() & 0xFF;
        int b1 = nextByte() & 0xFF;
        int b2 = nextByte() & 0xFF;
        int b3 = nextByte() & 0xFF;
        return (b0) | (b1 << 8) | (b2 << 16) | (b3 << 24);
    }

    private long nextLongInternal() {
        long b0 = nextByte() & 0xFFL;
        long b1 = nextByte() & 0xFFL;
        long b2 = nextByte() & 0xFFL;
        long b3 = nextByte() & 0xFFL;
        long b4 = nextByte() & 0xFFL;
        long b5 = nextByte() & 0xFFL;
        long b6 = nextByte() & 0xFFL;
        long b7 = nextByte() & 0xFFL;
        return (b0) |
                (b1 << 8) |
                (b2 << 16) |
                (b3 << 24) |
                (b4 << 32) |
                (b5 << 40) |
                (b6 << 48) |
                (b7 << 56);
    }

    private byte nextByte() {
        if (bufferPos >= buffer.length) {
            generateBlock();
            bufferPos = 0;
        }
        return buffer[bufferPos++];
    }

    private void generateBlock() {
        // Initialize engine state:
        // constants
        engineState[0] = 0x61707865; // "expa"
        engineState[1] = 0x3320646e; // "nd 3"
        engineState[2] = 0x79622d32; // "2-by"
        engineState[3] = 0x6b206574; // "te k"

        // key (8 * 4 bytes) little-endian
        for (int i = 0; i < 8; i++) {
            engineState[4 + i] = toIntLittleEndian(key, i * 4);
        }

        // block counter
        engineState[12] = blockCounter++;

        // nonce (3 * 4 bytes)
        engineState[13] = toIntLittleEndian(nonce, 0);
        engineState[14] = toIntLittleEndian(nonce, 4);
        engineState[15] = toIntLittleEndian(nonce, 8);

        // working state
        System.arraycopy(engineState, 0, workingState, 0, 16);

        // 20 rounds (10 double rounds)
        for (int i = 0; i < 10; i++) {
            // column rounds
            quarterRound(0, 4, 8, 12);
            quarterRound(1, 5, 9, 13);
            quarterRound(2, 6, 10, 14);
            quarterRound(3, 7, 11, 15);
            // diagonal rounds
            quarterRound(0, 5, 10, 15);
            quarterRound(1, 6, 11, 12);
            quarterRound(2, 7, 8, 13);
            quarterRound(3, 4, 9, 14);
        }

        // add original state
        for (int i = 0; i < 16; i++) {
            workingState[i] += engineState[i];
        }

        // serialize into buffer (little endian)
        int offset = 0;
        for (int i = 0; i < 16; i++) {
            int x = workingState[i];
            buffer[offset++] = (byte) (x);
            buffer[offset++] = (byte) (x >>> 8);
            buffer[offset++] = (byte) (x >>> 16);
            buffer[offset++] = (byte) (x >>> 24);
        }
    }

    private void quarterRound(int a, int b, int c, int d) {
        int[] s = workingState;

        s[a] += s[b]; s[d] ^= s[a]; s[d] = Integer.rotateLeft(s[d], 16);
        s[c] += s[d]; s[b] ^= s[c]; s[b] = Integer.rotateLeft(s[b], 12);
        s[a] += s[b]; s[d] ^= s[a]; s[d] = Integer.rotateLeft(s[d], 8);
        s[c] += s[d]; s[b] ^= s[c]; s[b] = Integer.rotateLeft(s[b], 7);
    }

    private static int toIntLittleEndian(byte[] bs, int off) {
        return (bs[off] & 0xFF) |
                ((bs[off + 1] & 0xFF) << 8) |
                ((bs[off + 2] & 0xFF) << 16) |
                ((bs[off + 3] & 0xFF) << 24);
    }

    private static void longToBytesLE(long v, byte[] out, int offset) {
        out[offset]     = (byte) (v);
        out[offset + 1] = (byte) (v >>> 8);
        out[offset + 2] = (byte) (v >>> 16);
        out[offset + 3] = (byte) (v >>> 24);
        out[offset + 4] = (byte) (v >>> 32);
        out[offset + 5] = (byte) (v >>> 40);
        out[offset + 6] = (byte) (v >>> 48);
        out[offset + 7] = (byte) (v >>> 56);
    }
}