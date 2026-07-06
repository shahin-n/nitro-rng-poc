package com.mario.random.internal.strategies;

import com.mario.random.internal.EntropySource;
import com.mario.random.internal.InternalRandomStrategy;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

public final class Sha256CounterRandomStrategy implements InternalRandomStrategy {

    private final byte[] seed = new byte[32];
    private long counter = 0L;

    private final byte[] buffer = new byte[32]; // SHA-256 output
    private int bufferPos = buffer.length;

    private final MessageDigest md;
    private boolean initialized = false;

    public Sha256CounterRandomStrategy() {
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    @Override
    public synchronized int nextInt(int bound, EntropySource entropy) {
        Objects.requireNonNull(entropy, "entropy");
        if (bound <= 0) {
            throw new IllegalArgumentException("bound must be > 0");
        }
        ensureSeeded(entropy);

        int r;
        int m = bound - 1;
        if ((bound & m) == 0) {
            r = (int) (nextInt32() & m);
            return r;
        }
        int u;
        do {
            u = nextInt32() >>> 1;
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

        long s1 = entropy.getCompositeSeed();
        long s2 = entropy.getSeed();
        long s3 = entropy.getNanoTime();
        long s4 = entropy.getSeed()
                ^ (((long) entropy.getThreadCount()) << 32)
                ^ entropy.getCpuCores();

        longToBytesLE(s1, seed, 0);
        longToBytesLE(s2, seed, 8);
        longToBytesLE(s3, seed, 16);
        longToBytesLE(s4, seed, 24);

        counter = 0L;
        bufferPos = buffer.length;
        initialized = true;
    }

    // --------------- internal helpers ---------------

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
        // input = seed (32 bytes) || counter (8 bytes, big-endian)
        byte[] input = new byte[40];
        System.arraycopy(seed, 0, input, 0, 32);
        putLongBE(counter++, input, 32);

        md.reset();
        md.update(input);
        byte[] hash = md.digest();
        System.arraycopy(hash, 0, buffer, 0, 32);
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

    private static void putLongBE(long v, byte[] out, int offset) {
        out[offset]     = (byte) (v >>> 56);
        out[offset + 1] = (byte) (v >>> 48);
        out[offset + 2] = (byte) (v >>> 40);
        out[offset + 3] = (byte) (v >>> 32);
        out[offset + 4] = (byte) (v >>> 24);
        out[offset + 5] = (byte) (v >>> 16);
        out[offset + 6] = (byte) (v >>> 8);
        out[offset + 7] = (byte) (v);
    }
}
