package com.mario.rng;

import com.google.protobuf.ByteString;
import com.mario.rng.app.CommitReveal;
import com.mario.rng.app.CommitRevealResult;
import com.mario.rng.app.BytesResult;
import com.mario.rng.app.IntResult;
import com.mario.rng.app.NextBytes;
import com.mario.rng.app.NextInt;
import com.mario.rng.app.RngOp;
import com.mario.rng.app.RngResult;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * The confidential RNG application — executed only after HPKE decryption inside
 * the enclave. Entropy is {@link SecureRandom} (the enclave seeds from NSM-backed
 * hardware entropy in production).
 */
final class RngEngine {

    private static final int SEED_BYTES = 32;

    private final SecureRandom random = new SecureRandom();

    RngResult execute(RngOp op) {
        return switch (op.getOpCase()) {
            case NEXT_INT -> RngResult.newBuilder().setIntResult(nextInt(op.getNextInt())).build();
            case NEXT_BYTES -> RngResult.newBuilder().setBytesResult(nextBytes(op.getNextBytes())).build();
            case COMMIT_REVEAL -> RngResult.newBuilder().setCommitReveal(commitReveal(op.getCommitReveal())).build();
            case OP_NOT_SET -> throw new IllegalArgumentException("empty RngOp");
        };
    }

    private IntResult nextInt(NextInt op) {
        return IntResult.newBuilder().setValue(uniform(op.getMin(), op.getMax())).build();
    }

    private BytesResult nextBytes(NextBytes op) {
        byte[] buf = new byte[op.getCount()];
        random.nextBytes(buf);
        return BytesResult.newBuilder().setData(ByteString.copyFrom(buf)).build();
    }

    private CommitRevealResult commitReveal(CommitReveal op) {
        byte[] seed = new byte[SEED_BYTES];
        random.nextBytes(seed);
        byte[] hash = sha256(seed);
        long value = deriveValue(hash, op.getMin(), op.getMax());
        sleep(op.getDelaySeconds());
        return CommitRevealResult.newBuilder()
                .setCommitHash(ByteString.copyFrom(hash))
                .setSeed(ByteString.copyFrom(seed))
                .setValue(value)
                .build();
    }

    private long uniform(long min, long max) {
        if (max < min) {
            long t = min;
            min = max;
            max = t;
        }
        long span = max - min + 1;
        long bits = random.nextLong();
        return span <= 0 ? bits : min + Math.floorMod(bits, span);
    }

    static long deriveValue(byte[] hash, long min, long max) {
        if (max < min) {
            long t = min;
            min = max;
            max = t;
        }
        long span = max - min + 1;
        long bits = 0;
        for (int i = 0; i < 8; i++) {
            bits = (bits << 8) | (hash[i] & 0xFFL);
        }
        return span <= 0 ? bits : min + Long.remainderUnsigned(bits, span);
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static void sleep(int seconds) {
        try {
            Thread.sleep(seconds * 1000L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
