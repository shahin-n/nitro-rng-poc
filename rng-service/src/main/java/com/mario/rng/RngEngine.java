package com.mario.rng;

import com.google.protobuf.ByteString;
import com.mario.random.internal.RandomManager;
import com.mario.rng.app.CommitReveal;
import com.mario.rng.app.CommitResult;
import com.mario.rng.app.RevealResult;
import com.mario.rng.app.BytesResult;
import com.mario.rng.app.IntResult;
import com.mario.rng.app.NextBytes;
import com.mario.rng.app.NextInt;
import com.mario.rng.app.RngOp;
import com.mario.rng.app.RngResult;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * The confidential RNG application — executed only after HPKE decryption inside
 * the enclave. Entropy comes from {@link RandomManager} (common-random), which rotates
 * between crypto strategies (SecureRandom, HMAC-DRBG, SHA-256 counter, ChaCha20).
 *
 * <p>{@code RandomManager} is thread-confined, but this engine is shared across the
 * server's worker threads, so each thread gets its own instance via a {@link ThreadLocal}.
 *
 * <p>Commit/reveal is stateless here: {@link #commitReveal} mints a seed and returns
 * BOTH frames (the hash-only commit and the seed+value reveal). {@code RngServer}
 * pushes them over a held stream — commit first, then the reveal after the delay —
 * so the enclave is bound to the hash before the seed reaches the wire. No map, no
 * second call: the seed only ever lives in the streaming handler's stack.
 */
final class RngEngine {

    private static final int SEED_BYTES = 32;

    private final ThreadLocal<RandomManager> random = ThreadLocal.withInitial(RandomManager::new);

    /** The two frames of one commit-reveal; {@code RngServer} pushes commit, waits, pushes reveal. */
    record CommitRevealFrames(CommitResult commit, RevealResult reveal) {
    }

    RngResult execute(RngOp op) {
        return switch (op.getOpCase()) {
            case NEXT_INT -> RngResult.newBuilder().setIntResult(nextInt(op.getNextInt())).build();
            case NEXT_BYTES -> RngResult.newBuilder().setBytesResult(nextBytes(op.getNextBytes())).build();
            case COMMIT_REVEAL -> throw new IllegalArgumentException("commit_reveal must use ServeStream");
            case OP_NOT_SET -> throw new IllegalArgumentException("empty RngOp");
        };
    }

    private IntResult nextInt(NextInt op) {
        return IntResult.newBuilder().setValue(uniform(op.getMin(), op.getMax())).build();
    }

    private BytesResult nextBytes(NextBytes op) {
        byte[] buf = new byte[op.getCount()];
        random.get().nextBytes(buf);
        return BytesResult.newBuilder().setData(ByteString.copyFrom(buf)).build();
    }

    /** Mint a seed and build both stream frames; the hash binds the (later) revealed seed. */
    CommitRevealFrames commitReveal(CommitReveal op) {
        byte[] seed = new byte[SEED_BYTES];
        random.get().nextBytes(seed);
        byte[] hash = sha256(seed);
        long value = deriveValue(hash, op.getMin(), op.getMax());
        CommitResult commit = CommitResult.newBuilder()
                .setCommitHash(ByteString.copyFrom(hash))
                .setDelaySeconds(op.getDelaySeconds())
                .build();
        RevealResult reveal = RevealResult.newBuilder()
                .setSeed(ByteString.copyFrom(seed))
                .setValue(value)
                .build();
        return new CommitRevealFrames(commit, reveal);
    }

    private long uniform(long min, long max) {
        if (max < min) {
            long t = min;
            min = max;
            max = t;
        }
        long span = max - min + 1;
        long bits = random.get().nextLong();
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

}
