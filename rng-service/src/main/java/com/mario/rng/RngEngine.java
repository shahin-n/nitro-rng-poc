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
import com.mario.rng.app.NoiseCommitReveal;
import com.mario.rng.app.NoiseCommitResult;
import com.mario.rng.app.NoiseRevealResult;
import com.mario.rng.app.RngOp;
import com.mario.rng.app.RngResult;
import com.mario.rng.reveal.NoiseConfig;
import com.mario.rng.reveal.ResultProcessor;
import com.mario.rng.reveal.ResultProcessorFactory;

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

    /** The two frames of one noise-padded commit-reveal (commit hash, then the noise-wrapped payload). */
    record NoiseFrames(NoiseCommitResult commit, NoiseRevealResult reveal) {
    }

    RngResult execute(RngOp op) {
        return switch (op.getOpCase()) {
            case NEXT_INT -> RngResult.newBuilder().setIntResult(nextInt(op.getNextInt())).build();
            case NEXT_BYTES -> RngResult.newBuilder().setBytesResult(nextBytes(op.getNextBytes())).build();
            case COMMIT_REVEAL -> throw new IllegalArgumentException("commit_reveal must use ServeStream");
            case NOISE_COMMIT_REVEAL -> throw new IllegalArgumentException("noise_commit_reveal must use ServeStreamAttested");
            case ROUND_OPEN, ROUND_ACTION, ROUND_SETTLE ->
                    throw new IllegalArgumentException(op.getOpCase() + " must use ServeAttested");
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

    /**
     * Noise-padded commit-reveal. The DICE come from the enclave RNG ({@link RandomManager} via
     * {@link #uniform}); the noise/emoji wrapping + commit hash come from {@link ResultProcessor}
     * (its own SecureRandom — noise is not the result). Returns both frames; the hash binds the
     * (later) revealed payload just like the seed variant.
     */
    NoiseFrames noiseCommitReveal(NoiseCommitReveal op) {
        int count = op.getDiceCount() > 0 ? op.getDiceCount() : 3;
        int faces = op.getDiceFaces() > 0 ? op.getDiceFaces() : 6;

        StringBuilder rt = new StringBuilder();
        for (int i = 0; i < count; i++) {
            if (i > 0) {
                rt.append("-");
            }
            rt.append(uniform(1, faces)); // each die in [1..faces], from the trusted enclave RNG
        }
        String resultText = rt.toString();

        NoiseConfig cfg = new NoiseConfig(
                op.getEncryptionType(), op.getUseEncryption(),
                op.getNoiseStringLength(), op.getNoiseEmojiLength(), op.getNoiseAdjustment());
        ResultProcessor.NoiseResult nr = ResultProcessorFactory.create(cfg)
                .handle(op.getSessionId(), resultText);

        NoiseCommitResult commit = NoiseCommitResult.newBuilder()
                .setCommit(nr.commit())
                .setEncryptionType(nr.encryptionType())
                .setDelaySeconds(op.getDelaySeconds())
                .build();
        NoiseRevealResult reveal = NoiseRevealResult.newBuilder()
                .setPayload(nr.payload())
                .setResultText(resultText)
                .build();
        return new NoiseFrames(commit, reveal);
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
