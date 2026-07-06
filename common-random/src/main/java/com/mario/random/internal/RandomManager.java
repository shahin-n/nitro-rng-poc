package com.mario.random.internal;

import java.util.Random;

import com.mario.random.internal.strategies.ChaCha20RandomStrategy;
import com.mario.random.internal.strategies.HmacDrbgRandomStrategy;
import com.mario.random.internal.strategies.SecureRandomStrategy;
import com.mario.random.internal.strategies.Sha256CounterRandomStrategy;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * {@code RandomManager} is a strategy-backed random number generator with a secure-only default
 * strategy pool for production use.
 * <p>
 * It extends {@link java.util.Random} and backs the {@link Random} entropy source with
 * interchangeable {@link InternalRandomStrategy} implementations. The bounded and scalar methods
 * are implemented directly, and inherited methods such as {@link #nextInt()},
 * {@link #nextFloat()}, and {@link #nextBytes(byte[])} derive their randomness through
 * {@link #next(int)}, preserving the standard {@link Random} contracts for ranges and signedness:
 * <p>
 * <b>Thread confinement:</b> a {@code RandomManager} instance is intended to be owned by a single
 * thread. It is not safe to share one instance across threads, and callers must not rely on the
 * usual "share a {@link Random}" usage pattern for this type.
 * <ul>
 *   <li>{@link SecureRandomStrategy} – cryptographically strong randomness</li>
 *   <li>{@link HmacDrbgRandomStrategy} – deterministic random bit generator (HMAC-DRBG)</li>
 *   <li>{@link Sha256CounterRandomStrategy} – SHA-256 counter-mode randomness</li>
 *   <li>{@link ChaCha20RandomStrategy} – ChaCha20-based randomness</li>
 * </ul>
 * The manager periodically rotates between strategies every
 * {@link #ROTATION_STRATEGY_THRESHOLD} nanoseconds (default 500 ms), using an entropy-based seed.
 * This reduces predictability and dependency on a single algorithm.
 *
 * <h2><b>⚠ Important Security Note</b></h2>
 * Standard {@link Random} methods derive entropy from the internal strategy source, but the
 * manager remains thread-confined and rotates between strategies. Treat it as a custom RNG with
 * {@link Random}-compatible method contracts rather than a shareable drop-in replacement for every
 * {@link Random} use case. The default constructor uses only cryptographically strong strategy
 * implementations.
 *
 * <h2>Usage Example</h2>
 * <pre>{@code
 * RandomManager random = new RandomManager();
 * int value = random.nextInt(100);
 * double fraction = random.nextDouble();
 * long secureLong = random.nextLong();
 * boolean flag = random.nextBoolean();
 * }</pre>
 */
public class RandomManager extends Random {
    public static final Duration ROTATION_STRATEGY_THRESHOLD = Duration.ofMillis(500); // 500ms

    private final List<InternalRandomStrategy> strategies;
    private final EntropySource entropy;
    private final AtomicLong lastSwitch;
    private volatile InternalRandomStrategy currentStrategy;

    public RandomManager() {
        strategies = createDefaultStrategies();
        entropy = createEntropySource();
        currentStrategy = strategies.get(0);
        lastSwitch = new AtomicLong(entropy.getNanoTime());
    }

    /**
     * Creates the production-oriented secure default strategy pool.
     */
    protected List<InternalRandomStrategy> createDefaultStrategies() {
        return Arrays.asList(
                new SecureRandomStrategy(),
                new HmacDrbgRandomStrategy(),
                new Sha256CounterRandomStrategy(),
                new ChaCha20RandomStrategy()
        );
    }

    protected EntropySource createEntropySource() {
        return new EntropySource();
    }

    /**
     * Returns the simple class name of the currently active strategy for debugging or
     * same-thread diagnostics.
     */
    public String getCurrentStrategyName() {
        return currentStrategy.getClass().getSimpleName();
    }

    @Override
    protected int next(int bits) {
        if (bits <= 0 || bits > Integer.SIZE) {
            throw new IllegalArgumentException("bits must be between 1 and 32");
        }
        return (int) (currentStrategyForUse().nextLong(entropy) >>> (Long.SIZE - bits));
    }

    @Override
    public int nextInt(int bound) {
        if (bound <= 0) {
            throw new IllegalArgumentException("bound must be positive");
        }
        return currentStrategyForUse().nextInt(bound, entropy);
    }

    @Override
    public double nextDouble() {
        return currentStrategyForUse().nextDouble(entropy);
    }

    @Override
    public long nextLong() {
        return currentStrategyForUse().nextLong(entropy);
    }

    @Override
    public boolean nextBoolean() {
        return currentStrategyForUse().nextBoolean(entropy);
    }

    private InternalRandomStrategy currentStrategyForUse() {
        if (shouldRotateStrategy()) {
            rotateStrategy();
        }
        return currentStrategy;
    }

    private boolean shouldRotateStrategy() {
        final long currentTime = entropy.getNanoTime();
        final long timeSinceLastSwitch = currentTime - lastSwitch.get();
        return timeSinceLastSwitch > ROTATION_STRATEGY_THRESHOLD.getNano();
    }

    private void rotateStrategy() {
        long seed = entropy.getCompositeSeed();
        if (seed == Long.MIN_VALUE) {
            seed = 0;
        }
        final int newIndex = (int) (Math.abs(seed) % strategies.size());
        final InternalRandomStrategy nextStrategy = strategies.get(newIndex);
        nextStrategy.reseed(entropy);
        currentStrategy = nextStrategy;
        lastSwitch.set(entropy.getNanoTime());
    }
}
