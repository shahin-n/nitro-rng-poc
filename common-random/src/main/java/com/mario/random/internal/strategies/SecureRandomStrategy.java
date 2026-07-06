package com.mario.random.internal.strategies;

import com.mario.random.internal.EntropySource;
import com.mario.random.internal.InternalRandomStrategy;

import java.security.SecureRandom;

public class SecureRandomStrategy implements InternalRandomStrategy {

    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public int nextInt(int bound, EntropySource entropy) {
        return secureRandom.nextInt(bound);
    }

    @Override
    public boolean nextBoolean(EntropySource entropy) {
        return secureRandom.nextBoolean();
    }

    @Override
    public double nextDouble(EntropySource entropy) {
        return secureRandom.nextDouble();
    }

    @Override
    public long nextLong(EntropySource entropy) {
        return secureRandom.nextLong();
    }

    @Override
    public void reseed(EntropySource entropy) {
        secureRandom.setSeed(entropy.getSeed());
    }
}
