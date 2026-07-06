package com.mario.random.internal;

public interface InternalRandomStrategy {
    int nextInt(int bound, EntropySource entropy);

    boolean nextBoolean(EntropySource entropy);

    double nextDouble(EntropySource entropy);

    long nextLong(EntropySource entropy);

    void reseed(EntropySource entropy);
}
