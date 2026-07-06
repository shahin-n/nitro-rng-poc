package com.mario.random.internal;
import java.security.SecureRandom;

public class EntropySource {
    private final SecureRandom secureRandom = new SecureRandom();

    public long getSeed() {
        return System.nanoTime() ^
                Runtime.getRuntime().freeMemory() ^
                secureRandom.nextLong();
    }

    public long getCompositeSeed() {
        return getSeed() ^
                ((long) Thread.activeCount() << 24) ^
                ((long) System.identityHashCode(this) << 32);
    }

    public long getNanoTime() {
        return System.nanoTime();
    }

    public int getThreadCount() {
        return Thread.activeCount();
    }

    public int getCpuCores() {
        return Runtime.getRuntime().availableProcessors();
    }
}
