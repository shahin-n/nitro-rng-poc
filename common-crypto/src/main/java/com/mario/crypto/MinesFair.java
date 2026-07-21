package com.mario.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Deterministic mine-layout derivation, shared by the enclave (generates) and the client
 * (audits). Given the seeds + grid, both sides compute the SAME sorted set of mine cells,
 * so at reveal the client recomputes the layout from the disclosed serverSeed and checks it
 * against what the enclave revealed.
 */
public final class MinesFair {

    private MinesFair() {
    }

    /**
     * The mine cell indices (sorted, distinct) for a rows*cols grid, derived from the fairness
     * stream via a partial Fisher-Yates shuffle. Canonical params string keeps derivation stable
     * regardless of protobuf wire encoding.
     */
    public static int[] layout(byte[] serverSeed, byte[] clientSeed, int rows, int cols, int mines) {
        int n = rows * cols;
        if (rows <= 0 || cols <= 0 || mines < 0 || mines > n) {
            throw new IllegalArgumentException("bad grid: " + rows + "x" + cols + " mines=" + mines);
        }
        Fairness.Stream s = Fairness.stream(serverSeed, clientSeed, params(rows, cols, mines));
        int[] deck = new int[n];
        for (int i = 0; i < n; i++) {
            deck[i] = i;
        }
        for (int i = 0; i < mines; i++) {
            int j = i + s.nextInt(n - i);
            int t = deck[i];
            deck[i] = deck[j];
            deck[j] = t;
        }
        int[] out = Arrays.copyOf(deck, mines);
        Arrays.sort(out);
        return out;
    }

    /** Payout multiplier after {@code safe} safe picks on a rows*cols grid with {@code mines} mines. */
    public static double multiplier(int rows, int cols, int mines, int safe) {
        int n = rows * cols;
        double m = 1.0;
        // fair (house-edge-free) multiplier = product of inverse survival probabilities
        for (int k = 0; k < safe; k++) {
            int safeLeft = n - mines - k;
            int cellsLeft = n - k;
            if (safeLeft <= 0) {
                break;
            }
            m *= (double) cellsLeft / safeLeft;
        }
        return Math.round(m * 100.0) / 100.0;
    }

    private static byte[] params(int rows, int cols, int mines) {
        return (rows + "x" + cols + "x" + mines).getBytes(StandardCharsets.UTF_8);
    }
}
