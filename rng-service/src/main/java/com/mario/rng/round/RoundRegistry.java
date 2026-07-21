package com.mario.rng.round;

import com.mario.crypto.Fairness;
import com.mario.rng.app.RoundKind;
import com.mario.rng.app.RoundStatus;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Holds in-flight rounds in enclave RAM, keyed by round_id. This is the deliberate stateful
 * core that lets interactive games (mines/aviator) keep a committed secret across multiple
 * attested calls. Bounded to survive abuse:
 * <ul>
 *   <li><b>max-rounds cap</b> — {@link #open} rejects new rounds past {@link #maxRounds} (DoS bound);</li>
 *   <li><b>TTL eviction</b> — rounds past {@link #ttlMs} since open are swept (also drops leaked
 *       secrets promptly). A lazy sweep runs on each {@code open}.</li>
 * </ul>
 * Secrets are dropped as soon as a round leaves the map.
 */
public final class RoundRegistry {

    private static final HexFormat HEX = HexFormat.of();

    private final ConcurrentHashMap<String, Round> rounds = new ConcurrentHashMap<>();
    private final SecureRandom rng = new SecureRandom();
    private final int maxRounds;
    private final long ttlMs;

    public RoundRegistry() {
        this(Integer.getInteger("apfr.maxRounds", 10_000),
                Long.getLong("apfr.ttlMs", 10 * 60_000L));
    }

    public RoundRegistry(int maxRounds, long ttlMs) {
        this.maxRounds = maxRounds;
        this.ttlMs = ttlMs;
    }

    /**
     * Create a round with a fresh 32-byte serverSeed. The commit ({@code SHA256(serverSeed)}) is
     * derived by the caller via {@link Fairness#commit}. Throws if the max-rounds cap is hit.
     */
    public Round open(String gameType, RoundKind kind, byte[] clientSeed, byte[] params,
                      String sessionId, String ownerModuleId, long nowMs, long settleAtMs) {
        sweep(nowMs);
        if (rounds.size() >= maxRounds) {
            throw new IllegalStateException("round capacity reached (" + maxRounds + ")");
        }
        byte[] serverSeed = new byte[Fairness.SEED_BYTES];
        rng.nextBytes(serverSeed);
        String roundId = newRoundId();
        Round r = new Round(roundId, gameType, kind, serverSeed,
                clientSeed == null ? new byte[0] : clientSeed,
                params == null ? new byte[0] : params,
                sessionId == null ? "" : sessionId,
                ownerModuleId == null ? "" : ownerModuleId,
                nowMs, settleAtMs);
        rounds.put(roundId, r);
        return r;
    }

    /** Look up a live round; null if unknown or already evicted. */
    public Round get(String roundId) {
        return rounds.get(roundId);
    }

    /** Drop a settled/terminal round and wipe its secret. */
    public void remove(String roundId) {
        Round r = rounds.remove(roundId);
        if (r != null) {
            java.util.Arrays.fill(r.serverSeed(), (byte) 0);
        }
    }

    public int size() {
        return rounds.size();
    }

    /** Evict rounds whose TTL elapsed (also settles the status to EXPIRED before drop). */
    private void sweep(long nowMs) {
        for (Iterator<Map.Entry<String, Round>> it = rounds.entrySet().iterator(); it.hasNext(); ) {
            Round r = it.next().getValue();
            if (nowMs - r.openedAtMs() > ttlMs) {
                synchronized (r.lock()) {
                    if (r.status() == RoundStatus.ROUND_OPEN) {
                        r.setStatus(RoundStatus.ROUND_EXPIRED);
                    }
                }
                java.util.Arrays.fill(r.serverSeed(), (byte) 0);
                it.remove();
            }
        }
    }

    private String newRoundId() {
        byte[] id = new byte[16];
        rng.nextBytes(id);
        return HEX.formatHex(id);
    }
}
