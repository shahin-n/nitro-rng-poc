package com.mario.rng.round;

import com.mario.rng.app.RoundKind;
import com.mario.rng.app.RoundStatus;

/**
 * One in-flight Attested Provably-Fair Round, held in enclave RAM by {@link RoundRegistry}
 * between the open, the actions and the settle. The secret fields ({@link #serverSeed()} and the
 * engine's hidden {@link #gameState()}) NEVER leave the enclave until the settle reveal.
 *
 * <p>All mutation happens under {@link #lock()}. Not a record — it is mutable per-round state.
 * Accessors are public because engines live in {@code com.mario.rng.round.engines} and the server
 * in {@code com.mario.rng}; every caller is enclave code.
 */
public final class Round {

    private final String roundId;
    private final String gameType;
    private final RoundKind kind;
    private final byte[] serverSeed;   // secret until settle
    private final byte[] clientSeed;
    private final byte[] params;       // game-specific params bytes (echoed, not secret)
    private final String sessionId;
    private final String ownerModuleId; // the enclave module that owns this round (affinity/audit)
    private final long openedAtMs;
    private final long settleAtMs;      // enclave-clock deadline for auto-settle; 0 = manual only

    private final Object lock = new Object();

    private RoundStatus status = RoundStatus.ROUND_OPEN;
    private int lastSeq = 0;            // last applied action seq (monotonic guard)
    private Object gameState;          // engine-private hidden state (e.g. mines layout + picks)

    Round(String roundId, String gameType, RoundKind kind, byte[] serverSeed, byte[] clientSeed,
          byte[] params, String sessionId, String ownerModuleId, long openedAtMs, long settleAtMs) {
        this.roundId = roundId;
        this.gameType = gameType;
        this.kind = kind;
        this.serverSeed = serverSeed;
        this.clientSeed = clientSeed;
        this.params = params;
        this.sessionId = sessionId;
        this.ownerModuleId = ownerModuleId;
        this.openedAtMs = openedAtMs;
        this.settleAtMs = settleAtMs;
    }

    public String roundId() {
        return roundId;
    }

    public String gameType() {
        return gameType;
    }

    public RoundKind kind() {
        return kind;
    }

    public byte[] serverSeed() {
        return serverSeed;
    }

    public byte[] clientSeed() {
        return clientSeed;
    }

    public byte[] params() {
        return params;
    }

    public String sessionId() {
        return sessionId;
    }

    public String ownerModuleId() {
        return ownerModuleId;
    }

    public long openedAtMs() {
        return openedAtMs;
    }

    public long settleAtMs() {
        return settleAtMs;
    }

    public Object lock() {
        return lock;
    }

    public RoundStatus status() {
        return status;
    }

    public void setStatus(RoundStatus status) {
        this.status = status;
    }

    public int lastSeq() {
        return lastSeq;
    }

    public void setLastSeq(int seq) {
        this.lastSeq = seq;
    }

    public Object gameState() {
        return gameState;
    }

    public void setGameState(Object gameState) {
        this.gameState = gameState;
    }

    public boolean terminal() {
        return status != RoundStatus.ROUND_OPEN;
    }
}
