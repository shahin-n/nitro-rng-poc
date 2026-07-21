package com.mario.rng.round;

import com.mario.rng.app.RoundStatus;

/**
 * A pluggable game. Everything a game must define lives in these four methods — the round
 * protocol, attestation, registry and transport never change per game. Register an engine in
 * {@link EngineRegistry} by {@link #gameType()} and it is reachable via the APFR round ops.
 *
 * <p>Contract: engines derive their outcome deterministically from {@code round.serverSeed +
 * clientSeed + params} (via {@link com.mario.crypto.Fairness}) and MUST NOT leak any unrevealed
 * secret through {@link #open} public params or {@link #act} results — only {@link #settle}
 * discloses the seed/outcome. Callers hold {@code round.lock} around {@link #act}/{@link #settle}.
 */
public interface GameEngine {

    String gameType();

    /** Validate params, precompute + stash the hidden outcome in {@code round.gameState}, return public info. */
    OpenResult open(Round round);

    /** Apply one player action; returns the game result bytes + the (possibly changed) round status. */
    ActionOutcome act(Round round, byte[] action, long nowMs);

    /** Whether the round may settle now (time- or action-driven). */
    boolean canSettle(Round round, long nowMs);

    /** Produce the reveal (serverSeed is added by the caller); returns the full outcome bytes + final status. */
    SettleOutcome settle(Round round);

    /** Public info returned at open (e.g. echoed grid dimensions). Never contains the secret. */
    record OpenResult(byte[] publicParams, RoundStatus status) {
    }

    /** Result of one action: game-specific bytes + the round's status after applying it. */
    record ActionOutcome(byte[] result, RoundStatus status) {
    }

    /** Settle reveal: game-specific full outcome bytes + terminal status. */
    record SettleOutcome(byte[] outcome, RoundStatus status) {
    }
}
