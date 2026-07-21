package com.mario.rng.round.engines;

import com.mario.crypto.Fairness;
import com.mario.rng.app.RoundStatus;
import com.mario.rng.round.GameEngine;
import com.mario.rng.round.Round;

import java.nio.charset.StandardCharsets;

/**
 * Dice (gourd-crab / tai-xiu style) — the existing commit-reveal expressed as an APFR round, to
 * prove the generic model covers today's case. Rolls 3d6 from the fairness stream at open, has no
 * actions, and reveals the roll at settle. The auto-settle hold (if any) is enforced by the server
 * via the round's settle deadline.
 */
public final class DiceEngine implements GameEngine {

    private static final int DICE = 3;
    private static final int FACES = 6;

    @Override
    public String gameType() {
        return "dice";
    }

    @Override
    public OpenResult open(Round round) {
        Fairness.Stream s = Fairness.stream(round.serverSeed(), round.clientSeed(), round.params());
        int[] dice = new int[DICE];
        for (int i = 0; i < DICE; i++) {
            dice[i] = s.nextInt(FACES) + 1;
        }
        round.setGameState(dice);
        return new OpenResult(new byte[0], RoundStatus.ROUND_OPEN);
    }

    @Override
    public ActionOutcome act(Round round, byte[] action, long nowMs) {
        throw new UnsupportedOperationException("dice round has no actions");
    }

    @Override
    public boolean canSettle(Round round, long nowMs) {
        return round.settleAtMs() == 0 || nowMs >= round.settleAtMs();
    }

    @Override
    public SettleOutcome settle(Round round) {
        int[] dice = (int[]) round.gameState();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < dice.length; i++) {
            if (i > 0) {
                sb.append("-");
            }
            sb.append(dice[i]);
        }
        return new SettleOutcome(sb.toString().getBytes(StandardCharsets.UTF_8), RoundStatus.ROUND_SETTLED);
    }
}
