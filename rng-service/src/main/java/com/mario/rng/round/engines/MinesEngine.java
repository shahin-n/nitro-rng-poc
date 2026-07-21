package com.mario.rng.round.engines;

import com.google.protobuf.ByteString;
import com.mario.crypto.MinesFair;
import com.mario.rng.app.MinesOutcome;
import com.mario.rng.app.MinesParams;
import com.mario.rng.app.MinesPick;
import com.mario.rng.app.MinesPickResult;
import com.mario.rng.app.RoundStatus;
import com.mario.rng.round.GameEngine;
import com.mario.rng.round.Round;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Mines (per-player). At open, a mine layout is fixed from the fairness stream and hidden; the
 * player picks cells one per action. A mine busts the round; safe picks raise the multiplier. At
 * settle the full layout is revealed so the client recomputes it from the disclosed serverSeed
 * and audits every pick.
 */
public final class MinesEngine implements GameEngine {

    /** Hidden per-round state — lives only in the enclave's {@code Round.gameState}. */
    private static final class State {
        int rows, cols, mines;
        Set<Integer> mineSet;
        Set<Integer> picked = new HashSet<>();
        int safeCount;
    }

    @Override
    public String gameType() {
        return "mines";
    }

    @Override
    public OpenResult open(Round round) {
        MinesParams p;
        try {
            p = MinesParams.parseFrom(round.params());
        } catch (Exception e) {
            throw new IllegalArgumentException("bad MinesParams: " + e.getMessage());
        }
        int rows = p.getRows(), cols = p.getCols(), mines = p.getMines();
        int n = rows * cols;
        if (rows <= 0 || cols <= 0 || mines < 1 || mines >= n) {
            throw new IllegalArgumentException("invalid grid " + rows + "x" + cols + " mines=" + mines);
        }
        int[] layout = MinesFair.layout(round.serverSeed(), round.clientSeed(), rows, cols, mines);
        State s = new State();
        s.rows = rows;
        s.cols = cols;
        s.mines = mines;
        s.mineSet = new HashSet<>();
        for (int c : layout) {
            s.mineSet.add(c);
        }
        round.setGameState(s);
        byte[] pub = MinesParams.newBuilder().setRows(rows).setCols(cols).setMines(mines).build().toByteArray();
        return new OpenResult(pub, RoundStatus.ROUND_OPEN);
    }

    @Override
    public ActionOutcome act(Round round, byte[] action, long nowMs) {
        State s = (State) round.gameState();
        if (s == null || round.status() != RoundStatus.ROUND_OPEN) {
            throw new IllegalStateException("round not open");
        }
        MinesPick pick;
        try {
            pick = MinesPick.parseFrom(action);
        } catch (Exception e) {
            throw new IllegalArgumentException("bad MinesPick: " + e.getMessage());
        }
        int cell = pick.getCell();
        int n = s.rows * s.cols;
        if (cell < 0 || cell >= n) {
            throw new IllegalArgumentException("cell out of range: " + cell);
        }
        if (!s.picked.add(cell)) {
            throw new IllegalArgumentException("cell already picked: " + cell);
        }

        boolean isMine = s.mineSet.contains(cell);
        RoundStatus status;
        double multiplier;
        if (isMine) {
            round.setStatus(RoundStatus.ROUND_BUST);
            status = RoundStatus.ROUND_BUST;
            multiplier = 0.0;
        } else {
            s.safeCount++;
            multiplier = MinesFair.multiplier(s.rows, s.cols, s.mines, s.safeCount);
            if (s.safeCount >= n - s.mines) {
                round.setStatus(RoundStatus.ROUND_WIN); // cleared every safe cell
                status = RoundStatus.ROUND_WIN;
            } else {
                status = RoundStatus.ROUND_OPEN;
            }
        }
        byte[] result = MinesPickResult.newBuilder()
                .setIsMine(isMine)
                .setSafeRevealed(s.safeCount)
                .setMultiplier(multiplier)
                .build().toByteArray();
        return new ActionOutcome(result, status);
    }

    @Override
    public boolean canSettle(Round round, long nowMs) {
        return true; // player may cash out any time; a bust also settles
    }

    @Override
    public SettleOutcome settle(Round round) {
        State s = (State) round.gameState();
        int[] mineCells = s == null ? new int[0] : s.mineSet.stream().mapToInt(Integer::intValue).sorted().toArray();
        MinesOutcome.Builder b = MinesOutcome.newBuilder();
        for (int c : mineCells) {
            b.addMineCells(c);
        }
        // cashout on an open round is a win; a busted round stays a bust
        RoundStatus status = round.status() == RoundStatus.ROUND_OPEN ? RoundStatus.ROUND_WIN : round.status();
        return new SettleOutcome(b.build().toByteArray(), status);
    }
}
