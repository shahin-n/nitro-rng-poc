package com.mario.rng.round;

import com.google.protobuf.ByteString;
import com.mario.crypto.Fairness;
import com.mario.crypto.MinesFair;
import com.mario.rng.app.ActionResult;
import com.mario.rng.app.MinesOutcome;
import com.mario.rng.app.MinesParams;
import com.mario.rng.app.MinesPick;
import com.mario.rng.app.MinesPickResult;
import com.mario.rng.app.RngOp;
import com.mario.rng.app.RoundAction;
import com.mario.rng.app.RoundKind;
import com.mario.rng.app.RoundOpen;
import com.mario.rng.app.RoundOpened;
import com.mario.rng.app.RoundSettle;
import com.mario.rng.app.RoundSettled;
import com.mario.rng.app.RoundStatus;

import java.security.SecureRandom;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * In-process round-logic self-test (no enclave / NSM needed): drives {@link RoundService} through a
 * full mines round and audits it exactly as the client would.
 *
 * Run: mvn -pl rng-service -am -DskipTests package && \
 *      java -cp rng-service/target/rng-service.jar com.mario.rng.round.RoundSelfTest
 */
public final class RoundSelfTest {

    public static void main(String[] args) {
        boolean ok = minesRound() & diceRound();
        System.out.println(ok ? ">> ROUND SELF-TEST OK" : ">> ROUND SELF-TEST FAILED");
        if (!ok) {
            System.exit(1);
        }
    }

    private static boolean minesRound() {
        RoundService svc = new RoundService();
        int rows = 5, cols = 5, mines = 3, n = rows * cols;
        byte[] clientSeed = new byte[16];
        new SecureRandom().nextBytes(clientSeed);

        RngOp openOp = RngOp.newBuilder().setRoundOpen(RoundOpen.newBuilder()
                .setGameType("mines").setKind(RoundKind.PER_PLAYER)
                .setClientSeed(ByteString.copyFrom(clientSeed))
                .setParams(MinesParams.newBuilder().setRows(rows).setCols(cols).setMines(mines).build().toByteString())
                .setSessionId("selftest")).build();
        RoundOpened opened = svc.handle(openOp, "mod", 1_000).getRoundOpened();
        String roundId = opened.getRoundId();
        String commit = opened.getCommit();

        // Pick cells 0,1,2,... until a bust or all-safe cleared; record what the enclave reported.
        Map<Integer, Boolean> picks = new LinkedHashMap<>();
        int seq = 0;
        for (int cell = 0; cell < n; cell++) {
            RngOp actOp = RngOp.newBuilder().setRoundAction(RoundAction.newBuilder()
                    .setRoundId(roundId).setSeq(++seq)
                    .setAction(MinesPick.newBuilder().setCell(cell).build().toByteString())).build();
            ActionResult ar = svc.handle(actOp, "mod", 1_000).getActionResult();
            MinesPickResult pr;
            try {
                pr = MinesPickResult.parseFrom(ar.getResult());
            } catch (Exception e) {
                return fail("mines: parse pick result: " + e);
            }
            picks.put(cell, pr.getIsMine());
            if (pr.getIsMine() || ar.getStatus() == RoundStatus.ROUND_WIN) {
                break;
            }
        }

        RngOp settleOp = RngOp.newBuilder().setRoundSettle(RoundSettle.newBuilder().setRoundId(roundId)).build();
        RoundSettled settled = svc.handle(settleOp, "mod", 1_000).getRoundSettled();
        byte[] serverSeed = settled.getServerSeed().toByteArray();
        MinesOutcome outcome;
        try {
            outcome = MinesOutcome.parseFrom(settled.getOutcome());
        } catch (Exception e) {
            return fail("mines: parse outcome: " + e);
        }

        // audit exactly as the client does
        boolean commitOk = Fairness.commit(serverSeed).equalsIgnoreCase(commit);
        int[] recomputed = MinesFair.layout(serverSeed, clientSeed, rows, cols, mines);
        Set<Integer> recomputedSet = new HashSet<>();
        for (int c : recomputed) {
            recomputedSet.add(c);
        }
        Set<Integer> revealed = new HashSet<>(outcome.getMineCellsList());
        boolean layoutOk = revealed.equals(recomputedSet) && revealed.size() == mines;
        boolean picksOk = true;
        boolean sawMine = false;
        for (Map.Entry<Integer, Boolean> e : picks.entrySet()) {
            boolean actualMine = recomputedSet.contains(e.getKey());
            if (actualMine != e.getValue()) {
                picksOk = false;
            }
            sawMine |= e.getValue();
        }
        boolean statusOk = sawMine ? settled.getStatus() == RoundStatus.ROUND_BUST
                : settled.getStatus() == RoundStatus.ROUND_WIN;

        System.out.printf("  mines: commit=%s picks=%d mines=%s commitOk=%s layoutOk=%s picksOk=%s statusOk=%s%n",
                commit.substring(0, 12), picks.size(), revealed, commitOk, layoutOk, picksOk, statusOk);
        return commitOk && layoutOk && picksOk && statusOk;
    }

    private static boolean diceRound() {
        RoundService svc = new RoundService();
        byte[] clientSeed = new byte[8];
        new SecureRandom().nextBytes(clientSeed);
        RngOp openOp = RngOp.newBuilder().setRoundOpen(RoundOpen.newBuilder()
                .setGameType("dice").setKind(RoundKind.COMMON)
                .setClientSeed(ByteString.copyFrom(clientSeed))).build();
        RoundOpened opened = svc.handle(openOp, "mod", 2_000).getRoundOpened();
        RngOp settleOp = RngOp.newBuilder().setRoundSettle(RoundSettle.newBuilder().setRoundId(opened.getRoundId())).build();
        RoundSettled settled = svc.handle(settleOp, "mod", 2_000).getRoundSettled();
        boolean commitOk = Fairness.commit(settled.getServerSeed().toByteArray()).equalsIgnoreCase(opened.getCommit());
        String roll = settled.getOutcome().toStringUtf8();
        boolean rollOk = roll.matches("[1-6]-[1-6]-[1-6]");
        System.out.printf("  dice:  roll=%s commitOk=%s rollOk=%s%n", roll, commitOk, rollOk);
        return commitOk && rollOk;
    }

    private static boolean fail(String msg) {
        System.out.println("  FAIL: " + msg);
        return false;
    }
}
