package com.mario.rng.round;

import com.google.protobuf.ByteString;
import com.mario.crypto.Fairness;
import com.mario.rng.app.ActionResult;
import com.mario.rng.app.RngOp;
import com.mario.rng.app.RngResult;
import com.mario.rng.app.RoundAction;
import com.mario.rng.app.RoundOpen;
import com.mario.rng.app.RoundOpened;
import com.mario.rng.app.RoundSettle;
import com.mario.rng.app.RoundSettled;

/**
 * Drives the Attested Provably-Fair Round lifecycle inside the enclave: dispatches the round ops
 * (open / action / settle) against the {@link RoundRegistry} + {@link EngineRegistry}, and builds
 * the RngResult the server will attest. All secrets stay in the registry until {@link #settle}.
 *
 * <p>Affinity/authorization note (v1): a round_id is a 128-bit secret returned only to the opener,
 * so knowing it is the capability to act on the round; combined with proxy module_id routing (the
 * round lives in exactly one enclave) this bounds who can act. Stronger owner-identity binding is a
 * later refinement.
 */
public final class RoundService {

    private final RoundRegistry rounds = new RoundRegistry();
    private final EngineRegistry engines = new EngineRegistry();

    public RngResult handle(RngOp op, String ownerModuleId, long nowMs) {
        return switch (op.getOpCase()) {
            case ROUND_OPEN -> open(op.getRoundOpen(), ownerModuleId, nowMs);
            case ROUND_ACTION -> action(op.getRoundAction(), nowMs);
            case ROUND_SETTLE -> settle(op.getRoundSettle(), nowMs);
            default -> throw new IllegalArgumentException("not a round op: " + op.getOpCase());
        };
    }

    private RngResult open(RoundOpen ro, String ownerModuleId, long nowMs) {
        GameEngine engine = engines.get(ro.getGameType());
        long settleAt = ro.getSettleAfterSeconds() > 0 ? nowMs + ro.getSettleAfterSeconds() * 1000L : 0;
        Round r = rounds.open(ro.getGameType(), ro.getKind(),
                ro.getClientSeed().toByteArray(), ro.getParams().toByteArray(),
                ro.getSessionId(), ownerModuleId, nowMs, settleAt);

        GameEngine.OpenResult res;
        synchronized (r.lock()) {
            res = engine.open(r);
            r.setStatus(res.status());
        }
        RoundOpened opened = RoundOpened.newBuilder()
                .setRoundId(r.roundId())
                .setCommit(Fairness.commit(r.serverSeed())) // hex SHA256(serverSeed) — bound in the doc
                .setGameType(r.gameType())
                .setKind(r.kind())
                .setPublicParams(ByteString.copyFrom(res.publicParams()))
                .setServerTimeMs(nowMs)
                .build();
        return RngResult.newBuilder().setRoundOpened(opened).build();
    }

    private RngResult action(RoundAction ra, long nowMs) {
        Round r = require(ra.getRoundId());
        GameEngine engine = engines.get(r.gameType());
        GameEngine.ActionOutcome out;
        synchronized (r.lock()) {
            if (r.terminal()) {
                throw new IllegalStateException("round already terminal: " + r.status());
            }
            if (ra.getSeq() <= r.lastSeq()) {
                throw new IllegalStateException("stale or replayed seq: " + ra.getSeq());
            }
            out = engine.act(r, ra.getAction().toByteArray(), nowMs);
            r.setLastSeq(ra.getSeq());
            r.setStatus(out.status());
        }
        ActionResult ar = ActionResult.newBuilder()
                .setRoundId(r.roundId())
                .setSeq(ra.getSeq())
                .setResult(ByteString.copyFrom(out.result()))
                .setStatus(out.status())
                .build();
        return RngResult.newBuilder().setActionResult(ar).build();
    }

    private RngResult settle(RoundSettle rs, long nowMs) {
        Round r = require(rs.getRoundId());
        GameEngine engine = engines.get(r.gameType());
        GameEngine.SettleOutcome out;
        byte[] serverSeed;
        synchronized (r.lock()) {
            if (!engine.canSettle(r, nowMs)) {
                throw new IllegalStateException("round not settleable yet");
            }
            out = engine.settle(r);
            r.setStatus(out.status());
            serverSeed = r.serverSeed().clone(); // reveal a copy before the registry wipes it
        }
        RoundSettled settled = RoundSettled.newBuilder()
                .setRoundId(r.roundId())
                .setServerSeed(ByteString.copyFrom(serverSeed))
                .setClientSeed(ByteString.copyFrom(r.clientSeed()))
                .setOutcome(ByteString.copyFrom(out.outcome()))
                .setStatus(out.status())
                .build();
        rounds.remove(r.roundId()); // drop + wipe the secret now that it's revealed
        return RngResult.newBuilder().setRoundSettled(settled).build();
    }

    private Round require(String roundId) {
        Round r = rounds.get(roundId);
        if (r == null) {
            throw new IllegalStateException("unknown or expired round: " + roundId);
        }
        return r;
    }
}
