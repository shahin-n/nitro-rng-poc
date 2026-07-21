# Plan: Attested Provably-Fair Round (APFR) — a common game standard

## Context

Today the enclave only does one provably-fair shape: a stateless, two-frame commit-reveal
(`ServeStreamAttested` → commit hash, hold, reveal seed). That fits dice/noise but cannot express
games that need **state between commit and reveal**:

- **Mines** (greenfield — does not exist in the platform): a mine layout is fixed once at round
  start, then the player picks cells over several round-trips, cashes out, and the layout is revealed.
- **Aviator** (exists at `scaling/mini-game/aviator-mini-game-core` but is NOT commit-reveal today —
  crash decided at cash-out start, revealed at `endGame`): one crash multiplier per shared round,
  many players cash out before it, reveal after crash.

Rather than bespoke code per game, build **one generic attested-round standard** + a pluggable
per-game engine. Every game reuses the same commit → act → reveal machinery, attestation binding,
and registry; games differ only in three pure functions. This rides the request-bound attested
envelope just added (`AttestedResult` binds `SHA256(request‖result)`), so every round step — open,
each action, settle — is independently provable, giving an auditable proof chain per round.

**Locked decisions:** server+client seed fairness; two round kinds `PER_PLAYER` (mines) +
`COMMON`/shared (aviator, dice-broadcast); live cashouts as unary attested calls; first slice =
framework + retrofit dice + **mines** (aviator is designed-for but built later).

**Naming** mirrors the platform where it exists: `roundId`, `sessionId`, `gameType`, `commit`
(= their `resultHash`/`hash_result`), `outcome` (= their `result`). We introduce `serverSeed`/
`clientSeed` (absent in the platform today) since the seed-pair model was chosen.

## Approach

### 1. Generic round protocol (proto) — `proto/src/main/proto/app.proto`
Add a round envelope whose game-specific bodies are **opaque `bytes`** (nested game messages), so the
standard never changes per game:

```
enum RoundKind   { PER_PLAYER = 0; COMMON = 1; }
enum RoundStatus { ROUND_OPEN=0; ROUND_WIN=1; ROUND_LOSS=2; ROUND_BUST=3; ROUND_EXPIRED=4; ROUND_SETTLED=5; }

message RoundOpen   { string game_type=1; RoundKind kind=2; bytes client_seed=3; bytes params=4; string session_id=5; uint32 settle_after_seconds=6; }
message RoundOpened { string round_id=1; string commit=2; string game_type=3; RoundKind kind=4; bytes public_params=5; int64 server_time_ms=6; }
message RoundAction { string round_id=1; uint32 seq=2; bytes action=3; }
message ActionResult{ string round_id=1; uint32 seq=2; bytes result=3; RoundStatus status=4; }
message RoundSettle { string round_id=1; }
message RoundSettled{ string round_id=1; bytes server_seed=2; bytes client_seed=3; bytes outcome=4; RoundStatus status=5; }
```
Extend the existing oneofs: `RngOp += round_open=5, round_action=6, round_settle=7`;
`RngResult += round_opened=7, action_result=8, round_settled=9`.

New file `proto/src/main/proto/games.proto` for the first game bodies:
`MinesParams{uint32 rows, cols, mines}`, `MinesPick{uint32 cell}`,
`MinesPickResult{bool is_mine; uint32 safe_revealed; double multiplier}`,
`MinesOutcome{repeated uint32 mine_cells}`. Aviator bodies added when that game lands.

### 2. Fairness — `rng-service/.../rng/round/Fairness.java` (new)
- `serverSeed` = 32B from the enclave RNG (`RandomManager`, via `RngEngine`).
- `commit` = hex `SHA256(serverSeed)` (reuse `com.mario.rng.reveal.Sha256Utils`).
- `deriveOutcome`: deterministic stream `HMAC-SHA256(key=serverSeed, msg=clientSeed‖params‖counter)`
  consumed by the engine. Neither side alone controls the result.
- Settle reveals `serverSeed` (+ echoes `clientSeed`); client checks `SHA256(serverSeed)==commit`
  and recomputes `outcome`.

### 3. Stateful round registry — `rng-service/.../rng/round/` (new)
- `Round`: `roundId, gameType, kind, serverSeed(secret), clientSeed, params, outcome(secret,
  precomputed at open), status, List<action> log, openedAtMs, settleAtMs, ownerModuleId, ownerTag`.
- `RoundRegistry`: `ConcurrentHashMap<String,Round>` + **per-round lock**, **TTL eviction**
  (settle + grace) and a **max-rounds cap** (reject `RoundOpen` past the cap — DoS bound). Secret
  fields never serialized except the settle reveal. round_id = enclave-generated random id.
- **Affinity:** a round lives in one enclave's RAM; the proxy already routes by `module_id`
  (session affinity), so a pinned client's `RoundAction` reaches the owning enclave. Cross-enclave
  rounds are out of scope (single enclave, CID 16). `ownerModuleId` recorded; `PER_PLAYER` actions
  must come from the same pinned session.

### 4. Pluggable engine — `rng-service/.../rng/round/GameEngine.java` (interface) + `EngineRegistry`
```
String gameType();
OpenResult   open(params, Seeds);           // validate, compute public_params, precompute hidden outcome
ActionResult act(Round, action, long nowMs);// mines pick / aviator cashout; must not leak unrevealed secret
boolean      canSettle(Round, long nowMs);  // time/action based
SettleResult settle(Round);                 // serverSeed + outcome + proof
```
Register engines by `gameType`. **New game = implement + register**; protocol/attestation/registry
unchanged. First engines: `MinesEngine` (greenfield) and `DiceEngine` (retrofit of existing
commit-reveal as an auto-settle round — proves the generic model covers today's case).

`MinesEngine`: layout = `mines` distinct cells of `rows*cols` drawn from the fairness stream;
`act(pick)` → mine ⇒ `ROUND_BUST` + force settle, else safe ⇒ `is_mine=false` + running multiplier;
`settle` reveals `MinesOutcome{mine_cells}`. `DiceEngine`: `open` rolls dice from the seed, no
actions, `canSettle` after `settle_after_seconds`.

### 5. Transport — unary attested path
- `proto/src/main/proto/rng.proto`: add `rpc ServeAttested (SealedMessage) returns (SealedMessage);`
  (one request → one `AttestedResult`). Needed for `RoundOpen`/`RoundAction`/`RoundSettle`.
- `rng-service/.../rng/RngServer.java`: new vsock tag `'E'` (`TAG_SERVE_ATTESTED`); handler HPKE-opens
  the request, dispatches by `RngOp` case into `RoundRegistry`+`EngineRegistry`, seals via the
  existing **`sealAttestedFrame`** (already binds `request‖result` + fresh NSM doc). Reuse
  `sleepSeconds`, `openRequest`. Keep `ServeStreamAttested` for auto-settle rounds (dice hold,
  future aviator crash push).
- `proxy-service`: `RngProxyService.serveAttested` + `VsockRngClient.serveAttested` (relay tag `'E'`),
  routing by `module_id` as today; add an `audit` log line (op, module_id, cid, sizes, latency),
  matching the audit pattern just added.

### 6. Client — `game-service/.../game/`
- `EnclaveSession.callAttested(RngOp) -> RngResult` (unary attested) reusing `openVerifyAttested`
  (already request-bound: checks `ar.request == op sent` and `userData == SHA256(request‖result)`).
- `GameClient`: new **Mines** menu — `open` (print commit), pick loop (attested `is_mine`), cashout
  (`RoundSettled` → recompute layout from `serverSeed`, verify `SHA256(serverSeed)==commit`, audit
  every pick against the revealed layout). Config-file pattern already established
  (`noise-commit-reveal.properties`).

### Aviator (designed, built next)
`kind=COMMON`; `open` commits a crash multiplier derived from the seed (reuse
`AviatorCalculator.calculateAviatorTime0` / `calculateOdd`, `e^(0.00006·t)`); multiplier rises with
enclave-elapsed time; `act(cashout)` = unary attested call, WIN if enclave-clock multiplier < crash;
`canSettle` when elapsed ≥ crash time; settle reveals the crash. Confirms the standard spans shared
rounds + live input without protocol changes.

## Critical files
- `proto/src/main/proto/app.proto` (round envelope, enums, oneof entries) — **modify**
- `proto/src/main/proto/games.proto` (mines bodies) — **new**
- `proto/src/main/proto/rng.proto` (`ServeAttested` rpc) — **modify**
- `rng-service/.../rng/round/{Fairness,Round,RoundRegistry,GameEngine,EngineRegistry}.java` — **new**
- `rng-service/.../rng/round/engines/{MinesEngine,DiceEngine}.java` — **new**
- `rng-service/.../rng/RngServer.java` (`TAG_SERVE_ATTESTED` dispatch; reuse `sealAttestedFrame`) — **modify**
- `proxy-service/.../proxy/{RngProxyService,VsockRngClient}.java` (`serveAttested` relay + audit) — **modify**
- `game-service/.../game/{EnclaveSession,GameClient}.java` (`callAttested`, mines flow) — **modify**

## Reuse (do not reinvent)
- `com.mario.rng.reveal.Sha256Utils` / `Md5Utils` — commit hashing.
- `RngEngine` (`RandomManager` entropy, `uniform`, `sha256`) — seed + dice generation.
- `RngServer.sealAttestedFrame` — request-bound NSM-attested sealing (menu 6/7 already use it).
- `EnclaveSession.openVerifyAttested` — request-bound verify (already checks request == op sent).
- Proxy `audit` logger + `FrameMeter` pattern — audit lines.
- Platform vocabulary: `roundId`, `sessionId`, `gameType`, `RoundConfig` field shapes.

## Verification
1. **Unit / self-test (local, JDK 24, no enclave):** a `RoundSelfTest` main driving an in-process
   `RoundRegistry`+`MinesEngine`: open → assert `commit==SHA256(serverSeed)`; pick a known-mine and
   known-safe cell (derive layout with the same fairness code) → assert `is_mine` correct and
   `ROUND_BUST` on mine; settle → assert reveal recomputes the same layout and every logged pick is
   consistent. Same pattern as the existing `RevealSelfTest`. Add `FairnessTest` (determinism) and
   `RoundRegistry` TTL/cap test. Build: `JAVA_HOME=<corretto-24> mvn -DskipTests package`.
2. **End-to-end (staging, via `deploy/Makefile`):** `sync → build-eif → sign-manifest → build-jars →
   run-enclave → proxy-restart → client`. In `GameClient` run the mines flow: see the attested
   `commit`, pick cells (attested `is_mine`), cashout → reveal, client verifies
   `SHA256(serverSeed)==commit` and audits picks. Confirm `proxy` `audit` log shows
   `op=serveAttested round_id=… frames=…`. New EIF ⇒ re-run `sign-manifest` with the new PCR0.

## Notes / risks
- **Enclave becomes stateful** (was stateless). Bounded by TTL + max-rounds cap; secrets stay in RAM,
  revealed only at settle. This is the deliberate cost of interactive games.
- **COMMON-round operator auth is minimal in v1** — any attested session may open a shared round;
  players attest their own actions and the enclave is authoritative over the outcome, so a player
  cannot forge a crash/layout. Stronger operator-identity binding is a later refinement.
- **Breaking wire changes** are additive (new oneof fields, new rpc) — existing menu 1–7 keep working.