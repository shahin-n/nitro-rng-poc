package com.mario.game;

import com.mario.attestation.AttestationVerifier;
import com.mario.attestation.NitroPins;
import com.mario.attestation.PcrPolicy;
import com.mario.attestation.ReleaseKey;
import com.google.protobuf.ByteString;
import com.mario.crypto.Fairness;
import com.mario.crypto.MinesFair;
import com.mario.rng.app.ActionResult;
import com.mario.rng.app.CommitReveal;
import com.mario.rng.app.MinesOutcome;
import com.mario.rng.app.MinesParams;
import com.mario.rng.app.MinesPick;
import com.mario.rng.app.MinesPickResult;
import com.mario.rng.app.NextBytes;
import com.mario.rng.app.NextInt;
import com.mario.rng.app.NoiseCommitReveal;
import com.mario.rng.app.RngOp;
import com.mario.rng.app.RngResult;
import com.mario.rng.app.RoundAction;
import com.mario.rng.app.RoundKind;
import com.mario.rng.app.RoundOpen;
import com.mario.rng.app.RoundOpened;
import com.mario.rng.app.RoundSettle;
import com.mario.rng.app.RoundSettled;
import com.mario.rng.proto.ManifestRequest;
import com.mario.rng.proto.RngServiceGrpc;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * game-service — interactive CLI. Learns the allowed enclave measurements from
 * the release-signed PCR manifest (fetched via the proxy, verified under a pinned
 * release key), attests the enclave, then runs encrypted+signed RNG ops.
 *
 * <p>Env: {@code PROXY_HOST} (localhost), {@code PROXY_PORT} (50051).
 * <p>Manifest trust: {@code RELEASE_PUBKEY_PATH} (optional PEM override; default is
 * the pinned {@code release-pub.pem} bundled in the attestation module).
 * <p>Dev override: set {@code PCR0} + {@code PCR8} (96-hex SHA-384) to pin a single
 * measurement from env and skip the manifest entirely.
 */
public final class GameClient {

    private static final HexFormat HEX = HexFormat.of();
    private static final String SERVICE = "rng-service";

    public static void main(String[] args) throws Exception {
        String host = System.getenv().getOrDefault("PROXY_HOST", "localhost");
        int port = Integer.parseInt(System.getenv().getOrDefault("PROXY_PORT", "50051"));

        ManagedChannel channel = ManagedChannelBuilder.forAddress(host, port).usePlaintext().build();
        RngServiceGrpc.RngServiceBlockingStub stub = RngServiceGrpc.newBlockingStub(channel);

        PcrPolicy policy = loadPolicy(stub);
        AttestationVerifier verifier = new AttestationVerifier(policy);
        EnclaveSession session = new EnclaveSession(stub, verifier);

        // When trusting a signed manifest, poll for a newer one so a running client
        // adopts a rotation (new allowed PCR set) without a restart.
        if (policy instanceof com.mario.attestation.PcrManifest pm) {
            startManifestPoller(stub, verifier, pm.version());
        }
        Scanner in = new Scanner(System.in);

        System.out.printf("game-service CLI -> proxy %s:%d%n", host, port);
        try {
            loop:
            while (true) {
                printMenu(session);
                String choice = in.nextLine().trim();
                try {
                    switch (choice) {
                        case "1" -> doInt(session, in);
                        case "2" -> doBytes(session, in);
                        case "3" -> doCommitReveal(session, in, false);
                        case "6" -> doCommitReveal(session, in, true);
                        case "7" -> doNoiseCommitReveal(session);
                        case "8" -> doMines(session, in);
                        case "4" -> {
                            session.attest();
                            System.out.println("  attested OK, module_id=" + session.moduleId());
                        }
                        case "5" -> doBench(session, in);
                        case "0", "q", "quit", "exit" -> {
                            break loop;
                        }
                        default -> System.out.println("unknown choice: " + choice);
                    }
                } catch (Exception e) {
                    System.out.println("  ERROR: " + e.getClass().getSimpleName() + ": " + e.getMessage());
                }
            }
        } finally {
            System.out.println("bye");
            channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }
    }

    private static void printMenu(EnclaveSession s) {
        System.out.println();
        System.out.println("=== RNG menu === (attested: " + s.attested() + ")");
        System.out.println("  1) NextInt       uniform int in [min,max]");
        System.out.println("  2) NextBytes     N random bytes");
        System.out.println("  3) CommitReveal  hash + reveal after delay (provably fair)");
        System.out.println("  6) CommitReveal  attested — every frame carries a fresh NSM doc");
        System.out.println("  7) CommitReveal  attested + NOISE — sha256-padded payload (config-driven)");
        System.out.println("  8) Mines         attested provably-fair round (open, pick, cashout)");
        System.out.println("  4) re-attest");
        System.out.println("  5) Benchmark     N warm NextInt calls, latency percentiles + QPS");
        System.out.println("  0) quit");
        System.out.print("> ");
    }

    private static void doInt(EnclaveSession s, Scanner in) throws Exception {
        long min = askLong(in, "min", 1);
        long max = askLong(in, "max", 6);
        RngResult r = s.call(RngOp.newBuilder()
                .setNextInt(NextInt.newBuilder().setMin(min).setMax(max)).build());
        System.out.printf("  -> value=%d  [verified]%n", r.getIntResult().getValue());
    }

    private static void doBytes(EnclaveSession s, Scanner in) throws Exception {
        int count = (int) askLong(in, "count", 16);
        RngResult r = s.call(RngOp.newBuilder()
                .setNextBytes(NextBytes.newBuilder().setCount(count)).build());
        byte[] data = r.getBytesResult().getData().toByteArray();
        System.out.printf("  -> %d bytes: %s  [verified]%n", data.length, HEX.formatHex(data));
    }

    private static void doCommitReveal(EnclaveSession s, Scanner in, boolean attested) throws Exception {
        long min = askLong(in, "min", 1);
        long max = askLong(in, "max", 100);
        int delay = (int) askLong(in, "delay_seconds", 3);

        // One held stream: the enclave pushes the commit hash, holds `delay`, then pushes the reveal.
        // The hash lands before the seed exists to us, so the enclave is bound. When `attested`, every
        // frame is verified against its own fresh NSM doc rather than the once-attested ECDSA key.
        String tag = attested ? "attested" : "sig verified";
        byte[][] hash = new byte[1][];   // captured from the commit frame, checked against the reveal
        System.out.printf("  (commit-reveal %sstream; enclave will hold ~%ds before reveal)%n",
                attested ? "attested " : "", delay);
        RngOp op = RngOp.newBuilder()
                .setCommitReveal(CommitReveal.newBuilder().setMin(min).setMax(max).setDelaySeconds(delay)).build();
        Consumer<RngResult> onFrame = r -> {
            switch (r.getResultCase()) {
                case COMMIT -> {
                    hash[0] = r.getCommit().getCommitHash().toByteArray();
                    System.out.printf("  commit=%s  [%s]%n", HEX.formatHex(hash[0]), tag);
                }
                case REVEAL -> {
                    byte[] seed = r.getReveal().getSeed().toByteArray();
                    boolean hashOk = hash[0] != null && Arrays.equals(sha256(seed), hash[0]);
                    boolean valOk = deriveValue(sha256(seed), min, max) == r.getReveal().getValue();
                    System.out.printf("  reveal value=%d seed=%s%n",
                            r.getReveal().getValue(), HEX.formatHex(seed));
                    System.out.printf("  fairness -> hash %s, value %s  [%s]%n",
                            hashOk ? "OK" : "MISMATCH", valOk ? "OK" : "MISMATCH", tag);
                }
                default -> System.out.println("  unexpected frame: " + r.getResultCase());
            }
        };
        if (attested) {
            s.callStreamAttested(op, onFrame);
        } else {
            s.callStream(op, onFrame);
        }
    }

    /**
     * Attested NOISE commit-reveal. The five noise params come from a config file (client-owned),
     * sent to the enclave in the request. The enclave rolls the dice, wraps them in a noise+emoji
     * payload, commits hash(payload) first, then reveals the payload after the delay. We re-hash the
     * revealed payload (same encryptionType) and confirm it equals the commit, then extract {d1-d2-..}.
     */
    private static void doNoiseCommitReveal(EnclaveSession s) throws Exception {
        Properties cfg = loadNoiseConfig();
        String enc = cfg.getProperty("encryptionType", "SHA256");
        boolean useEnc = Boolean.parseBoolean(cfg.getProperty("useEncryption", "true"));
        int noiseLen = Integer.parseInt(cfg.getProperty("noiseStringLength", "100"));
        int emojiLen = Integer.parseInt(cfg.getProperty("noiseEmojiLength", "15"));
        double adjust = Double.parseDouble(cfg.getProperty("noiseAdjustmentLength", "0.2"));
        int diceCount = Integer.parseInt(cfg.getProperty("diceCount", "3"));
        int diceFaces = Integer.parseInt(cfg.getProperty("diceFaces", "6"));
        int delay = Integer.parseInt(cfg.getProperty("delaySeconds", "3"));
        String sessionId = cfg.getProperty("sessionId", "");

        System.out.printf("  (noise commit-reveal: %s useEncryption=%s noise=%d emoji=%d adjust=%.2f dice=%dx d%d, hold ~%ds)%n",
                enc, useEnc, noiseLen, emojiLen, adjust, diceCount, diceFaces, delay);

        RngOp op = RngOp.newBuilder()
                .setNoiseCommitReveal(NoiseCommitReveal.newBuilder()
                        .setDiceCount(diceCount).setDiceFaces(diceFaces).setDelaySeconds(delay)
                        .setSessionId(sessionId)
                        .setEncryptionType(enc).setUseEncryption(useEnc)
                        .setNoiseStringLength(noiseLen).setNoiseEmojiLength(emojiLen)
                        .setNoiseAdjustment(adjust))
                .build();

        String[] commit = new String[1];
        String[] encType = {enc};
        Consumer<RngResult> onFrame = r -> {
            switch (r.getResultCase()) {
                case NOISE_COMMIT -> {
                    commit[0] = r.getNoiseCommit().getCommit();
                    encType[0] = r.getNoiseCommit().getEncryptionType();
                    System.out.printf("  commit=%s  [%s, attested]%n", commit[0], encType[0]);
                }
                case NOISE_REVEAL -> {
                    String payload = r.getNoiseReveal().getPayload();
                    String resultText = r.getNoiseReveal().getResultText();
                    boolean useHash = commit[0] != null && !commit[0].equals(payload);
                    String recomputed = useHash ? hashHex(encType[0], payload) : payload;
                    boolean hashOk = commit[0] != null && recomputed.equalsIgnoreCase(commit[0]);
                    String extracted = extractResult(payload);
                    boolean resultOk = extracted != null && extracted.equals(resultText);
                    System.out.printf("  reveal payload=%s%n", payload);
                    System.out.printf("  result={%s}  (extracted {%s})%n", resultText, extracted);
                    System.out.printf("  fairness -> commit %s, result %s  [attested]%n",
                            hashOk ? "OK" : "MISMATCH", resultOk ? "OK" : "MISMATCH");
                }
                default -> System.out.println("  unexpected frame: " + r.getResultCase());
            }
        };
        s.callStreamAttested(op, onFrame);
    }

    /** Load noise params: {@code NOISE_CONFIG_PATH} file if set, else the bundled resource, else defaults. */
    private static Properties loadNoiseConfig() {
        Properties p = new Properties();
        String path = System.getenv("NOISE_CONFIG_PATH");
        try {
            if (path != null && !path.isBlank()) {
                try (InputStream is = Files.newInputStream(Path.of(path))) {
                    p.load(is);
                    return p;
                }
            }
            try (InputStream is = GameClient.class.getResourceAsStream("/noise-commit-reveal.properties")) {
                if (is != null) {
                    p.load(is);
                }
            }
        } catch (Exception e) {
            System.out.println("  noise config load failed, using defaults: " + e.getMessage());
        }
        return p;
    }

    /** Client-side commit hash — must match the enclave's Sha256Utils/Md5Utils hex (zero-padded). */
    private static String hashHex(String encryptionType, String input) {
        String algo = "MD5".equalsIgnoreCase(encryptionType) ? "MD5" : "SHA-256";
        int width = "MD5".equalsIgnoreCase(encryptionType) ? 32 : 64;
        try {
            byte[] d = MessageDigest.getInstance(algo).digest(input.getBytes());
            StringBuilder hex = new StringBuilder(new BigInteger(1, d).toString(16));
            while (hex.length() < width) {
                hex.insert(0, "0");
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(algo + " unavailable", e);
        }
    }

    /** Extract the dice text embedded as {d1-d2-..} in the noise payload. */
    private static String extractResult(String payload) {
        int a = payload.indexOf('{');
        int b = a < 0 ? -1 : payload.indexOf('}', a);
        return (a >= 0 && b > a) ? payload.substring(a + 1, b) : null;
    }

    /**
     * Mines — an Attested Provably-Fair Round. Open (attested commit), pick cells (each an attested
     * is_mine), cash out (reveal serverSeed + layout). Then AUDIT: verify SHA256(serverSeed)==commit,
     * recompute the layout from the disclosed seed with the same shared fairness code, and confirm
     * every pick the enclave reported matches the recomputed layout.
     */
    private static void doMines(EnclaveSession s, Scanner in) throws Exception {
        int rows = (int) askLong(in, "rows", 5);
        int cols = (int) askLong(in, "cols", 5);
        int mines = (int) askLong(in, "mines", 3);
        byte[] clientSeed = new byte[16];
        new SecureRandom().nextBytes(clientSeed);

        RngOp openOp = RngOp.newBuilder().setRoundOpen(RoundOpen.newBuilder()
                .setGameType("mines").setKind(RoundKind.PER_PLAYER)
                .setClientSeed(ByteString.copyFrom(clientSeed))
                .setParams(MinesParams.newBuilder().setRows(rows).setCols(cols).setMines(mines).build().toByteString())
                .setSessionId("")).build();
        RoundOpened opened = s.callAttested(openOp).getRoundOpened();
        String roundId = opened.getRoundId();
        String commit = opened.getCommit();
        System.out.printf("  opened round=%s%n  commit=%s  [attested]%n", roundId, commit);
        System.out.printf("  grid %dx%d, %d mines. pick cells 0..%d; -1 = cashout%n",
                rows, cols, mines, rows * cols - 1);

        Map<Integer, Boolean> picks = new LinkedHashMap<>();
        int seq = 0;
        while (true) {
            int cell = (int) askLong(in, "cell (-1 cashout)", -1);
            if (cell < 0) {
                break;
            }
            RngOp actOp = RngOp.newBuilder().setRoundAction(RoundAction.newBuilder()
                    .setRoundId(roundId).setSeq(++seq)
                    .setAction(MinesPick.newBuilder().setCell(cell).build().toByteString())).build();
            ActionResult ar = s.callAttested(actOp).getActionResult();
            MinesPickResult pr = MinesPickResult.parseFrom(ar.getResult());
            picks.put(cell, pr.getIsMine());
            System.out.printf("  cell %d -> %s  safe=%d mult=%.2f  status=%s  [attested]%n",
                    cell, pr.getIsMine() ? "MINE" : "safe", pr.getSafeRevealed(), pr.getMultiplier(), ar.getStatus());
            if (pr.getIsMine()) {
                System.out.println("  BUST");
                break;
            }
            if (ar.getStatus() == com.mario.rng.app.RoundStatus.ROUND_WIN) {
                System.out.println("  cleared all safe cells!");
                break;
            }
        }

        RngOp settleOp = RngOp.newBuilder().setRoundSettle(RoundSettle.newBuilder().setRoundId(roundId)).build();
        RoundSettled settled = s.callAttested(settleOp).getRoundSettled();
        byte[] serverSeed = settled.getServerSeed().toByteArray();
        MinesOutcome outcome = MinesOutcome.parseFrom(settled.getOutcome());

        boolean commitOk = Fairness.commit(serverSeed).equalsIgnoreCase(commit);
        int[] recomputed = MinesFair.layout(serverSeed, clientSeed, rows, cols, mines);
        Set<Integer> revealed = new HashSet<>(outcome.getMineCellsList());
        Set<Integer> recomputedSet = new HashSet<>();
        for (int c : recomputed) {
            recomputedSet.add(c);
        }
        boolean layoutOk = revealed.equals(recomputedSet);
        boolean picksOk = true;
        for (Map.Entry<Integer, Boolean> e : picks.entrySet()) {
            if (recomputedSet.contains(e.getKey()) != e.getValue()) {
                picksOk = false;
            }
        }

        System.out.printf("  settled status=%s  [attested]%n", settled.getStatus());
        System.out.printf("  server_seed=%s%n", HEX.formatHex(serverSeed));
        System.out.printf("  mines revealed=%s%n", new java.util.TreeSet<>(revealed));
        System.out.printf("  fairness -> commit %s, layout %s, picks %s%n",
                commitOk ? "OK" : "MISMATCH", layoutOk ? "OK" : "MISMATCH", picksOk ? "OK" : "MISMATCH");
    }

    private static void doBench(EnclaveSession s, Scanner in) throws Exception {
        int n = (int) askLong(in, "calls", 1000);
        int threads = (int) askLong(in, "threads", 32);
        int warmup = (int) askLong(in, "warmup", Math.min(200, n));
        RngOp op = RngOp.newBuilder()
                .setNextInt(NextInt.newBuilder().setMin(1).setMax(6)).build();

        // Attest once up front so the measured window is pure serve (no attest, no cold start).
        if (!s.attested()) {
            s.attest();
        }
        System.out.printf("  warming up %d calls (%d threads)...%n", warmup, threads);
        runConcurrent(s, op, warmup, threads, null);

        System.out.printf("  measuring %d calls across %d threads...%n", n, threads);
        long[] us = new long[n];      // per-call latency, microseconds (each slot written by one thread)
        long wall0 = System.nanoTime();
        int errors = runConcurrent(s, op, n, threads, us);
        long wallMs = (System.nanoTime() - wall0) / 1_000_000L;

        Arrays.sort(us);
        double qps = n * 1000.0 / Math.max(1, wallMs);
        System.out.println();
        System.out.printf("  === bench: %d calls in %d ms  =>  %.0f calls/s (%d threads) %s ===%n",
                n, wallMs, qps, threads, errors == 0 ? "" : "[" + errors + " ERRORS]");
        System.out.printf("  latency us: min=%d  p50=%d  p90=%d  p99=%d  max=%d  mean=%d%n",
                us[0], pct(us, 50), pct(us, 90), pct(us, 99), us[n - 1], mean(us));
        System.out.printf("  latency ms: p50=%.2f  p99=%.2f%n", pct(us, 50) / 1000.0, pct(us, 99) / 1000.0);
    }

    /**
     * Drive {@code count} concurrent calls across {@code threads} workers. Each worker pulls the
     * next index off a shared counter (work-stealing) until drained, so threads stay busy even with
     * an uneven latency tail. When {@code us != null}, each call's latency lands in its own slot
     * (distinct indices → no contention). Returns the number of failed calls.
     */
    private static int runConcurrent(EnclaveSession s, RngOp op, int count, int threads, long[] us)
            throws InterruptedException {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        AtomicInteger next = new AtomicInteger();
        AtomicInteger errors = new AtomicInteger();
        ConcurrentHashMap<String, AtomicInteger> errKinds = new ConcurrentHashMap<>();
        for (int t = 0; t < threads; t++) {
            pool.submit(() -> {
                int i;
                while ((i = next.getAndIncrement()) < count) {
                    long t0 = System.nanoTime();
                    try {
                        s.call(op);
                    } catch (Exception e) {
                        errors.incrementAndGet();
                        String kind = e.getClass().getSimpleName() + ": " + e.getMessage();
                        errKinds.computeIfAbsent(kind, k -> new AtomicInteger()).incrementAndGet();
                    }
                    if (us != null) us[i] = (System.nanoTime() - t0) / 1_000L;
                }
            });
        }
        pool.shutdown();
        pool.awaitTermination(10, TimeUnit.MINUTES);
        if (!errKinds.isEmpty()) {
            System.out.println("  error breakdown:");
            errKinds.entrySet().stream()
                    .sorted((a, b) -> b.getValue().get() - a.getValue().get())
                    .limit(8)
                    .forEach(e -> System.out.printf("    %6d  %s%n", e.getValue().get(), e.getKey()));
        }
        return errors.get();
    }

    private static long pct(long[] sorted, int p) {
        int idx = (int) Math.ceil(p / 100.0 * sorted.length) - 1;
        return sorted[Math.max(0, Math.min(sorted.length - 1, idx))];
    }

    private static long mean(long[] a) {
        long sum = 0;
        for (long x : a) sum += x;
        return sum / a.length;
    }

    // ---- helpers -------------------------------------------------------------

    /**
     * The allowed-measurement policy. Production: fetch the release-signed manifest
     * via the proxy and verify it under the pinned release key. Dev: if {@code PCR0}
     * and {@code PCR8} are set, pin those directly and skip the manifest.
     */
    private static PcrPolicy loadPolicy(RngServiceGrpc.RngServiceBlockingStub stub) throws Exception {
        String p0 = System.getenv("PCR0");
        String p8 = System.getenv("PCR8");
        if (p0 != null && p8 != null) {
            System.out.println("  [dev] pinning PCR0/PCR8 from env, skipping signed manifest");
            return NitroPins.ofHex(p0.trim(), p8.trim());
        }

        com.mario.attestation.PcrManifest manifest = fetchManifest(stub, loadReleaseKey());
        System.out.printf("  allowed PCRs from signed manifest v%d (expires %s)%n",
                manifest.version(), manifest.notAfter());
        return manifest;
    }

    /** Fetch + verify the signed manifest under the pinned release key. */
    private static com.mario.attestation.PcrManifest fetchManifest(
            RngServiceGrpc.RngServiceBlockingStub stub, PublicKey releaseKey) throws Exception {
        com.mario.rng.proto.PcrManifest resp = stub.getPcrManifest(ManifestRequest.newBuilder().build());
        return com.mario.attestation.PcrManifest.verify(
                resp.getManifestJson().toByteArray(),
                resp.getSignature().toByteArray(),
                releaseKey, SERVICE);
    }

    /**
     * Background poll: every {@code MANIFEST_POLL_SECONDS} (default 30, 0 disables),
     * re-fetch + verify the manifest and adopt it if its version is higher. Version is
     * monotonic, so a stale or replayed older manifest is ignored. Verification failures
     * are transient-tolerated — the current policy stays in force.
     */
    private static void startManifestPoller(RngServiceGrpc.RngServiceBlockingStub stub,
                                            AttestationVerifier verifier, int initialVersion) {
        int period = Integer.parseInt(System.getenv().getOrDefault("MANIFEST_POLL_SECONDS", "30"));
        if (period <= 0) {
            return;
        }
        PublicKey releaseKey;
        try {
            releaseKey = loadReleaseKey();
        } catch (Exception e) {
            System.out.println("  manifest poll disabled: " + e.getMessage());
            return;
        }
        AtomicInteger ver = new AtomicInteger(initialVersion);
        Thread t = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(period * 1000L);
                    com.mario.attestation.PcrManifest m = fetchManifest(stub, releaseKey);
                    if (m.version() > ver.get()) {
                        verifier.updatePolicy(m);
                        ver.set(m.version());
                        System.out.printf("  [manifest] adopted v%d (expires %s)%n", m.version(), m.notAfter());
                    }
                } catch (InterruptedException ie) {
                    return;
                } catch (Exception e) {
                    // transient (proxy blip, mid-rotation file swap) — keep the current policy
                }
            }
        }, "manifest-poller");
        t.setDaemon(true);
        t.start();
    }

    /** Pinned release public key: env-pointed PEM override, else the bundled default. */
    private static PublicKey loadReleaseKey() throws Exception {
        String path = System.getenv("RELEASE_PUBKEY_PATH");
        if (path != null && !path.isBlank()) {
            return ReleaseKey.fromPem(Files.readAllBytes(Path.of(path)));
        }
        return ReleaseKey.loadPinned();
    }

    private static long askLong(Scanner in, String label, long def) {
        System.out.printf("  %s [%d]: ", label, def);
        String line = in.nextLine().trim();
        if (line.isEmpty()) return def;
        try {
            return Long.parseLong(line);
        } catch (NumberFormatException e) {
            System.out.println("  not a number, using " + def);
            return def;
        }
    }

    static long deriveValue(byte[] hash, long min, long max) {
        if (max < min) {
            long t = min;
            min = max;
            max = t;
        }
        long span = max - min + 1;
        long bits = 0;
        for (int i = 0; i < 8; i++) {
            bits = (bits << 8) | (hash[i] & 0xFFL);
        }
        return span <= 0 ? bits : min + Long.remainderUnsigned(bits, span);
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private GameClient() {
    }
}
