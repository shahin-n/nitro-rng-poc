package com.mario.game;

import com.mario.attestation.AttestationVerifier;
import com.mario.attestation.NitroPins;
import com.mario.rng.app.CommitReveal;
import com.mario.rng.app.NextBytes;
import com.mario.rng.app.NextInt;
import com.mario.rng.app.RngOp;
import com.mario.rng.app.RngResult;
import com.mario.rng.proto.RngServiceGrpc;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * game-service — interactive CLI. Pins PCR0/PCR8 from env (release manifest),
 * attests the enclave, then runs encrypted+signed RNG ops through the proxy.
 *
 * <p>Env: {@code PROXY_HOST} (localhost), {@code PROXY_PORT} (50051),
 * {@code PCR0} + {@code PCR8} (96-hex-char SHA-384 measurements, required).
 */
public final class GameClient {

    private static final HexFormat HEX = HexFormat.of();

    public static void main(String[] args) throws InterruptedException {
        String host = System.getenv().getOrDefault("PROXY_HOST", "localhost");
        int port = Integer.parseInt(System.getenv().getOrDefault("PROXY_PORT", "50051"));

        NitroPins pins = readPins();
        if (pins == null) {
            System.out.println("Set PCR0 and PCR8 (hex, from the release manifest) to attest. Aborting.");
            return;
        }
        AttestationVerifier verifier = new AttestationVerifier(pins);

        ManagedChannel channel = ManagedChannelBuilder.forAddress(host, port).usePlaintext().build();
        RngServiceGrpc.RngServiceBlockingStub stub = RngServiceGrpc.newBlockingStub(channel);
        EnclaveSession session = new EnclaveSession(stub, verifier);
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

    private static NitroPins readPins() {
        String p0 = System.getenv("PCR0");
        String p8 = System.getenv("PCR8");
        if (p0 == null || p8 == null) {
            return null;
        }
        return NitroPins.ofHex(p0.trim(), p8.trim());
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
