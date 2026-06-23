package com.mario.game;

import com.mario.attestation.AttestationVerifier;
import com.mario.attestation.NitroPins;
import com.mario.rng.app.CommitReveal;
import com.mario.rng.app.CommitRevealResult;
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
import java.util.concurrent.TimeUnit;

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
                        case "3" -> doCommitReveal(session, in);
                        case "4" -> {
                            session.attest();
                            System.out.println("  attested OK, module_id=" + session.moduleId());
                        }
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
        System.out.println("  4) re-attest");
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

    private static void doCommitReveal(EnclaveSession s, Scanner in) throws Exception {
        long min = askLong(in, "min", 1);
        long max = askLong(in, "max", 100);
        int delay = (int) askLong(in, "delay_seconds", 3);
        System.out.println("  (waiting " + delay + "s for reveal...)");
        RngResult r = s.call(RngOp.newBuilder()
                .setCommitReveal(CommitReveal.newBuilder().setMin(min).setMax(max).setDelaySeconds(delay)).build());

        CommitRevealResult cr = r.getCommitReveal();
        byte[] hash = cr.getCommitHash().toByteArray();
        byte[] seed = cr.getSeed().toByteArray();
        boolean hashOk = Arrays.equals(sha256(seed), hash);
        long expect = deriveValue(sha256(seed), min, max);
        boolean valOk = expect == cr.getValue();
        System.out.printf("  commit=%s%n", HEX.formatHex(hash));
        System.out.printf("  reveal value=%d seed=%s%n", cr.getValue(), HEX.formatHex(seed));
        System.out.printf("  fairness -> hash %s, value %s  [sig verified]%n",
                hashOk ? "OK" : "MISMATCH", valOk ? "OK" : "MISMATCH");
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
