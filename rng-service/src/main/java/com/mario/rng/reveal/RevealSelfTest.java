package com.mario.rng.reveal;

import java.security.SecureRandom;

/**
 * Standalone round-trip check for the noise commit-reveal generator.
 * Rolls 3 dice from a SecureRandom (stand-in for the enclave RNG — number generation stays outside
 * this class), wraps the result in noise, and asserts the committed hash reproduces from the payload.
 *
 * Run: mvn -pl rng-service -am -DskipTests package && \
 *      java -cp rng-service/target/rng-service.jar com.mario.rng.reveal.RevealSelfTest
 */
public final class RevealSelfTest {

    public static void main(String[] args) {
        NoiseConfig cfg = new NoiseConfig("SHA256", true, 100, 15, 0.2);
        ResultProcessor proc = ResultProcessorFactory.create(cfg);

        SecureRandom dice = new SecureRandom();
        int d1 = dice.nextInt(6) + 1, d2 = dice.nextInt(6) + 1, d3 = dice.nextInt(6) + 1;
        String resultText = d1 + "-" + d2 + "-" + d3;

        ResultProcessor.NoiseResult r = proc.handle("MBUqG2140176", resultText);

        System.out.println("result       = " + d1 + ", " + d2 + ", " + d3);
        System.out.println("payload      = " + r.payload());
        System.out.println("commit       = " + r.commit());
        System.out.println("encryption   = " + r.encryptionType());

        String recomputed = Sha256Utils.getSha256(r.payload());
        boolean ok = recomputed.equals(r.commit());
        boolean hasResult = r.payload().contains("{" + resultText + "}");

        System.out.println("recomputed   = " + recomputed);
        System.out.println("hash matches = " + ok);
        System.out.println("has {result} = " + hasResult);

        if (!ok || !hasResult) {
            System.out.println(">> SELF-TEST FAILED");
            System.exit(1);
        }
        System.out.println(">> SELF-TEST OK");
    }
}
