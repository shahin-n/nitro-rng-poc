package com.mario.rng.reveal;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Hex SHA-256, zero-padded to 64 chars. Verbatim behaviour of the production Sha256Utils. */
public final class Sha256Utils {

    private Sha256Utils() {
    }

    public static String getSha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] digested = digest.digest(input.getBytes());
            BigInteger bigInteger = new BigInteger(1, digested);
            StringBuilder hashedText = new StringBuilder(bigInteger.toString(16));
            while (hashedText.length() < 64) {
                hashedText.insert(0, "0");
            }
            return hashedText.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
