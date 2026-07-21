package com.mario.rng.reveal;

/**
 * Per-request noise/commit configuration — sent by the client, applied inside the enclave.
 * Mirrors the production {@code ResultProcessorContext} (nhb-common-random / taixiu-unbalanced-core):
 * <ul>
 *   <li>{@code encryptionType} — "SHA256" or "MD5"; selects the commit hash</li>
 *   <li>{@code useEncryption} — when false the commit is the raw payload (no hashing)</li>
 *   <li>{@code noiseStringLength} — target length of the random noise string (~100)</li>
 *   <li>{@code noiseEmojiLength} — number of trailing emojis (~15)</li>
 *   <li>{@code noiseAdjustmentCoefficient} — fraction the noise length may be shortened by (~0.2)</li>
 * </ul>
 */
public record NoiseConfig(
        String encryptionType,
        boolean useEncryption,
        int noiseStringLength,
        int noiseEmojiLength,
        double noiseAdjustmentCoefficient) {

    public static final int DEFAULT_NOISE_STRING_LENGTH = 100;
    public static final int DEFAULT_EMOJI_LENGTH = 15;

    public NoiseConfig {
        if (encryptionType == null || encryptionType.isBlank()) {
            encryptionType = "SHA256";
        }
        if (useEncryption && noiseStringLength == 0) {
            noiseStringLength = DEFAULT_NOISE_STRING_LENGTH;
        }
    }
}
