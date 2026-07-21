package com.mario.rng.reveal;

import com.mario.rng.reveal.impl.ResultProcessorMD5;
import com.mario.rng.reveal.impl.ResultProcessorSHA256;

/** Selects the noise/commit processor by {@link NoiseConfig#encryptionType()} ("SHA256" | "MD5"). */
public final class ResultProcessorFactory {

    private ResultProcessorFactory() {
    }

    public static ResultProcessor create(NoiseConfig cfg) {
        String type = cfg.encryptionType();
        return switch (type == null ? "" : type.toUpperCase()) {
            case "SHA256" -> new ResultProcessorSHA256(cfg);
            case "MD5" -> new ResultProcessorMD5(cfg);
            default -> throw new IllegalArgumentException("Unsupported encryption type: " + type);
        };
    }
}
