package com.mario.rng.reveal.impl;

import com.mario.rng.reveal.NoiseConfig;
import com.mario.rng.reveal.ResultProcessor;
import com.mario.rng.reveal.Sha256Utils;

public class ResultProcessorSHA256 extends ResultProcessor {

    public ResultProcessorSHA256(NoiseConfig cfg) {
        super(cfg);
    }

    @Override
    protected String encrypt(String input) {
        return Sha256Utils.getSha256(input);
    }

    @Override
    public String getEncryptionType() {
        return "SHA256";
    }
}
