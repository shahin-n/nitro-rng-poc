package com.mario.rng.reveal.impl;

import com.mario.rng.reveal.Md5Utils;
import com.mario.rng.reveal.NoiseConfig;
import com.mario.rng.reveal.ResultProcessor;

public class ResultProcessorMD5 extends ResultProcessor {

    public ResultProcessorMD5(NoiseConfig cfg) {
        super(cfg);
    }

    @Override
    protected String encrypt(String input) {
        return Md5Utils.getMd5(input);
    }

    @Override
    public String getEncryptionType() {
        return "MD5";
    }
}
