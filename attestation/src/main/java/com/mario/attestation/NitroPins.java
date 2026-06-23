package com.mario.attestation;

import java.util.HexFormat;

/**
 * Release-pinned measurements the game asserts on every attestation:
 * PCR0 (exact EIF image) and PCR8 (signer identity). From the release manifest.
 */
public final class NitroPins {

    public final byte[] pcr0;
    public final byte[] pcr8;

    public NitroPins(byte[] pcr0, byte[] pcr8) {
        if (pcr0.length != 48 || pcr8.length != 48) {
            throw new IllegalArgumentException("PCRs must be 48 bytes (SHA-384)");
        }
        this.pcr0 = pcr0;
        this.pcr8 = pcr8;
    }

    public static NitroPins ofHex(String pcr0Hex, String pcr8Hex) {
        HexFormat hex = HexFormat.of();
        return new NitroPins(hex.parseHex(pcr0Hex), hex.parseHex(pcr8Hex));
    }
}
