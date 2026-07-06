package com.mario.attestation;

import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * A single release-pinned pair of measurements — PCR0 (exact EIF image) and PCR8
 * (signer identity). This is the dev / env-var policy; production uses the
 * release-signed {@link PcrManifest} (a set) instead. Kept as a {@link PcrPolicy}
 * so both feed {@link AttestationVerifier} the same way.
 */
public final class NitroPins implements PcrPolicy {

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

    @Override
    public boolean allowsPcr0(byte[] pcr0) {
        return pcr0 != null && MessageDigest.isEqual(pcr0, this.pcr0);
    }

    @Override
    public boolean allowsPcr8(byte[] pcr8) {
        return pcr8 != null && MessageDigest.isEqual(pcr8, this.pcr8);
    }

    @Override
    public String describe() {
        HexFormat hex = HexFormat.of();
        return "NitroPins{pcr0=" + hex.formatHex(pcr0) + ", pcr8=" + hex.formatHex(pcr8) + "}";
    }
}
