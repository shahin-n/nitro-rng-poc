package com.mario.attestation;

/**
 * The set of enclave measurements a client is willing to accept. Checked by
 * {@link AttestationVerifier} on every attestation, in place of a single pinned
 * value, so the allowed set can hold several releases at once — the property that
 * makes zero-downtime rotation possible (add new PCR0, deploy, drain old, drop old).
 *
 * <p>Two implementations: {@link NitroPins} (one exact PCR0/PCR8, for dev/env pins)
 * and {@link PcrManifest} (a release-signed set, the production path).
 */
public interface PcrPolicy {

    /** Is this PCR0 (48-byte SHA-384) in the allowed set? Constant-time. */
    boolean allowsPcr0(byte[] pcr0);

    /** Is this PCR8 (48-byte SHA-384) in the allowed set? Constant-time. */
    boolean allowsPcr8(byte[] pcr8);

    /** Short human description for logs (never secret — PCRs are public). */
    String describe();
}
