package com.mario.crypto;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.hpke.HPKE;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * HPKE base-mode wrapper (RFC 9180), single-shot seal/open.
 *
 * <p>Suite: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305 — the
 * primitives named in the architecture (X25519 + HKDF-SHA256 + ChaCha20-Poly1305,
 * libsodium sealed-box / HPKE style).
 *
 * <p>Wire = {@code enc(32 bytes X25519) || aead_ciphertext}. The proxy treats
 * the whole thing as opaque bytes.
 */
public final class Hpke {

    /** Domain-separation label bound into every context. */
    private static final byte[] INFO = "rng-nitro/v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] NO_AAD = new byte[0];
    // base mode: no pre-shared key, no sender auth
    private static final byte[] NO_PSK = new byte[0];
    private static final byte[] NO_PSK_ID = new byte[0];

    /** X25519 public key / KEM encapsulation length. */
    public static final int ENC_LEN = 32;

    private final HPKE hpke = new HPKE(
            HPKE.mode_base,
            HPKE.kem_X25519_SHA256,
            HPKE.kdf_HKDF_SHA256,
            HPKE.aead_CHACHA20_POLY1305);

    /** Fresh X25519 keypair for the KEM (enclave enc key, or game ephemeral). */
    public AsymmetricCipherKeyPair generateKeyPair() {
        return hpke.generatePrivateKey();
    }

    /** Raw 32-byte X25519 public key (goes into the attestation doc / request). */
    public byte[] serializePublic(AsymmetricCipherKeyPair kp) {
        return hpke.serializePublicKey(kp.getPublic());
    }

    public AsymmetricKeyParameter deserializePublic(byte[] raw) {
        return hpke.deserializePublicKey(raw);
    }

    /** Seal {@code pt} to recipient public key. Returns enc||ciphertext. */
    public byte[] seal(byte[] recipientPublic, byte[] pt) throws Exception {
        AsymmetricKeyParameter pkR = hpke.deserializePublicKey(recipientPublic);
        byte[][] ctAndEnc = hpke.seal(pkR, INFO, NO_AAD, pt, NO_PSK, NO_PSK_ID, null); // {ct, enc}
        byte[] ct = ctAndEnc[0];
        byte[] enc = ctAndEnc[1];
        byte[] wire = new byte[enc.length + ct.length];
        System.arraycopy(enc, 0, wire, 0, enc.length);
        System.arraycopy(ct, 0, wire, enc.length, ct.length);
        return wire;
    }

    /** Open enc||ciphertext with the recipient's keypair. */
    public byte[] open(byte[] wire, AsymmetricCipherKeyPair recipient) throws Exception {
        byte[] enc = Arrays.copyOfRange(wire, 0, ENC_LEN);
        byte[] ct = Arrays.copyOfRange(wire, ENC_LEN, wire.length);
        return hpke.open(enc, recipient, INFO, NO_AAD, ct, NO_PSK, NO_PSK_ID, null);
    }
}
