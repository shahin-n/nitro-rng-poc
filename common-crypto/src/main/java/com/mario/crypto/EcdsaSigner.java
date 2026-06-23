package com.mario.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * ECDSA P-384 over SHA-384 — the enclave's pre-signature signing key.
 *
 * <p>Public keys are exchanged as X.509 SubjectPublicKeyInfo DER (the bytes the
 * enclave puts in the attestation document's {@code user_data}).
 */
public final class EcdsaSigner {

    private static final String CURVE = "secp384r1";
    private static final String ALG = "SHA384withECDSA";
    private static final String KEY_ALG = "EC";

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private EcdsaSigner() {
    }

    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance(KEY_ALG, BouncyCastleProvider.PROVIDER_NAME);
            g.initialize(new ECGenParameterSpec(CURVE), new SecureRandom());
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("EC keygen failed", e);
        }
    }

    /** X.509 SubjectPublicKeyInfo DER of the public key. */
    public static byte[] encodePublic(PublicKey key) {
        return key.getEncoded();
    }

    public static PublicKey decodePublic(byte[] der) {
        try {
            KeyFactory kf = KeyFactory.getInstance(KEY_ALG, BouncyCastleProvider.PROVIDER_NAME);
            return kf.generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalArgumentException("bad EC public key", e);
        }
    }

    public static byte[] sign(PrivateKey key, byte[] data) {
        try {
            Signature s = Signature.getInstance(ALG, BouncyCastleProvider.PROVIDER_NAME);
            s.initSign(key);
            s.update(data);
            return s.sign();
        } catch (Exception e) {
            throw new IllegalStateException("sign failed", e);
        }
    }

    public static boolean verify(PublicKey key, byte[] data, byte[] signature) {
        try {
            Signature s = Signature.getInstance(ALG, BouncyCastleProvider.PROVIDER_NAME);
            s.initVerify(key);
            s.update(data);
            return s.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }
}
