package com.mario.attestation;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * The pinned RELEASE signing public key — the trust anchor for {@link PcrManifest}.
 * It verifies the manifest that tells a client which PCRs to accept, so it is as
 * load-bearing as the Nitro root: whoever holds the matching private key (an AWS
 * KMS asymmetric ECDSA-P384 key) decides the allowed enclave images.
 *
 * <p>Bundled as classpath {@code /release-pub.pem} (SubjectPublicKeyInfo PEM),
 * replaced only by a reviewed change. A running client may instead load an
 * operator-supplied PEM via {@link #fromPem} (e.g. from an env-pointed file) — the
 * key is still pinned by whoever provisions the client, never fetched at runtime.
 */
public final class ReleaseKey {

    private static final String RESOURCE = "/release-pub.pem";

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private ReleaseKey() {
    }

    /** The bundled, pinned release public key. */
    public static PublicKey loadPinned() {
        try (InputStream in = ReleaseKey.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("missing pinned release key: " + RESOURCE);
            }
            return fromPem(in.readAllBytes());
        } catch (Exception e) {
            throw new IllegalStateException("cannot load release public key", e);
        }
    }

    /** Parse an EC public key from SubjectPublicKeyInfo PEM ("PUBLIC KEY"). */
    public static PublicKey fromPem(byte[] pem) {
        try {
            String s = new String(pem, StandardCharsets.US_ASCII)
                    .replaceAll("-----BEGIN PUBLIC KEY-----", "")
                    .replaceAll("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(s);
            KeyFactory kf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            return kf.generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalArgumentException("bad release public key PEM", e);
        }
    }
}
