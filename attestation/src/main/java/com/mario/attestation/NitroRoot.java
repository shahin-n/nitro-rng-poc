package com.mario.attestation;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * The pinned AWS Nitro Enclaves root CA (G1), bundled as a classpath resource.
 * SHA256(root.pem) = 6eb9688305e4bbca67f44b59c29a0661ae930f09b5945b5d1d9ae01125c8d6c0
 * (AWS-published fingerprint). Replace only via a reviewed cert-rotation change.
 */
public final class NitroRoot {

    private static final String RESOURCE = "/nitro-root-g1.pem";

    private NitroRoot() {
    }

    public static X509Certificate load() {
        try (InputStream in = NitroRoot.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("missing pinned root: " + RESOURCE);
            }
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(in);
        } catch (Exception e) {
            throw new IllegalStateException("cannot load Nitro root", e);
        }
    }
}
