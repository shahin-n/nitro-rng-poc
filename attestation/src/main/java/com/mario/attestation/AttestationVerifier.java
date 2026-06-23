package com.mario.attestation;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Verifies a Nitro COSE_Sign1 attestation document, in the order mandated by the
 * architecture checklist:
 *
 * <ol>
 *   <li>COSE ES384 signature valid under the leaf (hypervisor) cert</li>
 *   <li>cert chain leaf -&gt; cabundle -&gt; PINNED AWS Nitro root, all in validity</li>
 *   <li>PCR0 == release, PCR8 == signer; reject all-zero PCRs (debug)</li>
 *   <li>nonce == client_nonce (constant-time)</li>
 * </ol>
 *
 * Only after all of these does the caller trust {@code public_key}/{@code user_data}.
 */
public final class AttestationVerifier {

    private static final BigInteger P384_N = curveOrder();

    private final X509Certificate root;
    private final NitroPins pins;

    public AttestationVerifier(NitroPins pins) {
        this.pins = pins;
        this.root = NitroRoot.load();
    }

    /** Returns the verified document, or throws on any failure (fail closed). */
    public AttestationDocument verify(byte[] coseDoc, byte[] clientNonce) throws Exception {
        CoseSign1 cose = CoseSign1.parse(coseDoc);
        AttestationDocument doc = AttestationDocument.parse(cose.payload);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate leaf = toCert(cf, doc.certificate);

        // 1) COSE signature under the leaf cert public key (ES384, raw r||s -> DER)
        BigInteger[] rs = PlainDSAEncoding.INSTANCE.decode(P384_N, cose.signature);
        byte[] der = StandardDSAEncoding.INSTANCE.encode(P384_N, rs[0], rs[1]);
        Signature es384 = Signature.getInstance("SHA384withECDSA");
        es384.initVerify(leaf.getPublicKey());
        es384.update(cose.sigStructure());
        if (!es384.verify(der)) {
            throw new SecurityException("COSE signature invalid");
        }

        // 2) chain leaf -> cabundle -> pinned root, all currently valid
        verifyChain(cf, leaf, doc);

        // 3) measurements
        assertEquals("PCR0", doc.pcr(0), pins.pcr0);
        assertEquals("PCR8", doc.pcr(8), pins.pcr8);
        if (isAllZero(doc.pcr(0))) {
            throw new SecurityException("all-zero PCR0 — debug enclave rejected");
        }

        // 4) nonce binding
        if (clientNonce == null || doc.nonce == null
                || !MessageDigest.isEqual(clientNonce, doc.nonce)) {
            throw new SecurityException("nonce mismatch");
        }

        if (doc.publicKey == null || doc.userData == null) {
            throw new SecurityException("doc missing enclave keys");
        }
        return doc;
    }

    private void verifyChain(CertificateFactory cf, X509Certificate leaf, AttestationDocument doc)
            throws Exception {
        Date now = new Date();
        // cabundle is ordered root -> ... -> issuing intermediate
        X509Certificate[] ca = new X509Certificate[doc.cabundle.length];
        for (int i = 0; i < ca.length; i++) {
            ca[i] = toCert(cf, doc.cabundle[i]);
            ca[i].checkValidity(now);
        }
        leaf.checkValidity(now);

        if (ca.length == 0) {
            throw new SecurityException("empty cabundle");
        }
        // cabundle[0] must be our pinned root (same bytes)
        if (!MessageDigest.isEqual(ca[0].getEncoded(), root.getEncoded())) {
            throw new SecurityException("cabundle root != pinned Nitro root");
        }
        ca[0].verify(root.getPublicKey()); // self-signed root

        // each cert signed by the previous (toward leaf)
        for (int i = 1; i < ca.length; i++) {
            ca[i].verify(ca[i - 1].getPublicKey());
        }
        leaf.verify(ca[ca.length - 1].getPublicKey());
    }

    private static X509Certificate toCert(CertificateFactory cf, byte[] der) throws Exception {
        return (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(der));
    }

    private static void assertEquals(String what, byte[] actual, byte[] expected) {
        if (actual == null || !MessageDigest.isEqual(actual, expected)) {
            throw new SecurityException(what + " mismatch");
        }
    }

    private static boolean isAllZero(byte[] b) {
        for (byte x : b) {
            if (x != 0) return false;
        }
        return true;
    }

    private static BigInteger curveOrder() {
        X9ECParameters p = SECNamedCurves.getByName("secp384r1");
        return p.getN();
    }
}
