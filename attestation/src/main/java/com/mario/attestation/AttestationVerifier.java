package com.mario.attestation;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.HexFormat;
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
    private static final Logger log = LoggerFactory.getLogger(AttestationVerifier.class);
    private static final HexFormat HEX = HexFormat.of();

    private final X509Certificate root;
    // Swappable so a client can hot-adopt a newer signed manifest without a restart
    // (background poll -> updatePolicy). Read once per verify into a local snapshot.
    private volatile PcrPolicy policy;

    /** Warn this many days before the pinned root expires (rotation to G2 needed). */
    private static final long ROOT_EXPIRY_WARN_DAYS = 365;

    public AttestationVerifier(PcrPolicy policy) {
        this.policy = policy;
        this.root = NitroRoot.load();
        warnIfRootNearExpiry();
        log.info("attest policy: {}", policy.describe());
    }

    /**
     * Replace the allowed-measurement policy (e.g. after fetching a newer signed
     * manifest). Atomic: an in-flight verify uses either the old or new policy whole,
     * never a mix. Callers must only pass a policy they have already verified.
     */
    public void updatePolicy(PcrPolicy next) {
        this.policy = next;
        log.info("attest policy updated: {}", next.describe());
    }

    /**
     * The pinned Nitro root (G1) expires 2049-10-28. AWS will publish a new
     * generation (G2) before then with a new key/fingerprint; this is NOT an
     * in-place key update — it requires a reviewed swap of nitro-root-g1.pem.
     * Log loudly as the date approaches so rotation is not missed.
     */
    private void warnIfRootNearExpiry() {
        Date notAfter = root.getNotAfter();
        long daysLeft = (notAfter.getTime() - System.currentTimeMillis()) / 86_400_000L;
        if (daysLeft <= 0) {
            log.error("PINNED NITRO ROOT EXPIRED on {} — attestation will fail; rotate to new AWS root generation NOW",
                    notAfter);
        } else if (daysLeft <= ROOT_EXPIRY_WARN_DAYS) {
            log.warn("pinned Nitro root expires in {} days ({}) — plan rotation to next AWS root generation",
                    daysLeft, notAfter);
        } else {
            log.debug("pinned Nitro root valid until {} ({} days)", notAfter, daysLeft);
        }
    }

    /** Returns the verified document, or throws on any failure (fail closed). */
    public AttestationDocument verify(byte[] coseDoc, byte[] clientNonce) throws Exception {
        long t0 = System.nanoTime();
        log.debug("attest-verify START doc={} bytes, nonce={} bytes", coseDoc.length,
                clientNonce == null ? 0 : clientNonce.length);

        if (log.isTraceEnabled()) {
            log.trace("  COSE_Sign1 full doc ({}B hex, paste into cbor.nemo157.com / cbor.me):\n{}",
                    coseDoc.length, HEX.formatHex(coseDoc));
        }
        long t = System.nanoTime();
        CoseSign1 cose = CoseSign1.parse(coseDoc);
        AttestationDocument doc = AttestationDocument.parse(cose.payload);
        log.trace("step 0/parse        OK  ({} ms) module={} ts={} pcrs={} cabundle={} certs",
                ms(t), doc.moduleId, doc.timestamp, doc.pcrs.keySet(), doc.cabundle.length);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate leaf = toCert(cf, doc.certificate);

        // 1) COSE signature under the leaf cert public key (ES384, raw r||s -> DER)
        t = System.nanoTime();
        BigInteger[] rs = PlainDSAEncoding.INSTANCE.decode(P384_N, cose.signature);
        byte[] der = StandardDSAEncoding.INSTANCE.encode(P384_N, rs[0], rs[1]);
        Signature es384 = Signature.getInstance("SHA384withECDSA");
        es384.initVerify(leaf.getPublicKey());
        es384.update(cose.sigStructure());
        if (!es384.verify(der)) {
            log.error("step 1/cose-sig     FAIL ({} ms) signature invalid under leaf", ms(t));
            throw new SecurityException("COSE signature invalid");
        }
        log.trace("step 1/cose-sig     OK  ({} ms) ES384 valid under leaf subject={}",
                ms(t), leaf.getSubjectX500Principal());

        // 2) chain leaf -> cabundle -> pinned root, all currently valid
        t = System.nanoTime();
        verifyChain(cf, leaf, doc);
        log.trace("step 2/cert-chain   OK  ({} ms) leaf->{} intermediates->pinned root",
                ms(t), doc.cabundle.length);

        // 3) measurements — PCR0/PCR8 must be in the allowed set (single pin or
        //    release-signed manifest); reject all-zero PCR0 (debug enclave).
        t = System.nanoTime();
        PcrPolicy pol = policy; // one snapshot: never mix old/new across the two checks
        logPcr("PCR0", doc.pcr(0));
        assertAllowed("PCR0", doc.pcr(0), pol.allowsPcr0(doc.pcr(0)));
        logPcr("PCR8", doc.pcr(8));
        assertAllowed("PCR8", doc.pcr(8), pol.allowsPcr8(doc.pcr(8)));
        if (isAllZero(doc.pcr(0))) {
            log.error("step 3/measurements FAIL all-zero PCR0 (debug enclave)");
            throw new SecurityException("all-zero PCR0 — debug enclave rejected");
        }
        log.trace("step 3/measurements OK  ({} ms) PCR0+PCR8 in allowed set, non-zero", ms(t));

        // 4) nonce binding
        t = System.nanoTime();
        if (clientNonce == null || doc.nonce == null
                || !MessageDigest.isEqual(clientNonce, doc.nonce)) {
            log.error("step 4/nonce        FAIL ({} ms) sent={} got={}", ms(t),
                    clientNonce == null ? "null" : HEX.formatHex(clientNonce),
                    doc.nonce == null ? "null" : HEX.formatHex(doc.nonce));
            throw new SecurityException("nonce mismatch");
        }
        log.trace("step 4/nonce        OK  ({} ms) client_nonce bound value={}",
                ms(t), HEX.formatHex(doc.nonce));

        if (doc.publicKey == null || doc.userData == null) {
            throw new SecurityException("doc missing enclave keys");
        }
        log.info("attest-verify OK module={} total={} ms (enc_pub {}B sign_pub {}B)",
                doc.moduleId, ms(t0), doc.publicKey.length, doc.userData.length);
        return doc;
    }

    private static long ms(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000L;
    }

    private static void logPcr(String what, byte[] actual) {
        if (log.isTraceEnabled()) {
            log.trace("  {} actual={}", what, actual == null ? "null" : HEX.formatHex(actual));
        }
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
        log.trace("    chain[0] root        {} (== pinned, self-signed OK)",
                ca[0].getSubjectX500Principal());

        // each cert signed by the previous (toward leaf)
        for (int i = 1; i < ca.length; i++) {
            ca[i].verify(ca[i - 1].getPublicKey());
            log.trace("    chain[{}] intermediate {} (signed by prev OK)",
                    i, ca[i].getSubjectX500Principal());
        }
        leaf.verify(ca[ca.length - 1].getPublicKey());
        log.trace("    chain[leaf] {} notAfter={} (signed by issuer OK)",
                leaf.getSubjectX500Principal(), leaf.getNotAfter());
    }

    private static X509Certificate toCert(CertificateFactory cf, byte[] der) throws Exception {
        return (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(der));
    }

    private static void assertAllowed(String what, byte[] actual, boolean allowed) {
        if (actual == null || !allowed) {
            throw new SecurityException(what + " not in allowed set");
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
