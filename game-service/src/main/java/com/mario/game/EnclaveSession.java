package com.mario.game;

import com.google.protobuf.ByteString;
import com.mario.attestation.AttestationDocument;
import com.mario.attestation.AttestationVerifier;
import com.mario.crypto.EcdsaSigner;
import com.mario.crypto.Hpke;
import com.mario.rng.app.AttestedResult;
import com.mario.rng.app.RngOp;
import com.mario.rng.app.RngResult;
import com.mario.rng.app.SealedRequest;
import com.mario.rng.app.SignedResult;
import com.mario.rng.proto.AttestReply;
import com.mario.rng.proto.AttestRequest;
import com.mario.rng.proto.RngServiceGrpc;
import com.mario.rng.proto.SealedMessage;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Iterator;
import java.util.function.Consumer;

/**
 * Client-side enclave session: attest once (verify + pin), then make confidential,
 * authenticated calls. Mirrors flow steps B (attest) and C (serve).
 */
final class EnclaveSession {

    private static final Logger log = LoggerFactory.getLogger(EnclaveSession.class);

    private final RngServiceGrpc.RngServiceBlockingStub stub;
    private final AttestationVerifier verifier;
    private final Hpke hpke = new Hpke();
    private final SecureRandom random = new SecureRandom();

    // Re-attest somewhere in [MIN, MAX] before the leaf expires. The margin is randomized per
    // attestation so a fleet of game-service instances that booted together does NOT re-attest in
    // lockstep — spreading the renewals avoids a periodic thundering herd on the enclave.
    private static final long RENEW_MARGIN_MIN_MS = 5 * 60_000L;
    private static final long RENEW_MARGIN_MAX_MS = 10 * 60_000L;

    /** Serializes attestation so concurrent callers don't stampede the enclave with parallel re-attests. */
    private final Object attestLock = new Object();

    /**
     * All pinned material as one immutable unit, published atomically via this single
     * volatile reference. A caller reads it once and uses that consistent snapshot for the
     * whole request, so a concurrent re-attest can never mix a new encPub with a stale moduleId.
     */
    private volatile Pinned pinned;

    private record Pinned(String moduleId, byte[] encPub, PublicKey signPub,
                          long leafNotAfterMs, long renewAtMs) {
        boolean fresh() {
            return System.currentTimeMillis() < renewAtMs;
        }
    }

    EnclaveSession(RngServiceGrpc.RngServiceBlockingStub stub, AttestationVerifier verifier) {
        this.stub = stub;
        this.verifier = verifier;
    }

    boolean attested() {
        Pinned p = pinned;
        return p != null && p.fresh();
    }

    String moduleId() {
        Pinned p = pinned;
        return p == null ? null : p.moduleId();
    }

    /** Step B — force a fresh attestation (e.g. the menu "re-attest"); publishes a new snapshot. */
    void attest() throws Exception {
        synchronized (attestLock) {
            doAttest();
        }
    }

    /** Return a fresh pinned snapshot, re-attesting under the lock only if needed (double-checked). */
    private Pinned ensureFresh() throws Exception {
        Pinned p = pinned;
        if (p != null && p.fresh()) {
            return p;
        }
        synchronized (attestLock) {
            p = pinned;                       // another thread may have renewed while we waited
            if (p != null && p.fresh()) {
                return p;
            }
            return doAttest();
        }
    }

    /** Must hold {@link #attestLock}. Fetches + verifies the doc and publishes a new snapshot. */
    private Pinned doAttest() throws Exception {
        byte[] nonce = new byte[32];
        random.nextBytes(nonce);

        log.info("attest: sending AttestRequest (gRPC -> proxy -> enclave vsock)...");
        long t = System.nanoTime();
        AttestReply reply = stub.attest(AttestRequest.newBuilder()
                .setClientNonce(ByteString.copyFrom(nonce))
                .build());
        long rpcMs = (System.nanoTime() - t) / 1_000_000L;
        log.info("attest: AttestReply received in {} ms ({} doc bytes); verifying...",
                rpcMs, reply.getAttestationDoc().size());

        AttestationDocument doc = verifier.verify(reply.getAttestationDoc().toByteArray(), nonce);
        long leafNotAfterMs = leafNotAfter(doc);
        long margin = RENEW_MARGIN_MIN_MS
                + (long) (random.nextDouble() * (RENEW_MARGIN_MAX_MS - RENEW_MARGIN_MIN_MS));
        Pinned p = new Pinned(doc.moduleId, doc.publicKey,
                EcdsaSigner.decodePublic(doc.userData), leafNotAfterMs, leafNotAfterMs - margin);
        this.pinned = p; // single atomic publish
        log.info("attest: DONE, session pinned to module={}, leaf valid until {} (auto re-attest at {}, ~{} min before)",
                p.moduleId(), new Date(p.leafNotAfterMs()), new Date(p.renewAtMs()), margin / 60_000L);
        return p;
    }

    /** Step C — HPKE-seal the op, serve, then verify signature + req_nonce. */
    RngResult call(RngOp op) throws Exception {
        Pinned p = ensureFresh();
        long c0 = System.nanoTime();

        long t = System.nanoTime();
        AsymmetricCipherKeyPair gameKp = hpke.generateKeyPair();
        byte[] gamePub = hpke.serializePublic(gameKp);
        byte[] reqNonce = new byte[16];
        random.nextBytes(reqNonce);

        byte[] sealedReq = SealedRequest.newBuilder()
                .setOp(op.toByteString())
                .setGamePub(ByteString.copyFrom(gamePub))
                .setReqNonce(ByteString.copyFrom(reqNonce))
                .build()
                .toByteArray();

        byte[] ciphertext = hpke.seal(p.encPub(), sealedReq);
        log.debug("serve step 1/seal     OK ({} ms) plain={}B cipher={}B module={}",
                ms(t), sealedReq.length, ciphertext.length, p.moduleId());

        t = System.nanoTime();
        SealedMessage reply = stub.serve(SealedMessage.newBuilder()
                .setCiphertext(ByteString.copyFrom(ciphertext))
                .setModuleId(p.moduleId()) // affinity: route to the enclave that attested this session
                .build());
        log.debug("serve step 2/rpc      OK ({} ms) reply cipher={}B",
                ms(t), reply.getCiphertext().size());

        RngResult result = openVerify(reply, gameKp, reqNonce, p);
        log.info("serve DONE total={} ms", ms(c0));
        return result;
    }

    /**
     * Step C (streaming) — HPKE-seal the op once, then consume the enclave-pushed stream. Each
     * frame is independently opened, replay-checked and signature-verified, then handed to
     * {@code onResult}. Used by commit-reveal: frame 1 is the commit hash, frame 2 (after the
     * enclave's hold) is the reveal. All frames share this request's gameKp + req_nonce.
     */
    void callStream(RngOp op, Consumer<RngResult> onResult) throws Exception {
        Pinned p = ensureFresh();
        AsymmetricCipherKeyPair gameKp = hpke.generateKeyPair();
        byte[] gamePub = hpke.serializePublic(gameKp);
        byte[] reqNonce = new byte[16];
        random.nextBytes(reqNonce);

        byte[] sealedReq = SealedRequest.newBuilder()
                .setOp(op.toByteString())
                .setGamePub(ByteString.copyFrom(gamePub))
                .setReqNonce(ByteString.copyFrom(reqNonce))
                .build()
                .toByteArray();
        byte[] ciphertext = hpke.seal(p.encPub(), sealedReq);

        Iterator<SealedMessage> frames = stub.serveStream(SealedMessage.newBuilder()
                .setCiphertext(ByteString.copyFrom(ciphertext))
                .setModuleId(p.moduleId())
                .build());
        int n = 0;
        while (frames.hasNext()) {
            RngResult result = openVerify(frames.next(), gameKp, reqNonce, p);
            log.debug("stream frame {} OK module={}", ++n, p.moduleId());
            onResult.accept(result);
        }
    }

    /**
     * Step C (streaming, per-response attested) — like {@link #callStream}, but every pushed frame
     * carries its OWN fresh NSM attestation document. Each frame is HPKE-opened, replay-checked, then
     * FULLY attestation-verified (PCRs + Nitro cert chain + nonce == req_nonce) and bound to its result
     * (user_data == SHA256(result)). So the client trusts each response on live hardware evidence, not
     * on a key attested once at session start. Used by the attested commit-reveal.
     */
    void callStreamAttested(RngOp op, Consumer<RngResult> onResult) throws Exception {
        Pinned p = ensureFresh();
        AsymmetricCipherKeyPair gameKp = hpke.generateKeyPair();
        byte[] gamePub = hpke.serializePublic(gameKp);
        byte[] reqNonce = new byte[16];
        random.nextBytes(reqNonce);

        byte[] sealedReq = SealedRequest.newBuilder()
                .setOp(op.toByteString())
                .setGamePub(ByteString.copyFrom(gamePub))
                .setReqNonce(ByteString.copyFrom(reqNonce))
                .build()
                .toByteArray();
        byte[] ciphertext = hpke.seal(p.encPub(), sealedReq);

        Iterator<SealedMessage> frames = stub.serveStreamAttested(SealedMessage.newBuilder()
                .setCiphertext(ByteString.copyFrom(ciphertext))
                .setModuleId(p.moduleId())
                .build());
        int n = 0;
        while (frames.hasNext()) {
            RngResult result = openVerifyAttested(frames.next(), gameKp, reqNonce, p);
            log.debug("attested stream frame {} OK module={}", ++n, p.moduleId());
            onResult.accept(result);
        }
    }

    /** Open one sealed reply, enforce req_nonce + signature under the pinned keys, return the result. */
    private RngResult openVerify(SealedMessage reply, AsymmetricCipherKeyPair gameKp, byte[] reqNonce, Pinned p)
            throws Exception {
        byte[] signedPlain = hpke.open(reply.getCiphertext().toByteArray(), gameKp);
        SignedResult sr = SignedResult.parseFrom(signedPlain);
        if (!MessageDigest.isEqual(reqNonce, sr.getReqNonce().toByteArray())) {
            throw new SecurityException("req_nonce mismatch — possible replay");
        }
        byte[] signedData = concat(sr.getResult().toByteArray(), sr.getReqNonce().toByteArray());
        if (!EcdsaSigner.verify(p.signPub(), signedData, sr.getSignature().toByteArray())) {
            throw new SecurityException("result signature invalid");
        }
        return RngResult.parseFrom(sr.getResult());
    }

    /**
     * Open one attested reply and trust it on hardware evidence alone: replay-check req_nonce, run the
     * full attestation verify on the frame's own doc (PCRs + Nitro cert chain + nonce == req_nonce),
     * bind the doc to the result (user_data == SHA256(result)), and confirm it's the same enclave
     * module the session pinned. Returns the verified result.
     */
    private RngResult openVerifyAttested(SealedMessage reply, AsymmetricCipherKeyPair gameKp, byte[] reqNonce, Pinned p)
            throws Exception {
        byte[] plain = hpke.open(reply.getCiphertext().toByteArray(), gameKp);
        AttestedResult ar = AttestedResult.parseFrom(plain);
        if (!MessageDigest.isEqual(reqNonce, ar.getReqNonce().toByteArray())) {
            throw new SecurityException("req_nonce mismatch — possible replay");
        }
        byte[] resultBytes = ar.getResult().toByteArray();
        // Full hardware attestation of THIS response; verify() checks nonce == req_nonce.
        AttestationDocument doc = verifier.verify(ar.getAttestationDoc().toByteArray(), reqNonce);
        if (doc.userData == null || !MessageDigest.isEqual(doc.userData, sha256(resultBytes))) {
            throw new SecurityException("attestation user_data != SHA256(result)");
        }
        if (!doc.moduleId.equals(p.moduleId())) {
            throw new SecurityException("attested module_id != session module — wrong enclave");
        }
        return RngResult.parseFrom(resultBytes);
    }

    private static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    /** Leaf (hypervisor) cert notAfter, in epoch millis — bounds how long this attestation stays fresh. */
    private static long leafNotAfter(AttestationDocument doc) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate leaf = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(doc.certificate));
        return leaf.getNotAfter().getTime();
    }

    private static long ms(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000L;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }
}
