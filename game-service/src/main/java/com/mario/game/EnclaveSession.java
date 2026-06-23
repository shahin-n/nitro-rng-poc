package com.mario.game;

import com.google.protobuf.ByteString;
import com.mario.attestation.AttestationDocument;
import com.mario.attestation.AttestationVerifier;
import com.mario.crypto.EcdsaSigner;
import com.mario.crypto.Hpke;
import com.mario.rng.app.RngOp;
import com.mario.rng.app.RngResult;
import com.mario.rng.app.SealedRequest;
import com.mario.rng.app.SignedResult;
import com.mario.rng.proto.AttestReply;
import com.mario.rng.proto.AttestRequest;
import com.mario.rng.proto.RngServiceGrpc;
import com.mario.rng.proto.SealedMessage;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * Client-side enclave session: attest once (verify + pin), then make confidential,
 * authenticated calls. Mirrors flow steps B (attest) and C (serve).
 */
final class EnclaveSession {

    private final RngServiceGrpc.RngServiceBlockingStub stub;
    private final AttestationVerifier verifier;
    private final Hpke hpke = new Hpke();
    private final SecureRandom random = new SecureRandom();

    private String moduleId;
    private byte[] encPub;       // enclave X25519 pub (from doc)
    private PublicKey signPub;   // enclave ECDSA pub (from doc)

    EnclaveSession(RngServiceGrpc.RngServiceBlockingStub stub, AttestationVerifier verifier) {
        this.stub = stub;
        this.verifier = verifier;
    }

    boolean attested() {
        return encPub != null;
    }

    String moduleId() {
        return moduleId;
    }

    /** Step B — fetch + verify the attestation document, cache the enclave keys. */
    void attest() throws Exception {
        byte[] nonce = new byte[32];
        random.nextBytes(nonce);

        AttestReply reply = stub.attest(AttestRequest.newBuilder()
                .setClientNonce(ByteString.copyFrom(nonce))
                .build());

        AttestationDocument doc = verifier.verify(reply.getAttestationDoc().toByteArray(), nonce);
        this.moduleId = doc.moduleId;
        this.encPub = doc.publicKey;
        this.signPub = EcdsaSigner.decodePublic(doc.userData);
    }

    /** Step C — HPKE-seal the op, serve, then verify signature + req_nonce. */
    RngResult call(RngOp op) throws Exception {
        if (!attested()) {
            attest();
        }

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

        byte[] ciphertext = hpke.seal(encPub, sealedReq);
        SealedMessage reply = stub.serve(SealedMessage.newBuilder()
                .setCiphertext(ByteString.copyFrom(ciphertext))
                .build());

        byte[] signedPlain = hpke.open(reply.getCiphertext().toByteArray(), gameKp);
        SignedResult sr = SignedResult.parseFrom(signedPlain);

        if (!MessageDigest.isEqual(reqNonce, sr.getReqNonce().toByteArray())) {
            throw new SecurityException("req_nonce mismatch — possible replay");
        }
        byte[] signedData = concat(sr.getResult().toByteArray(), sr.getReqNonce().toByteArray());
        if (!EcdsaSigner.verify(signPub, signedData, sr.getSignature().toByteArray())) {
            throw new SecurityException("result signature invalid");
        }
        return RngResult.parseFrom(sr.getResult());
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }
}
