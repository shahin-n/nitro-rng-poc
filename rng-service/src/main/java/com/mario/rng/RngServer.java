package com.mario.rng;

import com.google.protobuf.ByteString;
import com.mario.crypto.EcdsaSigner;
import com.mario.crypto.Hpke;
import com.mario.rng.app.AttestedResult;
import com.mario.rng.app.RngOp;
import com.mario.rng.app.RngResult;
import com.mario.rng.app.SealedRequest;
import com.mario.rng.app.SignedResult;
import com.mario.rng.round.RoundService;
import com.mario.rng.proto.AttestReply;
import com.mario.rng.proto.AttestRequest;
import com.mario.rng.proto.SealedMessage;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.newsclub.net.unix.AFVSOCKSocketAddress;
import org.newsclub.net.unix.vsock.AFVSOCKServerSocket;
import org.newsclub.net.unix.vsock.AFVSOCKSocket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * RNG Engine entrypoint — runs inside the Nitro Enclave.
 *
 * <p>Boot: generate ephemeral keys in RAM (X25519 enc + ECDSA-P384 sign), nothing
 * persisted. Listens on vsock and serves two opaque frame types:
 * <pre>
 *   'A' AttestRequest  -> AttestReply       (NSM COSE doc bound to nonce + keys)
 *   'S' SealedMessage  -> SealedMessage      (HPKE open -> RNG -> sign -> HPKE seal)
 * </pre>
 */
public final class RngServer {

    private static final Logger log = LoggerFactory.getLogger(RngServer.class);

    static final int TAG_ATTEST = 'A';
    static final int TAG_SERVE = 'S';
    static final int TAG_STREAM = 'C'; // commit-reveal: one request, two pushed frames
    static final int TAG_STREAM_ATTESTED = 'D'; // commit-reveal, each frame NSM-attested
    static final int TAG_SERVE_ATTESTED = 'E'; // APFR round op: one request, one NSM-attested reply

    private static final int CID_ANY = -1; // VMADDR_CID_ANY

    private final int port;
    private final RngEngine engine = new RngEngine();
    private final RoundService rounds = new RoundService();
    private final Hpke hpke = new Hpke();
    private final ExecutorService workers = Executors.newCachedThreadPool();

    // ephemeral identity, per boot, RAM only
    private final AsymmetricCipherKeyPair encKeyPair;
    private final byte[] encPub;
    private final KeyPair signKeyPair;
    private final byte[] signPubDer;

    public RngServer(int port) {
        this.port = port;
        this.encKeyPair = hpke.generateKeyPair();
        this.encPub = hpke.serializePublic(encKeyPair);
        this.signKeyPair = EcdsaSigner.generateKeyPair();
        this.signPubDer = EcdsaSigner.encodePublic(signKeyPair.getPublic());
    }

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(System.getenv().getOrDefault("RNG_VSOCK_PORT", "5005"));
        new RngServer(port).serve();
    }

    public void serve() throws IOException {
        AFVSOCKSocketAddress addr = AFVSOCKSocketAddress.ofPortAndCID(port, CID_ANY);
        try (AFVSOCKServerSocket server = AFVSOCKServerSocket.bindOn(addr)) {
            log.info("RNG Engine on vsock port {} — ephemeral keys generated", port);
            while (!Thread.currentThread().isInterrupted()) {
                AFVSOCKSocket conn = server.accept();
                workers.submit(() -> handle(conn));
            }
        }
    }

    private void handle(AFVSOCKSocket conn) {
        try (AFVSOCKSocket c = conn;
             InputStream in = c.getInputStream();
             OutputStream out = c.getOutputStream()) {
            int tag;
            while ((tag = in.read()) != -1) {
                switch (tag) {
                    case TAG_ATTEST -> attest(in, out);
                    case TAG_SERVE -> serveOne(in, out);
                    case TAG_STREAM -> {
                        serveStream(in, out);   // pushes both frames itself, then we close the connection
                        return;
                    }
                    case TAG_STREAM_ATTESTED -> {
                        serveStreamAttested(in, out); // same, but each frame carries a fresh NSM doc
                        return;
                    }
                    case TAG_SERVE_ATTESTED -> serveAttested(in, out); // APFR round op, one attested reply
                    default -> {
                        log.warn("unknown tag {} — closing", tag);
                        return;
                    }
                }
                out.flush();
            }
        } catch (Exception e) {
            log.debug("connection closed: {}", e.getMessage());
        }
    }

    private void attest(InputStream in, OutputStream out) throws IOException {
        AttestRequest req = AttestRequest.parseDelimitedFrom(in);
        byte[] nonce = req.getClientNonce().toByteArray();
        try (NsmClient nsm = new NsmClient()) {
            byte[] doc = nsm.attest(signPubDer, nonce, encPub);
            AttestReply.newBuilder()
                    .setAttestationDoc(ByteString.copyFrom(doc))
                    .build()
                    .writeDelimitedTo(out);
            log.info("attested: nonce={}B doc={}B", nonce.length, doc.length);
        }
    }

    private void serveOne(InputStream in, OutputStream out) throws Exception {
        SealedRequest sreq = openRequest(in);
        RngResult result = engine.execute(RngOp.parseFrom(sreq.getOp()));
        sealFrame(result, sreq).writeDelimitedTo(out);
    }

    /**
     * Commit-reveal over a held connection: push the signed commit-hash frame and flush,
     * sleep the delay on the enclave's own clock, then push the signed reveal frame. The
     * caller closes the connection afterwards so the proxy sees end-of-stream.
     */
    private void serveStream(InputStream in, OutputStream out) throws Exception {
        SealedRequest sreq = openRequest(in);
        RngOp op = RngOp.parseFrom(sreq.getOp());
        if (op.getOpCase() != RngOp.OpCase.COMMIT_REVEAL) {
            throw new IllegalArgumentException("ServeStream serves commit_reveal only, got " + op.getOpCase());
        }
        RngEngine.CommitRevealFrames frames = engine.commitReveal(op.getCommitReveal());

        // frame 1 — commit hash; flushed now, so the enclave is bound before the seed exists to the game
        sealFrame(RngResult.newBuilder().setCommit(frames.commit()).build(), sreq).writeDelimitedTo(out);
        out.flush();

        // hold the stream for the delay (enclave clock), then push the reveal
        sleepSeconds(frames.commit().getDelaySeconds());
        sealFrame(RngResult.newBuilder().setReveal(frames.reveal()).build(), sreq).writeDelimitedTo(out);
        out.flush();
    }

    /**
     * Commit-reveal, per-response attested. Same two-frame flow as {@link #serveStream}, but each
     * frame is sealed with a FRESH NSM attestation document (see {@link #sealAttestedFrame}) rather
     * than the ephemeral ECDSA signature — so every pushed response independently proves it came
     * from the genuine enclave (PCRs + Nitro cert chain), not just from a once-attested key. One
     * NsmClient is held open for the whole stream (two attest ioctls).
     */
    private void serveStreamAttested(InputStream in, OutputStream out) throws Exception {
        SealedRequest sreq = openRequest(in);
        RngOp op = RngOp.parseFrom(sreq.getOp());
        switch (op.getOpCase()) {
            case COMMIT_REVEAL -> {
                RngEngine.CommitRevealFrames frames = engine.commitReveal(op.getCommitReveal());
                try (NsmClient nsm = new NsmClient()) {
                    // frame 1 — commit hash, attested + flushed now (enclave bound before the seed hits the wire)
                    sealAttestedFrame(RngResult.newBuilder().setCommit(frames.commit()).build(), sreq, nsm).writeDelimitedTo(out);
                    out.flush();
                    // hold the stream for the delay (enclave clock), then push the attested reveal
                    sleepSeconds(frames.commit().getDelaySeconds());
                    sealAttestedFrame(RngResult.newBuilder().setReveal(frames.reveal()).build(), sreq, nsm).writeDelimitedTo(out);
                    out.flush();
                }
            }
            case NOISE_COMMIT_REVEAL -> {
                RngEngine.NoiseFrames frames = engine.noiseCommitReveal(op.getNoiseCommitReveal());
                try (NsmClient nsm = new NsmClient()) {
                    // frame 1 — commit hash of the noise payload, attested + flushed before the payload is revealed
                    sealAttestedFrame(RngResult.newBuilder().setNoiseCommit(frames.commit()).build(), sreq, nsm).writeDelimitedTo(out);
                    out.flush();
                    sleepSeconds(frames.commit().getDelaySeconds());
                    sealAttestedFrame(RngResult.newBuilder().setNoiseReveal(frames.reveal()).build(), sreq, nsm).writeDelimitedTo(out);
                    out.flush();
                }
            }
            default -> throw new IllegalArgumentException(
                    "ServeStreamAttested serves commit_reveal / noise_commit_reveal only, got " + op.getOpCase());
        }
    }

    /**
     * APFR round op (RoundOpen / RoundAction / RoundSettle) — one request, one NSM-attested reply.
     * The round state lives in {@link RoundService} across calls; the reply is sealed with a fresh
     * doc that binds SHA256(request || result), so every round step is independently verifiable.
     */
    private void serveAttested(InputStream in, OutputStream out) throws Exception {
        SealedRequest sreq = openRequest(in);
        RngOp op = RngOp.parseFrom(sreq.getOp());
        RngResult result = rounds.handle(op, "", System.currentTimeMillis());
        try (NsmClient nsm = new NsmClient()) {
            sealAttestedFrame(result, sreq, nsm).writeDelimitedTo(out);
        }
    }

    /** Read one delimited SealedMessage and HPKE-open it to the inner SealedRequest. */
    private SealedRequest openRequest(InputStream in) throws Exception {
        SealedMessage msg = SealedMessage.parseDelimitedFrom(in);
        return SealedRequest.parseFrom(hpke.open(msg.getCiphertext().toByteArray(), encKeyPair));
    }

    /** Sign (result || req_nonce) and HPKE-seal the SignedResult to the game's ephemeral pub. */
    private SealedMessage sealFrame(RngResult result, SealedRequest sreq) throws Exception {
        byte[] resultBytes = result.toByteArray();
        byte[] reqNonce = sreq.getReqNonce().toByteArray();
        byte[] signature = EcdsaSigner.sign(signKeyPair.getPrivate(), concat(resultBytes, reqNonce));
        byte[] signed = SignedResult.newBuilder()
                .setResult(ByteString.copyFrom(resultBytes))
                .setReqNonce(ByteString.copyFrom(reqNonce))
                .setSignature(ByteString.copyFrom(signature))
                .build()
                .toByteArray();
        byte[] sealed = hpke.seal(sreq.getGamePub().toByteArray(), signed);
        return SealedMessage.newBuilder().setCiphertext(ByteString.copyFrom(sealed)).build();
    }

    /**
     * Attest one result and HPKE-seal it to the game. The NSM doc binds user_data = SHA256(result)
     * and nonce = req_nonce; public_key = encPub (matches the session attestation). The game runs
     * the full attestation verify on this doc, so the frame is trusted on hardware evidence alone.
     */
    private SealedMessage sealAttestedFrame(RngResult result, SealedRequest sreq, NsmClient nsm) throws Exception {
        byte[] resultBytes = result.toByteArray();
        byte[] reqBytes = sreq.getOp().toByteArray();          // the exact RngOp the enclave processed
        byte[] reqNonce = sreq.getReqNonce().toByteArray();
        // Bind BOTH request and result into the signed doc: proves this enclave produced this
        // result FOR this request, not just some result. The client re-derives the same digest.
        byte[] userData = RngEngine.sha256(concat(reqBytes, resultBytes));
        byte[] doc = nsm.attest(userData, reqNonce, encPub);
        byte[] attested = AttestedResult.newBuilder()
                .setResult(ByteString.copyFrom(resultBytes))
                .setReqNonce(ByteString.copyFrom(reqNonce))
                .setRequest(ByteString.copyFrom(reqBytes))
                .setAttestationDoc(ByteString.copyFrom(doc))
                .build()
                .toByteArray();
        byte[] sealed = hpke.seal(sreq.getGamePub().toByteArray(), attested);
        return SealedMessage.newBuilder().setCiphertext(ByteString.copyFrom(sealed)).build();
    }

    private static void sleepSeconds(int seconds) {
        try {
            Thread.sleep(seconds * 1000L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }
}
