package com.mario.rng;

import com.google.protobuf.ByteString;
import com.mario.crypto.EcdsaSigner;
import com.mario.crypto.Hpke;
import com.mario.rng.app.RngOp;
import com.mario.rng.app.RngResult;
import com.mario.rng.app.SealedRequest;
import com.mario.rng.app.SignedResult;
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

    private static final int CID_ANY = -1; // VMADDR_CID_ANY

    private final int port;
    private final RngEngine engine = new RngEngine();
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
        SealedMessage msg = SealedMessage.parseDelimitedFrom(in);

        // 1) HPKE open with the enclave enc key
        byte[] plain = hpke.open(msg.getCiphertext().toByteArray(), encKeyPair);
        SealedRequest sreq = SealedRequest.parseFrom(plain);

        // 2) run RNG
        RngOp op = RngOp.parseFrom(sreq.getOp());
        RngResult result = engine.execute(op);
        byte[] resultBytes = result.toByteArray();
        byte[] reqNonce = sreq.getReqNonce().toByteArray();

        // 3) sign (result || req_nonce) with sign_priv
        byte[] signature = EcdsaSigner.sign(signKeyPair.getPrivate(), concat(resultBytes, reqNonce));
        byte[] signed = SignedResult.newBuilder()
                .setResult(ByteString.copyFrom(resultBytes))
                .setReqNonce(ByteString.copyFrom(reqNonce))
                .setSignature(ByteString.copyFrom(signature))
                .build()
                .toByteArray();

        // 4) HPKE seal to the game's ephemeral pub
        byte[] sealed = hpke.seal(sreq.getGamePub().toByteArray(), signed);
        SealedMessage.newBuilder()
                .setCiphertext(ByteString.copyFrom(sealed))
                .build()
                .writeDelimitedTo(out);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }
}
