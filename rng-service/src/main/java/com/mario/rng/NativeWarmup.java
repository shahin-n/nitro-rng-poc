package com.mario.rng;

import com.google.protobuf.ByteString;
import com.mario.crypto.EcdsaSigner;
import com.mario.crypto.Hpke;
import com.mario.rng.app.CommitReveal;
import com.mario.rng.app.NextBytes;
import com.mario.rng.app.NextInt;
import com.mario.rng.app.RngOp;
import com.mario.rng.app.RngResult;
import com.mario.rng.app.SealedRequest;
import com.mario.rng.app.SignedResult;
import com.mario.rng.proto.AttestReply;
import com.mario.rng.proto.AttestRequest;
import com.mario.rng.proto.SealedMessage;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import java.security.KeyPair;

/**
 * Not a server — a build-time harness. Run under the GraalVM tracing agent
 * ({@code -agentlib:native-image-agent}) to record every reflective / FFM path
 * the engine actually uses (protobuf builders+parsers, BouncyCastle, FFM downcall
 * linkage), so the native image is built with correct reachability metadata.
 *
 * <p>Exercises everything EXCEPT the real {@code /dev/nsm} ioctl (unavailable off
 * an enclave); the NSM FFM handles still link, which is what we need recorded.
 */
public final class NativeWarmup {

    public static void main(String[] args) throws Exception {
        RngEngine engine = new RngEngine();
        Hpke hpke = new Hpke();

        // --- protobuf: build + serialize + parse every wire/app message ---
        AttestRequest.parseFrom(AttestRequest.newBuilder()
                .setClientNonce(ByteString.copyFrom(new byte[32])).build().toByteArray());
        AttestReply.parseFrom(AttestReply.newBuilder()
                .setAttestationDoc(ByteString.copyFrom(new byte[4])).build().toByteArray());
        SealedMessage.parseFrom(SealedMessage.newBuilder()
                .setCiphertext(ByteString.copyFrom(new byte[4])).build().toByteArray());

        for (RngOp op : new RngOp[]{
                RngOp.newBuilder().setNextInt(NextInt.newBuilder().setMin(1).setMax(6)).build(),
                RngOp.newBuilder().setNextBytes(NextBytes.newBuilder().setCount(8)).build(),
                RngOp.newBuilder().setCommitReveal(CommitReveal.newBuilder().setMin(1).setMax(9).setDelaySeconds(0)).build()}) {
            RngResult r = engine.execute(RngOp.parseFrom(op.toByteArray()));
            r.toByteArray();
        }

        // --- HPKE + ECDSA round-trip (BouncyCastle) ---
        AsymmetricCipherKeyPair enc = hpke.generateKeyPair();
        byte[] encPub = hpke.serializePublic(enc);
        KeyPair sign = EcdsaSigner.generateKeyPair();
        byte[] signPubDer = EcdsaSigner.encodePublic(sign.getPublic());

        SealedRequest sreq = SealedRequest.newBuilder()
                .setOp(RngOp.newBuilder().setNextInt(NextInt.newBuilder().setMin(1).setMax(6)).build().toByteString())
                .setGamePub(ByteString.copyFrom(encPub))
                .setReqNonce(ByteString.copyFrom(new byte[16]))
                .build();
        byte[] ct = hpke.seal(encPub, sreq.toByteArray());
        SealedRequest.parseFrom(hpke.open(ct, enc));

        byte[] sig = EcdsaSigner.sign(sign.getPrivate(), encPub);
        EcdsaSigner.verify(EcdsaSigner.decodePublic(signPubDer), encPub, sig);
        SignedResult.newBuilder().setResult(ByteString.EMPTY).setReqNonce(ByteString.EMPTY)
                .setSignature(ByteString.copyFrom(sig)).build().toByteArray();

        // --- link the NSM FFM downcall handles (no real ioctl off-enclave) ---
        try (NsmClient ignored = new NsmClient()) {
            // unreachable off enclave; class init linked the FFM stubs already
        } catch (Throwable ignored) {
            // expected: no /dev/nsm
        }

        System.out.println("warmup complete");
    }

    private NativeWarmup() {
    }
}
