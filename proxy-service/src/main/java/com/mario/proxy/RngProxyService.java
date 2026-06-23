package com.mario.proxy;

import com.mario.rng.proto.AttestReply;
import com.mario.rng.proto.AttestRequest;
import com.mario.rng.proto.RngServiceGrpc;
import com.mario.rng.proto.SealedMessage;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * gRPC endpoint for games. Relays Attest + Serve to the enclave over vsock,
 * verbatim. No decryption, no verification — that is the game's and enclave's job.
 */
final class RngProxyService extends RngServiceGrpc.RngServiceImplBase {

    private static final Logger log = LoggerFactory.getLogger(RngProxyService.class);

    private final VsockRngClient enclave;

    RngProxyService(VsockRngClient enclave) {
        this.enclave = enclave;
    }

    @Override
    public void attest(AttestRequest request, StreamObserver<AttestReply> responseObserver) {
        try {
            responseObserver.onNext(enclave.attest(request));
            responseObserver.onCompleted();
        } catch (IOException e) {
            fail(responseObserver, e);
        }
    }

    @Override
    public void serve(SealedMessage request, StreamObserver<SealedMessage> responseObserver) {
        try {
            responseObserver.onNext(enclave.serve(request));
            responseObserver.onCompleted();
        } catch (IOException e) {
            fail(responseObserver, e);
        }
    }

    private void fail(StreamObserver<?> obs, IOException e) {
        log.error("enclave vsock relay failed", e);
        obs.onError(Status.UNAVAILABLE
                .withDescription("enclave unreachable: " + e.getMessage())
                .withCause(e)
                .asRuntimeException());
    }
}
