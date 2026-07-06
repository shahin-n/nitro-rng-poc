package com.mario.proxy;

import com.google.protobuf.ByteString;
import com.mario.rng.proto.AttestReply;
import com.mario.rng.proto.AttestRequest;
import com.mario.rng.proto.ManifestRequest;
import com.mario.rng.proto.PcrManifest;
import com.mario.rng.proto.RngServiceGrpc;
import com.mario.rng.proto.SealedMessage;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * gRPC endpoint for games. module_id-affinity routing:
 *
 * <ul>
 *   <li>{@code Attest} -> routed to the enclave CID. The proxy reads the public
 *       module_id from the returned doc and records module_id -> CID.</li>
 *   <li>{@code Serve} / {@code ServeStream} -> routed to the CID the session's
 *       module_id was attested on, so the HPKE/signature keys always match.
 *       Unknown module_id => re-attest.</li>
 * </ul>
 *
 * Pure ciphertext relay (module_id is public). The module -> CID map also supports
 * running more than one enclave behind the proxy without changing this code.
 */
final class RngProxyService extends RngServiceGrpc.RngServiceImplBase {

    private static final Logger log = LoggerFactory.getLogger(RngProxyService.class);

    private final VsockRngClient enclave;
    private final int enclaveCid;
    private final ConcurrentMap<String, Integer> moduleToCid = new ConcurrentHashMap<>();

    // Release-signed PCR manifest + detached signature, loaded from disk and relayed
    // VERBATIM. The proxy is untrusted for these — the client verifies the signature
    // under a pinned release key. Volatile + swapped together so a file-watch reload
    // (rotation) takes effect with no restart; null when not configured.
    private volatile ByteString manifestJson;
    private volatile ByteString manifestSig;

    RngProxyService(VsockRngClient enclave, int enclaveCid, byte[] manifestJson, byte[] manifestSig) {
        this.enclave = enclave;
        this.enclaveCid = enclaveCid;
        this.manifestJson = manifestJson == null ? null : ByteString.copyFrom(manifestJson);
        this.manifestSig = manifestSig == null ? null : ByteString.copyFrom(manifestSig);
    }

    /** Swap in a freshly-read manifest+signature (called by the file watcher). */
    void reloadManifest(byte[] json, byte[] sig) {
        this.manifestJson = ByteString.copyFrom(json);
        this.manifestSig = ByteString.copyFrom(sig);
    }

    @Override
    public void attest(AttestRequest request, StreamObserver<AttestReply> responseObserver) {
        try {
            AttestReply reply = enclave.attest(enclaveCid, request);
            String moduleId = ModuleId.extract(reply.getAttestationDoc().toByteArray());
            moduleToCid.put(moduleId, enclaveCid);
            log.info("attested module_id={} -> cid={}", moduleId, enclaveCid);
            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        } catch (IOException e) {
            fail(responseObserver, e);
        } catch (RuntimeException e) {
            log.error("attest routing failed", e);
            responseObserver.onError(Status.INTERNAL.withDescription(e.getMessage()).asRuntimeException());
        }
    }

    @Override
    public void serve(SealedMessage request, StreamObserver<SealedMessage> responseObserver) {
        Integer cid = routeOrFail(request, responseObserver);
        if (cid == null) {
            return;
        }
        try {
            responseObserver.onNext(enclave.serve(cid, request));
            responseObserver.onCompleted();
        } catch (IOException e) {
            fail(responseObserver, e);
        }
    }

    @Override
    public void serveStream(SealedMessage request, StreamObserver<SealedMessage> responseObserver) {
        Integer cid = routeOrFail(request, responseObserver);
        if (cid == null) {
            return;
        }
        try {
            enclave.serveStream(cid, request, responseObserver::onNext);
            responseObserver.onCompleted();
        } catch (IOException e) {
            fail(responseObserver, e);
        }
    }

    @Override
    public void serveStreamAttested(SealedMessage request, StreamObserver<SealedMessage> responseObserver) {
        Integer cid = routeOrFail(request, responseObserver);
        if (cid == null) {
            return;
        }
        try {
            enclave.serveStreamAttested(cid, request, responseObserver::onNext);
            responseObserver.onCompleted();
        } catch (IOException e) {
            fail(responseObserver, e);
        }
    }

    @Override
    public void getPcrManifest(ManifestRequest request, StreamObserver<PcrManifest> responseObserver) {
        ByteString json = manifestJson;  // one snapshot: never mix json from one
        ByteString sig = manifestSig;     // reload with sig from another
        if (json == null || sig == null) {
            responseObserver.onError(Status.UNIMPLEMENTED
                    .withDescription("no PCR manifest configured on this proxy")
                    .asRuntimeException());
            return;
        }
        // Verbatim relay — proxy does not verify (can't; that's the client's job under
        // the pinned release key). Trust is in the signature, not this transport.
        responseObserver.onNext(PcrManifest.newBuilder()
                .setManifestJson(json)
                .setSignature(sig)
                .build());
        responseObserver.onCompleted();
    }

    /** Resolve the session's module_id to its attested CID, or fail the call and return null. */
    private Integer routeOrFail(SealedMessage request, StreamObserver<SealedMessage> responseObserver) {
        Integer cid = moduleToCid.get(request.getModuleId());
        if (cid == null) {
            responseObserver.onError(Status.FAILED_PRECONDITION
                    .withDescription("unknown module_id '" + request.getModuleId() + "' — re-attest")
                    .asRuntimeException());
        }
        return cid;
    }

    private void fail(StreamObserver<?> obs, IOException e) {
        log.error("enclave vsock relay failed", e);
        obs.onError(Status.UNAVAILABLE
                .withDescription("enclave unreachable: " + e.getMessage())
                .withCause(e)
                .asRuntimeException());
    }
}
