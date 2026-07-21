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
    // Dedicated audit trail. The proxy relays opaque HPKE ciphertext, so it can only attest to
    // ENVELOPE metadata: which module_id/CID, method, ciphertext sizes, frame counts, latency.
    private static final Logger audit = LoggerFactory.getLogger("audit");

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
        long t0 = System.nanoTime();
        try {
            AttestReply reply = enclave.attest(enclaveCid, request);
            String moduleId = ModuleId.extract(reply.getAttestationDoc().toByteArray());
            moduleToCid.put(moduleId, enclaveCid);
            log.info("attested module_id={} -> cid={}", moduleId, enclaveCid);
            audit.info("op=attest module_id={} cid={} nonce={}B doc={}B {}ms",
                    moduleId, enclaveCid, request.getClientNonce().size(),
                    reply.getAttestationDoc().size(), ms(t0));
            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        } catch (IOException e) {
            audit.warn("op=attest cid={} FAILED {}ms: {}", enclaveCid, ms(t0), e.getMessage());
            fail(responseObserver, e);
        } catch (RuntimeException e) {
            log.error("attest routing failed", e);
            audit.warn("op=attest cid={} FAILED {}ms: {}", enclaveCid, ms(t0), e.getMessage());
            responseObserver.onError(Status.INTERNAL.withDescription(e.getMessage()).asRuntimeException());
        }
    }

    @Override
    public void serve(SealedMessage request, StreamObserver<SealedMessage> responseObserver) {
        Integer cid = routeOrFail(request, responseObserver);
        if (cid == null) {
            return;
        }
        long t0 = System.nanoTime();
        try {
            SealedMessage reply = enclave.serve(cid, request);
            audit.info("op=serve module_id={} cid={} req={}B reply={}B {}ms",
                    request.getModuleId(), cid, request.getCiphertext().size(),
                    reply.getCiphertext().size(), ms(t0));
            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        } catch (IOException e) {
            audit.warn("op=serve module_id={} cid={} FAILED {}ms: {}", request.getModuleId(), cid, ms(t0), e.getMessage());
            fail(responseObserver, e);
        }
    }

    @Override
    public void serveAttested(SealedMessage request, StreamObserver<SealedMessage> responseObserver) {
        Integer cid = routeOrFail(request, responseObserver);
        if (cid == null) {
            return;
        }
        long t0 = System.nanoTime();
        try {
            SealedMessage reply = enclave.serveAttested(cid, request);
            audit.info("op=serveAttested module_id={} cid={} req={}B reply={}B {}ms",
                    request.getModuleId(), cid, request.getCiphertext().size(),
                    reply.getCiphertext().size(), ms(t0));
            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        } catch (IOException e) {
            audit.warn("op=serveAttested module_id={} cid={} FAILED {}ms: {}", request.getModuleId(), cid, ms(t0), e.getMessage());
            fail(responseObserver, e);
        }
    }

    @Override
    public void serveStream(SealedMessage request, StreamObserver<SealedMessage> responseObserver) {
        Integer cid = routeOrFail(request, responseObserver);
        if (cid == null) {
            return;
        }
        long t0 = System.nanoTime();
        FrameMeter m = new FrameMeter();
        try {
            enclave.serveStream(cid, request, m.wrap(responseObserver));
            audit.info("op=serveStream module_id={} cid={} req={}B frames={} replyBytes={} {}ms",
                    request.getModuleId(), cid, request.getCiphertext().size(), m.frames, m.bytes, ms(t0));
            responseObserver.onCompleted();
        } catch (IOException e) {
            audit.warn("op=serveStream module_id={} cid={} frames={} FAILED {}ms: {}",
                    request.getModuleId(), cid, m.frames, ms(t0), e.getMessage());
            fail(responseObserver, e);
        }
    }

    @Override
    public void serveStreamAttested(SealedMessage request, StreamObserver<SealedMessage> responseObserver) {
        Integer cid = routeOrFail(request, responseObserver);
        if (cid == null) {
            return;
        }
        long t0 = System.nanoTime();
        FrameMeter m = new FrameMeter();
        try {
            enclave.serveStreamAttested(cid, request, m.wrap(responseObserver));
            audit.info("op=serveStreamAttested module_id={} cid={} req={}B frames={} replyBytes={} {}ms",
                    request.getModuleId(), cid, request.getCiphertext().size(), m.frames, m.bytes, ms(t0));
            responseObserver.onCompleted();
        } catch (IOException e) {
            audit.warn("op=serveStreamAttested module_id={} cid={} frames={} FAILED {}ms: {}",
                    request.getModuleId(), cid, m.frames, ms(t0), e.getMessage());
            fail(responseObserver, e);
        }
    }

    /** Counts relayed frames + ciphertext bytes without touching the opaque payload. */
    private static final class FrameMeter {
        int frames;
        long bytes;

        java.util.function.Consumer<SealedMessage> wrap(StreamObserver<SealedMessage> out) {
            return msg -> {
                frames++;
                bytes += msg.getCiphertext().size();
                out.onNext(msg);
            };
        }
    }

    private static long ms(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000L;
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
        audit.info("op=getPcrManifest json={}B sig={}B", json.size(), sig.size());
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
