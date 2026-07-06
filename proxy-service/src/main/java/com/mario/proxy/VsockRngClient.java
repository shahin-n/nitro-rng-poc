package com.mario.proxy;

import com.mario.rng.proto.AttestReply;
import com.mario.rng.proto.AttestRequest;
import com.mario.rng.proto.SealedMessage;
import org.newsclub.net.unix.AFVSOCKSocketAddress;
import org.newsclub.net.unix.vsock.AFVSOCKSocket;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.function.Consumer;

/**
 * South-side relay to the enclaves over AF_VSOCK. Forwards the opaque frame types
 * to a given enclave CID; never inspects ciphertext. One connection per call.
 *
 * <pre>
 *   'A' + AttestRequest  -> AttestReply
 *   'S' + SealedMessage  -> SealedMessage
 *   'C' + SealedMessage  -> SealedMessage, SealedMessage, ...  (enclave-pushed stream)
 * </pre>
 */
final class VsockRngClient {

    static final int TAG_ATTEST = 'A';
    static final int TAG_SERVE = 'S';
    static final int TAG_STREAM = 'C';
    static final int TAG_STREAM_ATTESTED = 'D';

    private final int port;

    VsockRngClient(int port) {
        this.port = port;
    }

    AttestReply attest(int cid, AttestRequest req) throws IOException {
        try (AFVSOCKSocket s = connect(cid);
             OutputStream out = s.getOutputStream();
             InputStream in = s.getInputStream()) {
            out.write(TAG_ATTEST);
            req.writeDelimitedTo(out);
            out.flush();
            return AttestReply.parseDelimitedFrom(in);
        }
    }

    SealedMessage serve(int cid, SealedMessage req) throws IOException {
        try (AFVSOCKSocket s = connect(cid);
             OutputStream out = s.getOutputStream();
             InputStream in = s.getInputStream()) {
            out.write(TAG_SERVE);
            req.writeDelimitedTo(out);
            out.flush();
            return SealedMessage.parseDelimitedFrom(in);
        }
    }

    /**
     * Enclave-pushed stream: send one request, then relay each reply frame to {@code onFrame}
     * as it arrives (the enclave holds the connection between frames). Returns when the enclave
     * closes the stream. Pure ciphertext relay — frames are never inspected.
     */
    void serveStream(int cid, SealedMessage req, Consumer<SealedMessage> onFrame) throws IOException {
        relayStream(TAG_STREAM, cid, req, onFrame);
    }

    /** Same enclave-pushed stream as {@link #serveStream}, but each frame is NSM-attested. */
    void serveStreamAttested(int cid, SealedMessage req, Consumer<SealedMessage> onFrame) throws IOException {
        relayStream(TAG_STREAM_ATTESTED, cid, req, onFrame);
    }

    private void relayStream(int tag, int cid, SealedMessage req, Consumer<SealedMessage> onFrame) throws IOException {
        try (AFVSOCKSocket s = connect(cid);
             OutputStream out = s.getOutputStream();
             InputStream in = s.getInputStream()) {
            out.write(tag);
            req.writeDelimitedTo(out);
            out.flush();
            SealedMessage frame;
            while ((frame = SealedMessage.parseDelimitedFrom(in)) != null) {
                onFrame.accept(frame);
            }
        }
    }

    private AFVSOCKSocket connect(int cid) throws IOException {
        return AFVSOCKSocket.connectTo(AFVSOCKSocketAddress.ofPortAndCID(port, cid));
    }
}
