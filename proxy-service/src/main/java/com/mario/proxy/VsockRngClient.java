package com.mario.proxy;

import com.mario.rng.proto.AttestReply;
import com.mario.rng.proto.AttestRequest;
import com.mario.rng.proto.SealedMessage;
import org.newsclub.net.unix.AFVSOCKSocketAddress;
import org.newsclub.net.unix.vsock.AFVSOCKSocket;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * South-side relay to the enclave over AF_VSOCK. Forwards the two opaque frame
 * types; never inspects ciphertext. One connection per call.
 *
 * <pre>
 *   'A' + AttestRequest  -> AttestReply
 *   'S' + SealedMessage  -> SealedMessage
 * </pre>
 */
final class VsockRngClient {

    static final int TAG_ATTEST = 'A';
    static final int TAG_SERVE = 'S';

    private final int enclaveCid;
    private final int port;

    VsockRngClient(int enclaveCid, int port) {
        this.enclaveCid = enclaveCid;
        this.port = port;
    }

    AttestReply attest(AttestRequest req) throws IOException {
        try (AFVSOCKSocket s = connect();
             OutputStream out = s.getOutputStream();
             InputStream in = s.getInputStream()) {
            out.write(TAG_ATTEST);
            req.writeDelimitedTo(out);
            out.flush();
            return AttestReply.parseDelimitedFrom(in);
        }
    }

    SealedMessage serve(SealedMessage req) throws IOException {
        try (AFVSOCKSocket s = connect();
             OutputStream out = s.getOutputStream();
             InputStream in = s.getInputStream()) {
            out.write(TAG_SERVE);
            req.writeDelimitedTo(out);
            out.flush();
            return SealedMessage.parseDelimitedFrom(in);
        }
    }

    private AFVSOCKSocket connect() throws IOException {
        return AFVSOCKSocket.connectTo(AFVSOCKSocketAddress.ofPortAndCID(port, enclaveCid));
    }
}
