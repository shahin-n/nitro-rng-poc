package com.mario.rng;

import com.upokecenter.cbor.CBORObject;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

/**
 * Nitro Secure Module client — requests a hardware-signed attestation document
 * over the {@code /dev/nsm} ioctl interface, using the JDK FFM API (no JNA, so it
 * builds cleanly into a GraalVM native image).
 *
 * <pre>
 *   request  = { "Attestation": { "user_data": bstr, "nonce": bstr, "public_key": bstr } }
 *   response = { "Attestation": { "document": bstr } }   // bstr = COSE_Sign1 doc
 * </pre>
 *
 * <p>Linux/enclave only.
 */
public final class NsmClient implements AutoCloseable {

    private static final String DEV = "/dev/nsm";
    private static final int O_RDWR = 2;
    private static final int RESPONSE_MAX = 0x3000; // 12 KiB, per AWS nsm-driver

    // _IOWR(0x0A, 0, struct nsm_message), sizeof(nsm_message)=32 on LP64
    private static final long NSM_IOCTL = (3L << 30) | (32L << 16) | (0x0AL << 8);

    // struct nsm_message { struct iovec request; struct iovec response; }
    // struct iovec { void* iov_base; size_t iov_len; }  -> offsets 0,8 / 16,24
    private static final long OFF_REQ_BASE = 0;
    private static final long OFF_REQ_LEN = 8;
    private static final long OFF_RESP_BASE = 16;
    private static final long OFF_RESP_LEN = 24;
    private static final long MSG_SIZE = 32;

    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup LIBC = LINKER.defaultLookup();

    private static final MethodHandle OPEN = LINKER.downcallHandle(
            LIBC.find("open").orElseThrow(),
            FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT),
            Linker.Option.firstVariadicArg(2));
    private static final MethodHandle CLOSE = LINKER.downcallHandle(
            LIBC.find("close").orElseThrow(),
            FunctionDescriptor.of(JAVA_INT, JAVA_INT));
    private static final MethodHandle IOCTL = LINKER.downcallHandle(
            LIBC.find("ioctl").orElseThrow(),
            FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_LONG, ADDRESS),
            Linker.Option.firstVariadicArg(2));

    private final int fd;

    public NsmClient() throws IOException {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment path = arena.allocateFrom(DEV);
            this.fd = (int) OPEN.invoke(path, O_RDWR);
        } catch (Throwable t) {
            throw new IOException("open " + DEV + " failed", t);
        }
        if (fd < 0) {
            throw new IOException("cannot open " + DEV + " (enclave only?)");
        }
    }

    /** Returns the COSE_Sign1 attestation document bytes. */
    public byte[] attest(byte[] userData, byte[] nonce, byte[] publicKey) throws IOException {
        byte[] reqCbor = buildRequest(userData, nonce, publicKey);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment req = arena.allocate(reqCbor.length);
            MemorySegment.copy(reqCbor, 0, req, JAVA_BYTE, 0, reqCbor.length);
            MemorySegment resp = arena.allocate(RESPONSE_MAX);

            MemorySegment msg = arena.allocate(MSG_SIZE);
            msg.set(ADDRESS, OFF_REQ_BASE, req);
            msg.set(JAVA_LONG, OFF_REQ_LEN, reqCbor.length);
            msg.set(ADDRESS, OFF_RESP_BASE, resp);
            msg.set(JAVA_LONG, OFF_RESP_LEN, RESPONSE_MAX);

            int rc = (int) IOCTL.invoke(fd, NSM_IOCTL, msg);
            if (rc != 0) {
                throw new IOException("NSM ioctl failed rc=" + rc);
            }
            long respLen = msg.get(JAVA_LONG, OFF_RESP_LEN);
            byte[] respCbor = resp.asSlice(0, respLen).toArray(JAVA_BYTE);
            return parseDocument(respCbor);
        } catch (IOException e) {
            throw e;
        } catch (Throwable t) {
            throw new IOException("NSM ioctl error", t);
        }
    }

    private static byte[] buildRequest(byte[] userData, byte[] nonce, byte[] publicKey) {
        CBORObject inner = CBORObject.NewMap();
        inner.Add("user_data", CBORObject.FromObject(userData));
        inner.Add("nonce", CBORObject.FromObject(nonce));
        inner.Add("public_key", CBORObject.FromObject(publicKey));
        CBORObject req = CBORObject.NewMap();
        req.Add("Attestation", inner);
        return req.EncodeToBytes();
    }

    private static byte[] parseDocument(byte[] respCbor) throws IOException {
        CBORObject resp = CBORObject.DecodeFromBytes(respCbor);
        CBORObject att = resp.get("Attestation");
        if (att == null) {
            throw new IOException("NSM error: " + resp);
        }
        return att.get("document").GetByteString();
    }

    @Override
    public void close() {
        try {
            CLOSE.invoke(fd);
        } catch (Throwable ignored) {
            // best-effort
        }
    }
}
