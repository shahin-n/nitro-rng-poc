package com.mario.proxy;

import io.grpc.Server;
import io.grpc.ServerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * proxy-service entrypoint. Bridges game-service (gRPC/TCP) to the enclave
 * rng-service (AF_VSOCK).
 *
 * <p>Env:
 * <ul>
 *   <li>{@code PROXY_GRPC_PORT}  — TCP port for game-service (default 50051)</li>
 *   <li>{@code ENCLAVE_CID}      — enclave vsock CID (default 16)</li>
 *   <li>{@code RNG_VSOCK_PORT}   — enclave vsock port (default 5005)</li>
 * </ul>
 */
public final class ProxyServer {

    private static final Logger log = LoggerFactory.getLogger(ProxyServer.class);

    public static void main(String[] args) throws IOException, InterruptedException {
        int grpcPort = envInt("PROXY_GRPC_PORT", 50051);
        int enclaveCid = envInt("ENCLAVE_CID", 16);
        int vsockPort = envInt("RNG_VSOCK_PORT", 5005);

        VsockRngClient enclave = new VsockRngClient(enclaveCid, vsockPort);

        Server server = ServerBuilder.forPort(grpcPort)
                .addService(new RngProxyService(enclave))
                .build()
                .start();

        log.info("proxy-service gRPC up on :{} -> enclave vsock cid={} port={}",
                grpcPort, enclaveCid, vsockPort);

        Runtime.getRuntime().addShutdownHook(new Thread(server::shutdown));
        server.awaitTermination();
    }

    private static int envInt(String key, int def) {
        String v = System.getenv(key);
        return v == null ? def : Integer.parseInt(v);
    }
}
