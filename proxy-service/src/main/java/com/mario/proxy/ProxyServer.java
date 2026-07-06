package com.mario.proxy;

import io.grpc.Server;
import io.grpc.ServerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;

/**
 * proxy-service entrypoint. Bridges game-service (gRPC/TCP) to the enclave
 * rng-service (AF_VSOCK).
 *
 * <p>Env:
 * <ul>
 *   <li>{@code PROXY_GRPC_PORT}  — TCP port for game-service (default 50051)</li>
 *   <li>{@code ENCLAVE_CID}      — enclave CID new attestations route to (default 16)</li>
 *   <li>{@code RNG_VSOCK_PORT}   — enclave vsock port (default 5005)</li>
 *   <li>{@code PCR_MANIFEST_PATH}, {@code PCR_MANIFEST_SIG_PATH} — release-signed
 *       PCR manifest JSON + detached signature, served verbatim on GetPcrManifest
 *       (both optional; the RPC returns UNIMPLEMENTED if unset)</li>
 * </ul>
 *
 * <p>Serve calls route by the session's module_id, so they always reach the enclave
 * that issued the attestation.
 */
public final class ProxyServer {

    private static final Logger log = LoggerFactory.getLogger(ProxyServer.class);

    public static void main(String[] args) throws IOException, InterruptedException {
        int grpcPort = envInt("PROXY_GRPC_PORT", 50051);   // deployment (bootstrap.sh) sets this to 8800
        int enclaveCid = envInt("ENCLAVE_CID", 16);
        int vsockPort = envInt("RNG_VSOCK_PORT", 5005);

        VsockRngClient enclave = new VsockRngClient(vsockPort);

        String manifestPath = System.getenv("PCR_MANIFEST_PATH");
        String manifestSigPath = System.getenv("PCR_MANIFEST_SIG_PATH");
        byte[] manifestJson = readFileOrNull(manifestPath, "PCR_MANIFEST_PATH");
        byte[] manifestSig = readFileOrNull(manifestSigPath, "PCR_MANIFEST_SIG_PATH");
        boolean manifestServed = manifestJson != null && manifestSig != null;

        RngProxyService service = new RngProxyService(enclave, enclaveCid, manifestJson, manifestSig);
        Server server = ServerBuilder.forPort(grpcPort)
                .addService(service)
                .build()
                .start();

        log.info("proxy-service gRPC up on :{} -> enclave cid={} vsock port={} pcr-manifest={}",
                grpcPort, enclaveCid, vsockPort, manifestServed ? "served" : "NOT configured");

        // Hot-reload the manifest on disk change so a rotation (re-signed files) is
        // served without restarting the proxy. Verbatim relay either way.
        if (manifestServed) {
            startManifestWatcher(service, manifestPath, manifestSigPath);
        }

        Runtime.getRuntime().addShutdownHook(new Thread(server::shutdown));
        server.awaitTermination();
    }

    private static int envInt(String key, int def) {
        String v = System.getenv(key);
        return v == null ? def : Integer.parseInt(v);
    }

    /**
     * Watch the manifest files' directory; on any change re-read BOTH files and swap
     * them into the service atomically. Operators should write updates atomically
     * (write temp + {@code mv}) so a poll never catches a half-written pair — a
     * mismatched json/sig would just make clients reject the signature until the next
     * consistent read. Best-effort daemon: a read error skips this round, keeping the
     * last good manifest in memory.
     */
    private static void startManifestWatcher(RngProxyService service, String jsonPath, String sigPath) {
        Path json = Path.of(jsonPath).toAbsolutePath();
        Path sig = Path.of(sigPath).toAbsolutePath();
        Thread t = new Thread(() -> {
            try (WatchService ws = FileSystems.getDefault().newWatchService()) {
                json.getParent().register(ws, StandardWatchEventKinds.ENTRY_MODIFY,
                        StandardWatchEventKinds.ENTRY_CREATE);
                if (!sig.getParent().equals(json.getParent())) {
                    sig.getParent().register(ws, StandardWatchEventKinds.ENTRY_MODIFY,
                            StandardWatchEventKinds.ENTRY_CREATE);
                }
                log.info("watching PCR manifest for changes: {} , {}", json, sig);
                while (true) {
                    WatchKey key = ws.take();
                    key.pollEvents();
                    try {
                        service.reloadManifest(Files.readAllBytes(json), Files.readAllBytes(sig));
                        log.info("reloaded PCR manifest from disk");
                    } catch (IOException e) {
                        log.warn("manifest reload skipped: {}", e.getMessage());
                    }
                    key.reset();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (IOException e) {
                log.error("manifest watcher stopped: {}", e.getMessage());
            }
        }, "manifest-watcher");
        t.setDaemon(true);
        t.start();
    }

    private static byte[] readFileOrNull(String path, String key) throws IOException {
        if (path == null || path.isBlank()) {
            return null;
        }
        Path p = Path.of(path);
        if (!Files.isReadable(p)) {
            log.warn("{}={} not readable — PCR manifest will not be served", key, path);
            return null;
        }
        return Files.readAllBytes(p);
    }
}
