package com.mario.manifest;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Build and KMS-sign the PCR manifest — the release-signed allow-list of enclave
 * measurements a client will accept. Reuses the SAME AWS KMS asymmetric key that
 * signs the enclave EIF cert (see kms_selfsign_cert.py); its public half is pinned
 * in the client as attestation/src/main/resources/release-pub.pem.
 *
 * <p>The client fetches manifest.json + manifest.sig (via the proxy, untrusted
 * transport), verifies the signature over the EXACT bytes of manifest.json under the
 * pinned key, then trusts the PCR set (see {@code com.mario.attestation.PcrManifest}).
 * Rotation = re-run with the new PCR0 added, redeploy the two files behind the proxy.
 * No client change, additive set = zero-downtime.
 *
 * <p>Outputs: manifest.json (exact signed bytes) + manifest.sig (ECDSA-P384 DER).
 *
 * <pre>
 * # sign a manifest allowing two enclave images during a rotation window:
 * java -jar manifest-tool.jar --key-id alias/rng-enclave-signer --region ap-southeast-1 \
 *     --service rng-service --version 43 --valid-days 30 \
 *     --pcr0 &lt;hex48&gt; --pcr0 &lt;hex48-new&gt; --pcr8 &lt;hex48&gt;
 *
 * # export the pinned client trust anchor from the same key:
 * java -jar manifest-tool.jar --key-id alias/rng-enclave-signer --region ap-southeast-1 \
 *     --export-pubkey ../attestation/src/main/resources/release-pub.pem
 * </pre>
 * Creds via instance role / env / profile. Needs kms:GetPublicKey + kms:Sign.
 */
public final class ManifestSigner {

    private static final DateTimeFormatter RFC3339 =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC);

    public static void main(String[] args) throws Exception {
        Args a = Args.parse(args);
        if (a.keyId == null || a.region == null) {
            fail("--key-id and --region are required");
        }

        try (KmsClient kms = KmsClient.builder()
                .region(Region.of(a.region))
                .httpClient(UrlConnectionHttpClient.create())
                .build()) {

            if (a.exportPubkey != null) {
                exportPubkey(kms, a.keyId, a.exportPubkey);
                return;
            }
            if (a.version == null || a.pcr0.isEmpty() || a.pcr8.isEmpty()) {
                fail("signing a manifest needs --version, at least one --pcr0 and one --pcr8");
            }
            signManifest(kms, a);
        }
    }

    private static void exportPubkey(KmsClient kms, String keyId, String out) throws Exception {
        GetPublicKeyResponse pk = kms.getPublicKey(r -> r.keyId(keyId));
        byte[] spki = pk.publicKey().asByteArray(); // SubjectPublicKeyInfo DER
        String pem = "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(spki)
                + "\n-----END PUBLIC KEY-----\n";
        Files.writeString(Path.of(out), pem);
        System.out.println("wrote " + out + " (pin this in the client as release-pub.pem)");
    }

    private static void signManifest(KmsClient kms, Args a) throws Exception {
        for (String v : a.pcr0) requireHex48("pcr0", v);
        for (String v : a.pcr8) requireHex48("pcr8", v);

        String notAfter = RFC3339.format(Instant.now().plusSeconds(a.validDays * 86_400L));
        // Deterministic bytes — EXACTLY what we sign and what the client verifies.
        // Keys sorted: allowed_pcr0, allowed_pcr8, not_after, service, version.
        String json = "{"
                + "\"allowed_pcr0\":" + jsonArray(a.pcr0) + ","
                + "\"allowed_pcr8\":" + jsonArray(a.pcr8) + ","
                + "\"not_after\":\"" + notAfter + "\","
                + "\"service\":\"" + a.service + "\","
                + "\"version\":" + a.version
                + "}";
        byte[] blob = json.getBytes(StandardCharsets.UTF_8);

        SignResponse sr = kms.sign(b -> b.keyId(a.keyId)
                .message(SdkBytes.fromByteArray(blob))
                .messageType(MessageType.RAW)
                .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_384));
        byte[] sig = sr.signature().asByteArray(); // ASN.1/DER — what SHA384withECDSA expects

        Files.write(Path.of(a.out), blob);
        Files.write(Path.of(a.sigOut), sig);
        System.out.println("wrote " + a.out + " and " + a.sigOut);
        System.out.println("  service=" + a.service + " version=" + a.version + " not_after=" + notAfter);
        System.out.println("  allowed_pcr0=" + a.pcr0.size() + " allowed_pcr8=" + a.pcr8.size());
    }

    private static String jsonArray(List<String> hexes) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < hexes.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append('"').append(hexes.get(i).toLowerCase()).append('"');
        }
        return sb.append(']').toString();
    }

    private static void requireHex48(String tag, String v) {
        if (v.length() != 96 || !v.matches("[0-9a-fA-F]{96}")) {
            fail(tag + " '" + v + "' is not 96 hex chars (SHA-384)");
        }
    }

    private static void fail(String msg) {
        System.err.println("error: " + msg);
        System.exit(2);
    }

    /** Minimal flag parser mirroring the old sign-manifest.py CLI. */
    private static final class Args {
        String keyId, region, exportPubkey, service = "rng-service";
        Integer version;
        long validDays = 30;
        final List<String> pcr0 = new ArrayList<>();
        final List<String> pcr8 = new ArrayList<>();
        String out = "manifest.json";
        String sigOut = "manifest.sig";

        static Args parse(String[] args) {
            Args a = new Args();
            for (int i = 0; i < args.length; i++) {
                String k = args[i];
                switch (k) {
                    case "--key-id" -> a.keyId = next(args, ++i, k);
                    case "--region" -> a.region = next(args, ++i, k);
                    case "--export-pubkey" -> a.exportPubkey = next(args, ++i, k);
                    case "--service" -> a.service = next(args, ++i, k);
                    case "--version" -> a.version = Integer.parseInt(next(args, ++i, k));
                    case "--valid-days" -> a.validDays = Long.parseLong(next(args, ++i, k));
                    case "--pcr0" -> a.pcr0.add(next(args, ++i, k));
                    case "--pcr8" -> a.pcr8.add(next(args, ++i, k));
                    case "--out" -> a.out = next(args, ++i, k);
                    case "--sig-out" -> a.sigOut = next(args, ++i, k);
                    default -> fail("unknown arg: " + k);
                }
            }
            return a;
        }

        private static String next(String[] args, int i, String flag) {
            if (i >= args.length) {
                fail("missing value for " + flag);
            }
            return args[i];
        }
    }

    private ManifestSigner() {
    }
}
