package com.mario.attestation;

import com.upokecenter.cbor.CBORObject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/**
 * A release-signed allow-list of enclave measurements — the production
 * {@link PcrPolicy}. A client fetches the raw {@code manifest_json} + detached
 * {@code signature} (over an untrusted transport, e.g. the proxy), verifies the
 * signature under the pinned {@link ReleaseKey}, and only then trusts the PCR set.
 *
 * <p>Because the set holds MANY PCR0s, several enclave releases can be valid at
 * once — the overlap window that makes rotation zero-downtime for every client
 * with no client-side change.
 *
 * <p>Fail-closed: bad signature, wrong service, malformed JSON, or an expired
 * {@code not_after} all throw; a caller that gets a {@code PcrManifest} back holds
 * a verified, in-date policy.
 *
 * <p>JSON schema (the exact bytes that were signed):
 * <pre>{ "service":"rng-service", "version":42,
 *   "allowed_pcr0":["&lt;hex48&gt;",...], "allowed_pcr8":["&lt;hex48&gt;",...],
 *   "not_after":"2026-08-01T00:00:00Z" }</pre>
 */
public final class PcrManifest implements PcrPolicy {

    private static final Logger log = LoggerFactory.getLogger(PcrManifest.class);
    private static final HexFormat HEX = HexFormat.of();

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final String service;
    private final int version;
    private final Instant notAfter;
    private final List<byte[]> allowedPcr0;
    private final List<byte[]> allowedPcr8;

    private PcrManifest(String service, int version, Instant notAfter,
                        List<byte[]> allowedPcr0, List<byte[]> allowedPcr8) {
        this.service = service;
        this.version = version;
        this.notAfter = notAfter;
        this.allowedPcr0 = allowedPcr0;
        this.allowedPcr8 = allowedPcr8;
    }

    public int version() {
        return version;
    }

    public Instant notAfter() {
        return notAfter;
    }

    public String service() {
        return service;
    }

    /**
     * Verify the detached signature over {@code manifestJson} (exactly as received —
     * no re-serialization) under {@code releaseKey}, parse, and return the policy.
     * Rejects a manifest whose {@code service} != {@code expectedService} or whose
     * {@code not_after} is already in the past.
     */
    public static PcrManifest verify(byte[] manifestJson, byte[] signature,
                                     PublicKey releaseKey, String expectedService) throws Exception {
        if (manifestJson == null || signature == null) {
            throw new SecurityException("manifest or signature missing");
        }
        // 1) signature over the RAW signed bytes, under the pinned release key
        Signature es384 = Signature.getInstance("SHA384withECDSA", BouncyCastleProvider.PROVIDER_NAME);
        es384.initVerify(releaseKey);
        es384.update(manifestJson);
        if (!es384.verify(signature)) {
            throw new SecurityException("PCR manifest signature invalid under pinned release key");
        }

        // 2) parse only after the signature is trusted
        CBORObject j = CBORObject.FromJSONString(new String(manifestJson, StandardCharsets.UTF_8));
        String service = j.get("service").AsString();
        if (!service.equals(expectedService)) {
            throw new SecurityException("manifest service '" + service + "' != expected '" + expectedService + "'");
        }
        int version = j.get("version").AsInt32();
        Instant notAfter = Instant.parse(j.get("not_after").AsString());
        if (Instant.now().isAfter(notAfter)) {
            throw new SecurityException("PCR manifest expired at " + notAfter + " (version " + version + ")");
        }

        List<byte[]> pcr0 = parsePcrArray(j, "allowed_pcr0");
        List<byte[]> pcr8 = parsePcrArray(j, "allowed_pcr8");
        if (pcr0.isEmpty() || pcr8.isEmpty()) {
            throw new SecurityException("manifest allows no PCR0 or no PCR8");
        }

        log.info("PCR manifest verified: service={} version={} not_after={} pcr0={} pcr8={}",
                service, version, notAfter, pcr0.size(), pcr8.size());
        return new PcrManifest(service, version, notAfter, pcr0, pcr8);
    }

    private static List<byte[]> parsePcrArray(CBORObject j, String field) {
        CBORObject arr = j.get(field);
        if (arr == null || arr.getType() != com.upokecenter.cbor.CBORType.Array) {
            throw new SecurityException("manifest field '" + field + "' missing or not an array");
        }
        List<byte[]> out = new ArrayList<>();
        for (CBORObject e : arr.getValues()) {
            byte[] pcr = HEX.parseHex(e.AsString());
            if (pcr.length != 48) {
                throw new SecurityException(field + " entry not 48 bytes (SHA-384)");
            }
            out.add(pcr);
        }
        return out;
    }

    @Override
    public boolean allowsPcr0(byte[] pcr0) {
        return contains(allowedPcr0, pcr0);
    }

    @Override
    public boolean allowsPcr8(byte[] pcr8) {
        return contains(allowedPcr8, pcr8);
    }

    /** Constant-time set membership: never short-circuits on a match. */
    private static boolean contains(List<byte[]> set, byte[] value) {
        if (value == null) {
            return false;
        }
        boolean found = false;
        for (byte[] allowed : set) {
            found |= MessageDigest.isEqual(allowed, value);
        }
        return found;
    }

    @Override
    public String describe() {
        return "PcrManifest{service=" + service + ", version=" + version
                + ", not_after=" + notAfter + ", pcr0=" + allowedPcr0.size()
                + ", pcr8=" + allowedPcr8.size() + "}";
    }
}
