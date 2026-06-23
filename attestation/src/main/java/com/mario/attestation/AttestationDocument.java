package com.mario.attestation;

import com.upokecenter.cbor.CBORObject;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Parsed Nitro attestation document (the CBOR map inside the COSE_Sign1 payload).
 *
 * <pre>
 * { module_id, timestamp, digest:"SHA384",
 *   pcrs: { 0,1,2,3,4,8 -> bstr },
 *   certificate,            // hypervisor leaf cert (DER)
 *   cabundle: [...],        // chain to AWS Nitro root
 *   public_key,             // enclave enc_pub (X25519, 32 bytes)
 *   user_data,              // enclave sign_pub (ECDSA P-384, X.509 DER)
 *   nonce }                 // caller client_nonce
 * </pre>
 */
public final class AttestationDocument {

    public final String moduleId;
    public final long timestamp;
    public final String digest;
    public final Map<Integer, byte[]> pcrs;
    public final byte[] certificate;       // leaf cert DER
    public final byte[][] cabundle;        // intermediate/root DERs
    public final byte[] publicKey;         // enc_pub
    public final byte[] userData;          // sign_pub
    public final byte[] nonce;

    private AttestationDocument(String moduleId, long timestamp, String digest,
                               Map<Integer, byte[]> pcrs, byte[] certificate, byte[][] cabundle,
                               byte[] publicKey, byte[] userData, byte[] nonce) {
        this.moduleId = moduleId;
        this.timestamp = timestamp;
        this.digest = digest;
        this.pcrs = pcrs;
        this.certificate = certificate;
        this.cabundle = cabundle;
        this.publicKey = publicKey;
        this.userData = userData;
        this.nonce = nonce;
    }

    public byte[] pcr(int i) {
        return pcrs.get(i);
    }

    /** Parse the CBOR payload bytes of the COSE_Sign1 into a document. */
    public static AttestationDocument parse(byte[] payload) {
        CBORObject m = CBORObject.DecodeFromBytes(payload);

        Map<Integer, byte[]> pcrs = new LinkedHashMap<>();
        CBORObject pcrMap = m.get("pcrs");
        for (CBORObject k : pcrMap.getKeys()) {
            pcrs.put(k.AsInt32(), pcrMap.get(k).GetByteString());
        }

        CBORObject ca = m.get("cabundle");
        byte[][] cabundle = new byte[ca.size()][];
        for (int i = 0; i < ca.size(); i++) {
            cabundle[i] = ca.get(i).GetByteString();
        }

        return new AttestationDocument(
                m.get("module_id").AsString(),
                m.get("timestamp").AsInt64Value(),
                m.get("digest").AsString(),
                pcrs,
                m.get("certificate").GetByteString(),
                cabundle,
                bytesOrNull(m, "public_key"),
                bytesOrNull(m, "user_data"),
                bytesOrNull(m, "nonce"));
    }

    private static byte[] bytesOrNull(CBORObject m, String key) {
        CBORObject v = m.get(key);
        return (v == null || v.isNull()) ? null : v.GetByteString();
    }
}
