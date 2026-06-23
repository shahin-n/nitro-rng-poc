package com.mario.attestation;

import com.upokecenter.cbor.CBORObject;

/**
 * Minimal COSE_Sign1 (RFC 8152) reader.
 *
 * <p>Structure: {@code [ protected: bstr, unprotected: map, payload: bstr, signature: bstr ]},
 * optionally wrapped in CBOR tag 18.
 */
public final class CoseSign1 {

    public final byte[] protectedHeader; // serialized bstr
    public final byte[] payload;
    public final byte[] signature;       // raw r||s (P-384 -> 96 bytes)

    private CoseSign1(byte[] protectedHeader, byte[] payload, byte[] signature) {
        this.protectedHeader = protectedHeader;
        this.payload = payload;
        this.signature = signature;
    }

    public static CoseSign1 parse(byte[] cose) {
        CBORObject o = CBORObject.DecodeFromBytes(cose);
        if (o.isTagged()) {
            o = o.UntagOne();
        }
        if (o.getType() != com.upokecenter.cbor.CBORType.Array || o.size() != 4) {
            throw new IllegalArgumentException("not a COSE_Sign1 array");
        }
        return new CoseSign1(
                o.get(0).GetByteString(),
                o.get(2).GetByteString(),
                o.get(3).GetByteString());
    }

    /**
     * Sig_structure to be verified:
     * {@code [ "Signature1", protected, external_aad(empty), payload ]} CBOR-encoded.
     */
    public byte[] sigStructure() {
        CBORObject sig = CBORObject.NewArray();
        sig.Add(CBORObject.FromObject("Signature1"));
        sig.Add(CBORObject.FromObject(protectedHeader));
        sig.Add(CBORObject.FromObject(new byte[0]));
        sig.Add(CBORObject.FromObject(payload));
        return sig.EncodeToBytes();
    }
}
