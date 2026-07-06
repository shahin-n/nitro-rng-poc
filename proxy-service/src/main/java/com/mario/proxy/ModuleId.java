package com.mario.proxy;

import com.upokecenter.cbor.CBORObject;

/**
 * Pulls the PUBLIC {@code module_id} out of a COSE_Sign1 attestation document for
 * routing. Does NOT verify anything — that's the game's job. module_id is the
 * enclave instance id, not a secret, so reading it here keeps the proxy's
 * zero-trust posture intact.
 */
final class ModuleId {

    private ModuleId() {
    }

    static String extract(byte[] coseDoc) {
        CBORObject o = CBORObject.DecodeFromBytes(coseDoc);
        if (o.isTagged()) {
            o = o.UntagOne();
        }
        byte[] payload = o.get(2).GetByteString();        // COSE_Sign1[2] = payload
        CBORObject doc = CBORObject.DecodeFromBytes(payload);
        return doc.get("module_id").AsString();
    }
}
