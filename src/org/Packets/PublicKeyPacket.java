package org.Packets;

import java.io.Serializable;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class PublicKeyPacket extends Packet implements Serializable {
    private final byte[] publicKeyBytes;

    public PublicKeyPacket(byte[] publicKeyBytes) {
        this.publicKeyBytes = publicKeyBytes;
    }

    public byte[] getPublicKeyBytes() {
        return publicKeyBytes;
    }

    /**
     * Reconstructs and returns the PublicKey object from the stored byte array.
     * @return PublicKey object
     * @throws Exception if reconstruction fails
     */
    public PublicKey getPublicKey() throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    @Override
    public String getType() {
        return "PublicKey";
    }
}
