// src/org/Packets/RegisterPacket.java
package org.Packets;

import java.io.Serializable;

public class RegisterPacket extends Packet implements Serializable {
    private static final long serialVersionUID = 1L;

    private final String username;
    private final String password;
    private final byte[] publicKeyBytes;
    private final byte[] signedPreKey;
    private final byte[] signature;

    public RegisterPacket(String username, String password, byte[] publicKeyBytes,  byte[] signedPreKey,  byte[] signature) {
        this.username        = username;
        this.password        = password;
        this.publicKeyBytes  = publicKeyBytes;
        this.signedPreKey    = signedPreKey;
        this.signature        = signature;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    /** Returns the raw RSA public-key bytes for DB storage. */
    public byte[] getPublicKeyBytes() {
        return publicKeyBytes;
    }
    public byte[] getSignedPreKey() {
        return signedPreKey;
    }

    public byte[] getSignature() {
        return signature;
    }

    @Override
    public String getType() {
        return "Register";
    }
}
