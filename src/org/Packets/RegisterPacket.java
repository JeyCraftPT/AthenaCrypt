// src/org/Packets/RegisterPacket.java
package org.Packets;

import java.io.Serializable;

public class RegisterPacket extends Packet implements Serializable {
    private static final long serialVersionUID = 1L;

    private final String username;
    private final String password;
    private final byte[] publicKeyBytes;

    public RegisterPacket(String username, String password, byte[] publicKeyBytes) {
        this.username        = username;
        this.password        = password;
        this.publicKeyBytes  = publicKeyBytes;
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

    @Override
    public String getType() {
        return "Register";
    }
}
