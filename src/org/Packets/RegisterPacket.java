package org.Packets;

public class RegisterPacket extends Packet {
    private final String username;
    private final byte[] password;
    private final byte[] rsaIdentityPub;     // RSA identity key (for signing)
    private final byte[] x25519IdentityPub;  // X25519 identity key (for DH)
    private final byte[] x25519SigningPub;   // X25519 signed-prekey (for DH)
    private final byte[] signature;          // RSA-signature over x25519SigningPub

    public RegisterPacket(String username,
                          byte[] password,
                          byte[] rsaIdentityPub,
                          byte[] x25519IdentityPub,
                          byte[] x25519SigningPub,
                          byte[] signature)
    {
        this.username           = username;
        this.password           = password;
        this.rsaIdentityPub     = rsaIdentityPub;
        this.x25519IdentityPub  = x25519IdentityPub;
        this.x25519SigningPub   = x25519SigningPub;
        this.signature          = signature;
    }

    public String getUsername()              { return username;           }
    public byte[] getPassword()              { return password;           }
    public byte[] getRsaIdentityPub()        { return rsaIdentityPub;     }
    public byte[] getX25519IdentityPub()     { return x25519IdentityPub;  }
    public byte[] getX25519SigningPub()      { return x25519SigningPub;   }
    public byte[] getSignature()             { return signature;          }

    @Override
    public String getType() {
        return "Register";
    }
}