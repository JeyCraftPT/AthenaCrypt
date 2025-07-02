package org.Packets;

public class KeyBundle extends Packet {
    // RSA identity‐key (for verifying SPK signatures)
    private final byte[] rsaIdentityPub;
    // X25519 identity‐key (for X3DH IK_A)
    private final byte[] x25519IdentityPub;
    // X25519 signed‐prekey (for X3DH SPK_B)
    private final byte[] x25519SigningPub;
    // RSA signature over x25519SigningPub
    private final byte[] signature;
    // One-time X25519 key (for X3DH OPK_B)
    private final byte[] oneTimeKey;

    public KeyBundle(byte[] rsaIdentityPub,
                     byte[] x25519IdentityPub,
                     byte[] x25519SigningPub,
                     byte[] signature,
                     byte[] oneTimeKey)
    {
        this.rsaIdentityPub    = rsaIdentityPub;
        this.x25519IdentityPub = x25519IdentityPub;
        this.x25519SigningPub  = x25519SigningPub;
        this.signature         = signature;
        this.oneTimeKey        = oneTimeKey;
    }

    public byte[] getRsaIdentityPub()    { return rsaIdentityPub;    }
    public byte[] getX25519IdentityPub() { return x25519IdentityPub; }
    public byte[] getX25519SigningPub()  { return x25519SigningPub;  }
    public byte[] getSignature()         { return signature;         }
    public byte[] getOneTimeKey()        { return oneTimeKey;        }

    @Override
    public String getType() {
        return "KeyBundle";
    }
}