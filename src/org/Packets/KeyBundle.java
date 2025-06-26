package org.Packets;

public class KeyBundle extends Packet {


    public final byte[] identityPub;   // client_IPKey
    public final byte[] signingPub;    // client_SPKey
    public final byte[] signature;
    public final byte[] oneTimeKey;    // one of the client_one_time_keys

    public KeyBundle(byte[] identityPub, byte[] signingPub, byte[] signature , byte[] oneTimeKey) {
        this.identityPub = identityPub;
        this.signingPub  = signingPub;
        this.signature = signature;
        this.oneTimeKey  = oneTimeKey;
    }

    public byte[] getIdentityPub() {
        return identityPub;
    }
    public byte[] getSigningPub() {
        return signingPub;
    }
    public byte[] getSignature() {
        return signature;
    }
    public byte[] getOneTimeKey() {
        return oneTimeKey;
    }

    @Override
    public String getType(){
        return "KeyBundle";
    }
}
