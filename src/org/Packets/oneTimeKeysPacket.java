package org.Packets;

public class oneTimeKeysPacket extends Packet {
    private final String user;
    private final byte[] publicKey;

    public oneTimeKeysPacket(String user, byte[] publicKey){
        this.user = user;
        this.publicKey = publicKey;
    }

    public String getUser() {
        return user;
    }
    public byte[] getPublicKey() {
        return publicKey;
    }

    @Override
    public String getType(){
        return "oneTimeKeysPacket";
    }
}
