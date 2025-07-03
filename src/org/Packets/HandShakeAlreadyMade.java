package org.Packets;

public class HandShakeAlreadyMade extends Packet {
    private final String initiator;
    private final String receiver;
    private final int keyId;
    private final byte[] oneTimeKey;

    // new fields:
    private final byte[] peerIdentityPub;
    private final byte[] peerSigningPub;

    public HandShakeAlreadyMade(
            String initiator,
            String receiver,
            int keyId,
            byte[] oneTimeKey,
            byte[] peerIdentityPub,
            byte[] peerSigningPub
    ) {
        this.initiator       = initiator;
        this.receiver        = receiver;
        this.keyId           = keyId;
        this.oneTimeKey      = oneTimeKey;
        this.peerIdentityPub = peerIdentityPub;
        this.peerSigningPub  = peerSigningPub;
    }

    public String getInitiator()           { return initiator; }
    public String getReceiver()            { return receiver; }
    public int    getKeyId()               { return keyId; }
    public byte[] getOneTimeKey()          { return oneTimeKey; }
    public byte[] getPeerIdentityPub()     { return peerIdentityPub; }
    public byte[] getPeerSigningPub()      { return peerSigningPub; }

    @Override
    public String getType() {
        return "HandShakeAlreadyMade";
    }
}
