package org.Packets;

public class MadeHand extends Packet {
    private final String initiator;
    private final String peer;
    private final int keyId;
    private final byte[] ephKey;
    private final byte[] initiatorIdentityPub;
    private final byte[] initiatorSigningPub;

    /**
     * Represents a stored handshake initiation record.
     * @param initiator              the username of the initiator
     * @param peer                   the username of the peer/receiver
     * @param keyId                  the DB key_id for the initiator’s one-time key
     * @param ephKey                 the initiator’s ephemeral X25519 public key bytes
     * @param initiatorIdentityPub   the initiator’s X25519 identity public key bytes
     * @param initiatorSigningPub    the initiator’s X25519 signed-prekey public key bytes
     */
    public MadeHand(
            String initiator,
            String peer,
            int keyId,
            byte[] ephKey,
            byte[] initiatorIdentityPub,
            byte[] initiatorSigningPub
    ) {
        this.initiator = initiator;
        this.peer = peer;
        this.keyId = keyId;
        this.ephKey = ephKey;
        this.initiatorIdentityPub = initiatorIdentityPub;
        this.initiatorSigningPub = initiatorSigningPub;
    }

    public String getInitiator() {
        return initiator;
    }
    public String getPeer() {
        return peer;
    }
    public int getKeyId() {
        return keyId;
    }
    public byte[] getEphKey() {
        return ephKey;
    }

    /**
     * @return the initiator’s X25519 identity public key bytes
     */
    public byte[] getInitiatorIdentityPub() {
        return initiatorIdentityPub;
    }

    /**
     * @return the initiator’s X25519 signed-prekey public key bytes
     */
    public byte[] getInitiatorSigningPub() {
        return initiatorSigningPub;
    }

    @Override
    public String getType() {
        return "MadeHand";
    }
}
