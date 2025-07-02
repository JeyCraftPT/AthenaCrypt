package org.Packets;

import java.io.Serializable;

/**
 * Signals the start of the symmetric Double Ratchet.
 */
public class HandshakeInitPacket extends Packet implements Serializable {
    private static final long serialVersionUID = 1L;
    private final String sender;
    private final String receiver;
    private final byte[] headerPub;  // sender’s new DH public key

    public HandshakeInitPacket(String sender, String receiver, byte[] headerPub) {
        this.sender = sender;
        this.receiver = receiver;
        this.headerPub = headerPub.clone();
    }

    public String getSender() {
        return sender;
    }

    public String getReceiver() {
        return receiver;
    }

    public byte[] getHeaderPub() {
        return headerPub.clone();
    }

    @Override
    public String getType() {
        return "HandshakeInit";
    }
}
