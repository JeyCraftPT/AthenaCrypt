package org.Packets;

import java.io.Serializable;

/**
 * Acknowledges and completes the symmetric handshake.
 */
public class HandshakeAckPacket extends Packet implements Serializable {
    private static final long serialVersionUID = 1L;
    private final String sender;
    private final String receiver;
    private final byte[] headerPub;  // sender’s new DH public key

    public HandshakeAckPacket(String sender, String receiver, byte[] headerPub) {
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
        return "HandshakeAck";
    }
}
