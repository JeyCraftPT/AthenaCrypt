package org.Packets;

import java.io.Serializable;

public class DirectMessagePacket extends Packet implements Serializable {
    private final String recipient;
    private final String message;
    private final String sender;

    public DirectMessagePacket(String recipient, String message, String sender) {
        this.recipient = recipient;
        this.message   = message;
        this.sender = sender;
    }

    public String getRecipient() { return recipient; }
    public String getMessage()   { return message; }
    public String getSender()   { return sender; }

    @Override
    public String getType() {
        return "DirectMessage";
    }
}
