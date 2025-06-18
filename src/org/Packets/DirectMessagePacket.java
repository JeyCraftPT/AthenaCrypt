// src/org/Packets/DirectMessagePacket.java
package org.Packets;

import java.io.Serializable;

public class DirectMessagePacket extends Packet implements Serializable {
    private final String recipient;
    private final String message;

    public DirectMessagePacket(String recipient, String message) {
        this.recipient = recipient;
        this.message   = message;
    }

    public String getRecipient() { return recipient; }
    public String getMessage()   { return message; }

    @Override
    public String getType() {
        return "DirectMessage";
    }
}
