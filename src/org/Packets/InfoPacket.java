package org.Packets;

import java.io.Serializable;

public class InfoPacket extends Packet implements Serializable {
    private final String message;

    public InfoPacket(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }

    @Override
    public String getType() {
        return "Info";
    }
}
