package org.Packets;

public class MessagePacket extends Packet {
    private String message;

    public MessagePacket(String message) {
        this.message = message;
    }

    public String getMessage() { return message; }

    @Override
    public String getType() {
        return "Message";
    }
}
