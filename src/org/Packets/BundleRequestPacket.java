package org.Packets;

public class BundleRequestPacket extends Packet {
    private final String sender;
    private final String receiver;

    public BundleRequestPacket(String sender, String receiver) {
        this.sender = sender;
        this.receiver = receiver;
    }

    public String getSender() {
        return sender;
    }
    public String getReceiver() {
        return receiver;
    }

    @Override
    public String getType(){
        return "BundleRequest";
    }
}
