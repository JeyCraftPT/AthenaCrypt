package org.Packets;

import java.security.PublicKey;

public class AESRequest extends Packet {

    private final String sender;
    private final String reciver;
    private final PublicKey senderPub;

    public AESRequest(String sender, String reciver , PublicKey senderPub) {
        this.sender = sender;
        this.reciver = reciver;
        this.senderPub = senderPub;
    }

    public String getSender() { return sender; }
    public String getReciver() { return reciver; }
    public PublicKey getSenderPub() { return senderPub; }

    @Override
    public String getType() {
        return "AesRequest";
    }
}
