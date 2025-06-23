package org.Packets;

public class AESFinal extends Packet {
    private final String sender;
    private final String recipient;
    private final byte[] senderAES;

    public AESFinal(String sender, String recipient, byte[] senderAES) {
        this.sender = sender;
        this.recipient = recipient;
        this.senderAES = senderAES;
    }

    public String getSender() { return sender; }
    public String getRecipient() { return recipient; }
    public byte[] getSenderAES() { return senderAES; }

    @Override
    public String getType() {
        return "AESFinal";
    }
}
