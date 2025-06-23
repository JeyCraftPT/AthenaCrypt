package org.Packets;

import java.security.PublicKey;

public class AESAnswer extends Packet {
    private final String sender;
    private final String recipient;
    private final PublicKey publicKey;
    private final byte[] secretKey;

    public AESAnswer(String sender, String recipient, PublicKey publicKey, byte[] secretKey ) {
        this.sender = sender;
        this.recipient = recipient;
        this.publicKey = publicKey;
        this.secretKey = secretKey;
    }

    public String getSender() { return sender; }
    public String getRecipient() {return recipient;}
    public PublicKey getPublicKey() { return publicKey; }
    public byte[] getSecretKey() {return secretKey;}

    @Override
    public String getType() {
        return "AesAnswer_Cena";
    }
}
