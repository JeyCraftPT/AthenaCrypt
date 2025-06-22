package org.Packets;

import javax.crypto.SecretKey;
import java.security.PublicKey;

public class AESAnswer_Cena extends Packet {
    private String sender;
    private String recipient;
    private PublicKey publicKey;
    private byte[] secretKey;

    public AESAnswer_Cena(String sender, String recipient, PublicKey publicKey, byte[] secretKey ) {
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
