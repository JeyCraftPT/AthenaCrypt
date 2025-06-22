package org.Packets;

import javax.crypto.SecretKey;
import java.io.Serializable;

public class AESAnswer extends Packet {

    private String recipient;
    private SecretKey secretKey;

    public AESAnswer(String recipient, SecretKey secretKey) {
        this.recipient = recipient;
        this.secretKey = secretKey;
    }

    public String getRecipient() {
        return recipient;
    }
    public SecretKey getSecretKey() {
        return secretKey;
    }

    @Override
    public String getType() {
        return "AesAnswer";
    }
}
