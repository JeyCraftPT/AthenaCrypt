package org.Handler;

import java.io.Serializable;

public class EncryptedMessage implements Serializable {
    private final byte[] encryptedContent;
    private final byte[] encryptedSessionKey;
    private final MessageType type; // Changed to MessageType directly

    public EncryptedMessage(byte[] encryptedContent, byte[] encryptedSessionKey, MessageType type) {
        this.encryptedContent = encryptedContent;
        this.encryptedSessionKey = encryptedSessionKey;
        this.type = type; // Accept MessageType directly
    }

    public byte[] getEncryptedContent() {
        return encryptedContent;
    }

    public byte[] getEncryptedSessionKey() {
        return encryptedSessionKey;
    }

    public MessageType getType() {
        return type;
    }
}
