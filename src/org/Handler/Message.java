package org.Handler;

import java.io.Serializable;

public class Message implements Serializable {
    private final byte[] content;
    private final MessageType type;

    public Message(byte[] content, MessageType type) {
        this.content = content;
        this.type = type;
    }

    public byte[] getContent() {
        return content;
    }

    public MessageType getType() {
        return type;
    }
}