package org.Packets;

/**
 * Carries a double-ratchet encrypted direct message.
 */
public class DirectMessagePacket extends Packet {
    private final String sender;
    private final String recipient;
    private final byte[] headerPub;
    private final byte[] iv;
    private final byte[] ciphertext;

    /**
     * @param sender      the username of the sender
     * @param recipient   the username of the recipient
     * @param headerPub   the sender's ephemeral DH public key bytes
     * @param iv          the AES-GCM IV bytes
     * @param ciphertext  the encrypted payload bytes
     */
    public DirectMessagePacket(String sender,
                               String recipient,
                               byte[] headerPub,
                               byte[] iv,
                               byte[] ciphertext) {
        this.sender = sender;
        this.recipient = recipient;
        this.headerPub = headerPub;
        this.iv = iv;
        this.ciphertext = ciphertext;
    }

    public String getSender() { return sender; }
    public String getRecipient() { return recipient; }
    public byte[] getHeaderPub() { return headerPub; }
    public byte[] getIv() { return iv; }
    public byte[] getCiphertext() { return ciphertext; }

    @Override
    public String getType() {
        return "DirectMessage";
    }
}
