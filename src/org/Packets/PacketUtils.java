package org.Packets;

import javax.crypto.Cipher;
import java.io.*;
import java.security.PrivateKey;
import java.security.PublicKey;

public class PacketUtils {

    public static byte[] encryptPacket(Packet packet, PublicKey key) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(packet);
        }

        byte[] plainBytes = bos.toByteArray();

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plainBytes);
    }

    public static Packet decryptPacket(byte[] encryptedData, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(encryptedData);

        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decryptedBytes))) {
            Object obj = ois.readObject();
            if (obj instanceof Packet packet) {
                return packet;
            } else {
                throw new IOException("Decrypted object is not a valid Packet.");
            }
        }
    }
}
