package org.Packets;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

public class PacketUtils {

    // RSA-encrypt the one-off session key + IV
    public static byte[] encryptKeyPacket(byte[] keyPacket, PublicKey rsaPub) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsa.init(Cipher.ENCRYPT_MODE, rsaPub);
        return rsa.doFinal(keyPacket);
    }

    // RSA-decrypt the one-off session key + IV
    public static byte[] decryptKeyPacket(byte[] encKeyPkt, PrivateKey rsaPriv) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsa.init(Cipher.DECRYPT_MODE, rsaPriv);
        return rsa.doFinal(encKeyPkt);
    }

    // AES-encrypt any Packet after handshake
    public static byte[] encryptPacketAES(Packet pkt, SecretKey aesKey) throws Exception {
        // 1) serialize
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(pkt);
        }
        byte[] plain = baos.toByteArray();

        // 2) AES/CBC/PKCS5Padding with random IV
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        new java.security.SecureRandom().nextBytes(iv);
        aes.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] ciphertext = aes.doFinal(plain);

        // 3) Prepend IV to ciphertext
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(iv);
        out.write(ciphertext);
        return out.toByteArray();
    }

    // AES-decrypt any Packet after handshake
    public static Packet decryptPacketAES(byte[] blob, SecretKey aesKey) throws Exception {
        // 1) Extract IV (first 16 bytes)
        byte[] iv = new byte[16];
        System.arraycopy(blob, 0, iv, 0, 16);
        byte[] ciphertext = new byte[blob.length - 16];
        System.arraycopy(blob, 16, ciphertext, 0, ciphertext.length);

        // 2) Decrypt
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aes.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] plain = aes.doFinal(ciphertext);

        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(plain))) {
            return (Packet) ois.readObject();
        }
    }
}
