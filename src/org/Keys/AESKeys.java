package org.Keys;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESKeys {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    // Generate a new AES session key
    public static SecretKey generateSessionKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(256, new SecureRandom());
        return keyGen.generateKey();
    }

    // Convert a SecretKey to a byte array
    public static byte[] getKeyBytes(SecretKey key) {
        return key.getEncoded();
    }

    // Convert a byte array to a SecretKey
    public static SecretKey getKeyFromBytes(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    // Generate a random 16-byte IV
    public static IvParameterSpec generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    // Encrypt with AES key
    public static String encrypt(byte[] data, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encrypted = cipher.doFinal(data);

        return Base64.getEncoder().encodeToString(iv.getIV()) + ":" + Base64.getEncoder().encodeToString(encrypted);
    }

    // Decrypt with AES key
    /*public static byte[] decrypt(String encryptedData, SecretKey key) throws Exception {
        String[] parts = encryptedData.split(":");
        if (parts.length != 2) throw new IllegalArgumentException("Invalid encrypted data format");

        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] cipherText = Base64.getDecoder().decode(parts[1]);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(cipherText);
    }*/
    public static byte[] decrypt(String encryptedData, SecretKey key) throws Exception {
        /*String[] parts = encryptedData.split(":");
        if (parts.length != 2) throw new IllegalArgumentException("Invalid encrypted data format");

        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] cipherText = Base64.getDecoder().decode(parts[1]);*/
        byte[] cipherText = Base64.getDecoder().decode(encryptedData);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        /*cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));*/
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(cipherText);
    }
}
