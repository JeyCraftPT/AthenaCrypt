package org.Keys;

import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;

public class RSAKeys {
    private static final String ALGORITHM = "RSA";
    private static KeyPair cachedKeyPair;

    // Generate RSA Key Pair
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM); // Fixed line
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair getKeyPair() throws NoSuchAlgorithmException {
        if (cachedKeyPair == null) {
            cachedKeyPair = generateKeyPair(); // Generate once and reuse
        }
        return cachedKeyPair;
    }


    public static byte[] getKeyBytes(PrivateKey key) {
        return key.getEncoded();
    }

    // Encrypt using RSA public key
    // Encrypt byte array using RSA public key
    public static byte[] encrypt(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data); // Encrypts byte array
    }

    // Decrypt a byte array using RSA private key
    public static byte[] decrypt(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data); // Decrypts byte array
    }

}
