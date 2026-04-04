package org.Client;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class Utils {

    public static PrivateKey loadX25519PrivateKey(String password, String filename) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(filename));
        ByteBuffer buf = ByteBuffer.wrap(data);

        byte[] salt = new byte[16]; buf.get(salt);
        byte[] iv   = new byte[16]; buf.get(iv);
        byte[] cipherText = new byte[buf.remaining()]; buf.get(cipherText);

        // derive AES key
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = f.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

        // decrypt
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] pkcs8 = c.doFinal(cipherText);

        // parse as X25519 private
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8);
        return KeyFactory.getInstance("X25519").generatePrivate(keySpec);
    }

    public static DoubleRatchetState loadRatchetStateEncrypted(
            String password, String filename
    ) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(filename));
        ByteBuffer buf = ByteBuffer.wrap(data);
        byte[] salt = new byte[16]; buf.get(salt);
        byte[] iv   = new byte[16]; buf.get(iv);
        byte[] cipherText = new byte[buf.remaining()]; buf.get(cipherText);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = f.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] plain = cipher.doFinal(cipherText);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(plain))) {
            return (DoubleRatchetState) ois.readObject();
        }
    }

    public static void saveRatchetStateEncrypted(
            DoubleRatchetState state, String password, String filename
    ) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(state);
        }
        byte[] plain = baos.toByteArray();
        byte[] salt = new byte[16]; new SecureRandom().nextBytes(salt);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = f.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
        byte[] ciphertext = cipher.doFinal(plain);
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(salt); fos.write(iv); fos.write(ciphertext);
        }
    }

    public static byte[] hkdf(byte[] salt, byte[] ikm, byte[] info, int length)
            throws GeneralSecurityException {
        byte[] prk = hkdfExtract(salt, ikm);
        return hkdfExpand(prk, info, length);
    }

    public static byte[] hkdfExpand(byte[] prk, byte[] info, int length) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        byte[] okm = new byte[length], t = new byte[0];
        int copied = 0; byte counter = 1;
        while (copied < length) {
            mac.reset();
            mac.update(t);
            if (info != null) mac.update(info);
            mac.update(counter++);
            t = mac.doFinal();
            int toCopy = Math.min(t.length, length - copied);
            System.arraycopy(t, 0, okm, copied, toCopy);
            copied += toCopy;
        }
        return okm;
    }

    private static byte[] hkdfExtract(byte[] salt, byte[] ikm) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt != null ? salt : new byte[32], "HmacSHA256"));
        return mac.doFinal(ikm);
    }

    public static PublicKey derivePublicKey(PrivateKey priv) throws Exception {
        RSAPrivateCrtKey crt = (RSAPrivateCrtKey) priv;
        RSAPublicKeySpec spec = new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent());
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    public static PublicKey bytesToX25519Pub(byte[] raw) throws GeneralSecurityException {
        return KeyFactory.getInstance("X25519")
                .generatePublic(new X509EncodedKeySpec(raw));
    }

    public static byte[] x25519(PrivateKey sk, PublicKey pk) throws GeneralSecurityException {
        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(sk);
        ka.doPhase(pk, true);
        return ka.generateSecret();
    }

    public static List<KeyPair> loadOneTimeKeyPairsEncrypted(
            String password,
            String filename
    ) throws Exception {
        // 1) read file → salt | iv | ciphertext
        byte[] file = Files.readAllBytes(Paths.get(filename));
        ByteBuffer buf = ByteBuffer.wrap(file);

        byte[] salt = new byte[16];
        buf.get(salt);

        byte[] iv = new byte[16];
        buf.get(iv);

        byte[] cipherText = new byte[buf.remaining()];
        buf.get(cipherText);

        // 2) derive AES key
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65_536, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

        // 3) decrypt
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] plain = cipher.doFinal(cipherText);

        // 4) split & rebuild all pairs
        String text = new String(plain, StandardCharsets.UTF_8).trim();
        String[] lines = text.split("\\R");

        Base64.Decoder b64 = Base64.getDecoder();
        KeyFactory kf = KeyFactory.getInstance("X25519");
        List<KeyPair> pairs = new ArrayList<>();

        for (int i = 0; i < lines.length; i += 2) {
            // pub
            String pubB64  = lines[i].split(":", 2)[1].trim();
            byte[] pubBytes = b64.decode(pubB64);
            PublicKey pubKey = kf.generatePublic(new X509EncodedKeySpec(pubBytes));

            // priv
            String privB64 = lines[i+1].split(":", 2)[1].trim();
            byte[] privBytes = b64.decode(privB64);
            PrivateKey privKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privBytes));

            pairs.add(new KeyPair(pubKey, privKey));
        }

        return pairs;
    }

    public static KeyPair loadOneTimeKeyPairEncrypted(
            String password,
            String filename,
            int pairNumber
    ) throws Exception {
        // 1) read file → salt | iv | ciphertext
        byte[] file = Files.readAllBytes(Paths.get(filename));
        ByteBuffer buf = ByteBuffer.wrap(file);

        byte[] salt = new byte[16];
        buf.get(salt);

        byte[] iv = new byte[16];
        buf.get(iv);

        byte[] cipherText = new byte[buf.remaining()];
        buf.get(cipherText);

        // 2) derive AES key from password + salt
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65_536, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

        // 3) decrypt
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] plain = cipher.doFinal(cipherText);

        // 4) split into lines
        String text = new String(plain, StandardCharsets.UTF_8).trim();
        String[] lines = text.split("\\R");  // split on any line break

        // 5) locate the two lines for this pair
        //    each pair i occupies lines[(i-1)*2] (pub) and [(i-1)*2 + 1] (priv)
        int pubLineIndex  = (pairNumber - 1) * 2;
        int privLineIndex = pubLineIndex + 1;

        if (pubLineIndex < 0 || privLineIndex >= lines.length) {
            throw new IllegalArgumentException(
                    "Requested pairNumber=" + pairNumber +
                            " is out of range; only " + (lines.length/2) + " pairs available."
            );
        }

        // 6) extract Base64 payload after the colon
        Base64.Decoder b64 = Base64.getDecoder();
        String pubB64  = lines[pubLineIndex].split(":", 2)[1].trim();
        String privB64 = lines[privLineIndex].split(":", 2)[1].trim();

        byte[] pubBytes  = b64.decode(pubB64);
        byte[] privBytes = b64.decode(privB64);

        // 7) rebuild X25519 key objects
        KeyFactory kf = KeyFactory.getInstance("X25519");
        PublicKey pubKey = kf.generatePublic(new X509EncodedKeySpec(pubBytes));
        PrivateKey privKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privBytes));

        return new KeyPair(pubKey, privKey);
    }

    public static PublicKey loadOneTimeX25519PublicKeyEncrypted(
            String filename,
            String password,
            int keyIndex
    ) throws Exception {
        if ((keyIndex & 1) == 0) {
            throw new IllegalArgumentException("X25519 loader only returns public keys; choose an odd index");
        }

        // 1) Read salt + iv + ciphertext
        byte[] salt = new byte[16];
        byte[] iv   = new byte[16];
        byte[] ciphertext;
        try (FileInputStream fis = new FileInputStream(filename)) {
            if (fis.read(salt)   != salt.length)   throw new IOException("Could not read salt");
            if (fis.read(iv)     != iv.length)     throw new IOException("Could not read IV");
            ciphertext = fis.readAllBytes();
        }

        // 2) Re-derive AES key with PBKDF2-HMAC-SHA256
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65_536, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

        // 3) Decrypt with AES/CBC/PKCS5Padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] plain = cipher.doFinal(ciphertext);

        // 4) Parse lines "index: Base64" → map
        String content = new String(plain, StandardCharsets.UTF_8);
        String[] lines = content.split("\\R");
        Base64.Decoder b64 = Base64.getDecoder();
        Map<Integer, byte[]> map = new HashMap<>();
        for (String line : lines) {
            if (line.isBlank()) continue;
            String[] parts = line.split(":", 2);
            int idx = Integer.parseInt(parts[0].trim());
            map.put(idx, b64.decode(parts[1].trim()));
        }

        // 5) Decode your chosen public key
        byte[] keyDer = map.get(keyIndex);
        if (keyDer == null) {
            throw new IllegalArgumentException("No key at index " + keyIndex);
        }

        // 6) Rebuild X25519 public key
        KeyFactory kf = KeyFactory.getInstance("X25519");
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(keyDer);
        return kf.generatePublic(pubSpec);
    }

    public static void saveOneTimeKeysEncrypted(
            List<KeyPair> keyPairs,
            String password,
            String filename
    ) throws Exception {
        // 1) Build a textual "1: key" listing, Base64-encoding each key
        StringBuilder sb = new StringBuilder();
        int index = 1;
        Base64.Encoder b64 = Base64.getEncoder();
        for (KeyPair kp : keyPairs) {
            // public key
            String pubB64 = b64.encodeToString(kp.getPublic().getEncoded());
            sb.append(index++)
                    .append(": ")
                    .append(pubB64)
                    .append(System.lineSeparator());

            // private key
            String privB64 = b64.encodeToString(kp.getPrivate().getEncoded());
            sb.append(index++)
                    .append(": ")
                    .append(privB64)
                    .append(System.lineSeparator());
        }
        byte[] plain = sb.toString().getBytes(StandardCharsets.UTF_8);

        // 2) Derive a salt and AES key from the password
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65_536, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

        // 3) Encrypt with AES/CBC/PKCS5Padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = cipher.getParameters()
                .getParameterSpec(IvParameterSpec.class)
                .getIV();
        byte[] ciphertext = cipher.doFinal(plain);

        // 4) Write out: [salt][iv][ciphertext]
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(salt);
            fos.write(iv);
            fos.write(ciphertext);
        }
    }

    public static PrivateKey loadPrivateKeyFromFile(String password, String filename) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(filename));
        ByteBuffer buf = ByteBuffer.wrap(data);
        byte[] salt = new byte[16]; buf.get(salt);
        byte[] iv   = new byte[16]; buf.get(iv);
        byte[] cipherText = new byte[buf.remaining()]; buf.get(cipherText);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = f.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] pkcs8 = c.doFinal(cipherText);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    public static void savePrivateKeyEncrypted(PrivateKey priv, String password, String filename) throws Exception {
        byte[] pkcs8 = priv.getEncoded();
        byte[] salt = new byte[16]; new SecureRandom().nextBytes(salt);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = f.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = c.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
        byte[] cipherText = c.doFinal(pkcs8);
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(salt); fos.write(iv); fos.write(cipherText);
        }
    }



}
