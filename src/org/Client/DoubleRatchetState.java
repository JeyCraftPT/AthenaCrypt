package org.Client;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Double Ratchet State with ratchet steps, message key derivation,
 * and AES-GCM encrypt/decrypt. Uses separate DH private/public.
 */
public class DoubleRatchetState implements Serializable {
    private static final long serialVersionUID = 1L;
    private byte[] rootKey;
    private PrivateKey dhPrivate;   // our current DH private key
    private PublicKey  dhTheirPub;  // their current DH public key
    private byte[] sendChainKey;
    private byte[] recvChainKey;

    public static class Message {
        public final byte[] headerPub; // our ephemeral DH pub for this msg
        public final byte[] iv;        // AES-GCM IV
        public final byte[] ciphertext;
        public Message(byte[] headerPub, byte[] iv, byte[] ciphertext) {
            this.headerPub = headerPub;
            this.iv = iv;
            this.ciphertext = ciphertext;
        }
    }

    public DoubleRatchetState(
            byte[]     rootKey,
            PrivateKey dhPrivate,
            PublicKey  dhTheirPub,
            byte[]     sendChainKey,
            byte[]     recvChainKey
    ) {
        this.rootKey      = Arrays.copyOf(rootKey,      rootKey.length);
        this.dhPrivate    = dhPrivate;
        this.dhTheirPub   = dhTheirPub;
        this.sendChainKey = Arrays.copyOf(sendChainKey, sendChainKey.length);
        this.recvChainKey = Arrays.copyOf(recvChainKey, recvChainKey.length);
    }

    // getters
    public byte[]     getRootKey()      { return Arrays.copyOf(rootKey, rootKey.length); }
    public PrivateKey getDhPrivate()    { return dhPrivate; }
    public PublicKey  getDhTheirPub()   { return dhTheirPub; }
    public byte[]     getSendChainKey() { return Arrays.copyOf(sendChainKey, sendChainKey.length); }
    public byte[]     getRecvChainKey() { return Arrays.copyOf(recvChainKey, recvChainKey.length); }

    /**
     * Perform a receive ratchet when a new DH public arrives.
     */
    public void ratchetReceive(PublicKey theirNewPub) throws GeneralSecurityException {
        byte[] dh = dhAgreement(dhPrivate, theirNewPub);
        byte[] combined = hkdf(rootKey, dh, "Ratchet".getBytes(), 64);
        rootKey      = Arrays.copyOfRange(combined, 0, 32);
        recvChainKey = Arrays.copyOfRange(combined, 32, 48);
        sendChainKey = Arrays.copyOfRange(combined, 48, 64);
        dhTheirPub = theirNewPub;
    }

    /**
     * Perform a send ratchet by generating a fresh DH keypair.
     */
    public void ratchetSend() throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
        KeyPair newKP = kpg.generateKeyPair();
        byte[] dh = dhAgreement(newKP.getPrivate(), dhTheirPub);
        byte[] combined = hkdf(rootKey, dh, "Ratchet".getBytes(), 64);
        rootKey      = Arrays.copyOfRange(combined, 0, 32);
        sendChainKey = Arrays.copyOfRange(combined, 32, 48);
        recvChainKey = Arrays.copyOfRange(combined, 48, 64);
        dhPrivate = newKP.getPrivate();
    }

    private byte[] nextSendMessageKey() throws GeneralSecurityException {
        byte[] mk = hmacSha256(sendChainKey, new byte[]{0x01});
        sendChainKey = hmacSha256(sendChainKey, new byte[]{0x02});
        return mk;
    }

    private byte[] nextRecvMessageKey() throws GeneralSecurityException {
        byte[] mk = hmacSha256(recvChainKey, new byte[]{0x01});
        recvChainKey = hmacSha256(recvChainKey, new byte[]{0x02});
        return mk;
    }

    public Message encrypt(byte[] plaintext) throws GeneralSecurityException {
        ratchetSend();
        byte[] msgKey = nextSendMessageKey();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12]; new SecureRandom().nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        SecretKeySpec kspec = new SecretKeySpec(msgKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, kspec, spec);
        byte[] ct = cipher.doFinal(plaintext);
        byte[] header = dhPrivate.getEncoded();
        return new Message(header, iv, ct);
    }

    public byte[] decrypt(Message msg) throws GeneralSecurityException {
        PublicKey theirPub = KeyFactory.getInstance("X25519")
                .generatePublic(new X509EncodedKeySpec(msg.headerPub));
        if (!theirPub.equals(dhTheirPub)) ratchetReceive(theirPub);
        byte[] msgKey = nextRecvMessageKey();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, msg.iv);
        SecretKeySpec kspec = new SecretKeySpec(msgKey, "AES");
        cipher.init(Cipher.DECRYPT_MODE, kspec, spec);
        return cipher.doFinal(msg.ciphertext);
    }

    private static byte[] dhAgreement(PrivateKey sk, PublicKey pk) throws GeneralSecurityException {
        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(sk);
        ka.doPhase(pk, true);
        return ka.generateSecret();
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }

    private static byte[] hkdf(byte[] salt, byte[] ikm, byte[] info, int length)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt != null ? salt : new byte[32], "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);
        byte[] okm = new byte[length], t = new byte[0];
        int copied = 0; byte ctr = 1;
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        while (copied < length) {
            mac.reset(); mac.update(t);
            if (info != null) mac.update(info);
            mac.update(ctr++);
            t = mac.doFinal();
            int toCopy = Math.min(t.length, length - copied);
            System.arraycopy(t, 0, okm, copied, toCopy);
            copied += toCopy;
        }
        return okm;
    }
}
