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
 * and AES-GCM encrypt/decrypt. Uses full DH keypairs for send.
 */
public class DoubleRatchetState implements Serializable {
    private static final long serialVersionUID = 1L;

    private byte[] rootKey;
    private KeyPair dhPair;            // our current DH keypair
    private PublicKey dhTheirPub;      // their current DH public key
    private byte[] sendChainKey;
    private byte[] recvChainKey;


    public static class Message {
        public final byte[] headerPub;   // our ephemeral DH pub for this msg
        public final byte[] iv;          // AES-GCM IV
        public final byte[] ciphertext;
        public Message(byte[] headerPub, byte[] iv, byte[] ciphertext) {
            this.headerPub = headerPub;
            this.iv = iv;
            this.ciphertext = ciphertext;
        }
    }

    /**
     * @param rootKey       initial root key
     * @param dhPair        our initial DH keypair (private+pub)
     * @param dhTheirPub    their DH public key
     * @param sendChainKey  initial sending chain key
     * @param recvChainKey  initial receiving chain key
     */
    public DoubleRatchetState(
            byte[] rootKey,
            KeyPair dhPair,
            PublicKey dhTheirPub,
            byte[] sendChainKey,
            byte[] recvChainKey
    ) {
        this.rootKey      = Arrays.copyOf(rootKey, rootKey.length);
        this.dhPair       = dhPair;
        this.dhTheirPub   = dhTheirPub;
        this.sendChainKey = Arrays.copyOf(sendChainKey, sendChainKey.length);
        this.recvChainKey = Arrays.copyOf(recvChainKey, recvChainKey.length);
    }

    // getters
    public byte[]     getRootKey()      { return Arrays.copyOf(rootKey, rootKey.length); }
    public PrivateKey getDhPrivate()    { return dhPair.getPrivate(); }
    public PublicKey  getDhPublic()     { return dhPair.getPublic(); }
    public PublicKey  getDhTheirPub()   { return dhTheirPub; }
    public byte[]     getSendChainKey() { return Arrays.copyOf(sendChainKey, sendChainKey.length); }
    public byte[]     getRecvChainKey() { return Arrays.copyOf(recvChainKey, recvChainKey.length); }

    /**
     * Perform a receive ratchet when a new DH public arrives.
     */
    public void ratchetReceive(PublicKey theirNewPub) throws GeneralSecurityException {
        byte[] dh = dhAgreement(dhPair.getPrivate(), theirNewPub);
        byte[] combined = hkdf(rootKey, dh, "Ratchet".getBytes(), 64);
        rootKey      = Arrays.copyOfRange(combined, 0, 32);
        recvChainKey = Arrays.copyOfRange(combined, 32, 48);
        sendChainKey = Arrays.copyOfRange(combined, 48, 64);
        this.dhTheirPub = theirNewPub;
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
        this.dhPair = newKP;
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



    // at the top of DoubleRatchetState, if you haven’t already
    private static final byte PACKET_TYPE_RATCHET = 0x01;

    // ————————————————
// 1) Encrypt a plaintext → Message
// ————————————————
    public Message encrypt(byte[] plaintext) throws GeneralSecurityException {
        // derive the next send-message key
        byte[] mk = nextSendMessageKey();
        SecretKeySpec messageKey = new SecretKeySpec(mk, "AES");

        // AAD = our current DH public
        byte[] headerPub = dhPair.getPublic().getEncoded();

        // fresh 12-byte IV
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        // AES-GCM
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, messageKey, new GCMParameterSpec(128, iv));
        cipher.updateAAD(headerPub);
        byte[] ciphertext = cipher.doFinal(plaintext);

        return new Message(headerPub, iv, ciphertext);
    }

    // ————————————————
// 2) Decrypt a received Message → plaintext
// ————————————————
    /**
     * Decrypt a received ratchet Message → plaintext
     */
    public byte[] decrypt(Message env) throws GeneralSecurityException {
        // only ratchet if they really sent a *new* DH pub (compare raw encodings)
        if (!Arrays.equals(env.headerPub, dhTheirPub.getEncoded())) {
            PublicKey theirPub = KeyFactory
                    .getInstance("X25519")
                    .generatePublic(new X509EncodedKeySpec(env.headerPub));
            ratchetReceive(theirPub);
        }

        // now derive the next recv-message key
        byte[] mk = nextRecvMessageKey();
        SecretKeySpec messageKey = new SecretKeySpec(mk, "AES");

        // AES-GCM decrypt (AAD = headerPub)
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, messageKey,
                new GCMParameterSpec(128, env.iv));
        cipher.updateAAD(env.headerPub);
        return cipher.doFinal(env.ciphertext);
    }





    // --- HKDF & HMAC helpers ---
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
        // HKDF-Extract
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt != null ? salt : new byte[32], "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);
        // HKDF-Expand
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
