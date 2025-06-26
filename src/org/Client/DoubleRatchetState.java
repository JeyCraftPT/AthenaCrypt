package org.Client;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

public class DoubleRatchetState {
    private final byte[] rootKey;
    private final PrivateKey dhPrivate;   // our current DH private key
    private final PublicKey  dhTheirPub;  // their current DH public key
    private final byte[] sendChainKey;
    private final byte[] recvChainKey;

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
    public byte[]     getRootKey()      { return Arrays.copyOf(rootKey,      rootKey.length); }
    public PrivateKey getDhPrivate()    { return dhPrivate; }
    public PublicKey  getDhTheirPub()   { return dhTheirPub; }
    public byte[]     getSendChainKey() { return Arrays.copyOf(sendChainKey, sendChainKey.length); }
    public byte[]     getRecvChainKey() { return Arrays.copyOf(recvChainKey, recvChainKey.length); }

    // TODO: add methods for:
    //   - DH ratchet step (swap keys when you receive a new public)
    //   - chain-key KDF to derive message keys
    //   - encrypt(plaintext) / decrypt(ciphertext)
}
