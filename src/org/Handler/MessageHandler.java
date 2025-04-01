package org.Handler;

import org.Keys.AESKeys;
import org.Keys.RSAKeys;
import org.Handler.Message;

import javax.crypto.SecretKey;
import java.io.ObjectInputStream;
import java.security.PrivateKey;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

public class MessageHandler {

    /*public void sendPacket(Message packet, ObjectOutputStream objectOutputStream, PublicKey recipientPublicKey, SecretKey sessionKey) {
        try {
            // Encrypt message content with AES session key
            byte[] encryptedContent = AESKeys.encrypt(packet.getContent(), sessionKey);

            // Encrypt the AES session key with recipient's RSA public key
            byte[] encryptedSessionKey = RSAKeys.encrypt(AESKeys.getKeyBytes(sessionKey), recipientPublicKey);

            // Create encrypted message packet
            EncryptedMessage encryptedPacket = new EncryptedMessage(encryptedContent, encryptedSessionKey, packet.getType());

            // Send the encrypted message
            objectOutputStream.writeObject(encryptedPacket);
            objectOutputStream.flush();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }*/

    /////////////////////////////////////////////////////////////////////////////////////////////
/*
    public Message receivePacket(ObjectInputStream objectInputStream, PrivateKey recipientPrivateKey) {
        try {
            // Read the encrypted message packet from the input stream
            EncryptedMessage encryptedPacket = (EncryptedMessage) objectInputStream.readObject();

            // Decrypt the session key using RSA private key
            byte[] decryptedSessionKeyBytes = RSAKeys.decrypt(encryptedPacket.getEncryptedSessionKey(), recipientPrivateKey);

            // Convert the decrypted session key bytes back to a SecretKey
            SecretKey sessionKey = AESKeys.getKeyFromBytes(decryptedSessionKeyBytes);

            // Decrypt the content using the AES session key
            byte[] decryptedContent = AESKeys.decrypt(encryptedPacket.getEncryptedContent(), sessionKey);

            // Create and return the decrypted message
            Message decryptedMessage = new Message(decryptedContent, encryptedPacket.getType());
            return decryptedMessage;

        } catch (Exception e) {
            e.printStackTrace();
            return null; // Handle error or return null if decryption fails
        }
    }
*/


}
