package org.Server;

import org.Keys.RSAKeys;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;

public class SecureServer {
    private static final int PORT = 5000;
    private static HashMap<Socket, ObjectOutputStream> clientOutputStreams = new HashMap<>();

    public static void main(String[] args) {
        try {
            // Generate RSA key pair for the server
            KeyPair serverKeyPair = RSAKeys.generateKeyPair();
            PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
            PublicKey serverPublicKey = serverKeyPair.getPublic();

            // Start server socket
            ServerSocket serverSocket = new ServerSocket(PORT);
            System.out.println("Server started. Waiting for clients...");

            while (true) {
                // Accept two clients
                Socket client1 = serverSocket.accept();
                System.out.println("Client 1 connected.");

                Socket client2 = serverSocket.accept();
                System.out.println("Client 2 connected.");

                // Create object streams for clients
                ObjectOutputStream out1 = new ObjectOutputStream(client1.getOutputStream());
                ObjectInputStream in1 = new ObjectInputStream(client1.getInputStream());

                ObjectOutputStream out2 = new ObjectOutputStream(client2.getOutputStream());
                ObjectInputStream in2 = new ObjectInputStream(client2.getInputStream());

                System.out.println("create object stream");

                // Store client output streams
                clientOutputStreams.put(client1, out1);
                clientOutputStreams.put(client2, out2);

                // Send server public key to both clients
                out1.writeObject(serverPublicKey);
                out2.writeObject(serverPublicKey);
                out1.flush();
                out2.flush();

                System.out.println("send pub keys");

                // Receive public keys from both clients
                PublicKey client1PublicKey = (PublicKey) in1.readObject();
                PublicKey client2PublicKey = (PublicKey) in2.readObject();

                System.out.println("Receive pub keys");

                // Exchange public keys between clients
                out1.writeObject(client2PublicKey);
                out2.writeObject(client1PublicKey);
                out1.flush();
                out2.flush();

                System.out.println("Exchange public keys");

                // Receive HMAC keys from both users (encrypted with other Users public key)
                byte[] encryptedHmacKeyFromClient1 = (byte[]) in1.readObject();
                byte[] encryptedHmacKeyFromClient2 = (byte[]) in2.readObject();

                out2.writeObject( encryptedHmacKeyFromClient1);
                out2.flush();
                System.out.println("Sent AES key from Client 1 to Client 2.");

                out1.writeObject(encryptedHmacKeyFromClient2 );
                out1.flush();
                System.out.println("Sent AES key from Client 2 to Client 1.");


                // Receive AES keys from both clients (encrypted with other Users public key)
                byte[] encryptedAesKeyFromClient1 = (byte[]) in1.readObject();
                byte[] encryptedAesKeyFromClient2 = (byte[]) in2.readObject();

                // Send the encrypted AES keys to the correct clients
                out2.writeObject(encryptedAesKeyFromClient1);
                out2.flush();
                System.out.println("Sent AES key from Client 1 to Client 2.");

                out1.writeObject(encryptedAesKeyFromClient2);
                out1.flush();
                System.out.println("Sent AES key from Client 2 to Client 1.");


                // Start message relay thread
                new Thread(() -> handleClientMessages(client1, in1, client2)).start();
                new Thread(() -> handleClientMessages(client2, in2, client1)).start();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void handleClientMessages(Socket sender, ObjectInputStream input, Socket receiver) {
        try {
            while (true) {
                String encryptedMessageBase64 = (String) input.readObject();
                if (clientOutputStreams.containsKey(receiver)) {
                    clientOutputStreams.get(receiver).writeObject(encryptedMessageBase64);
                    clientOutputStreams.get(receiver).flush();
                }
            }
        } catch (Exception e) {
            System.out.println("Client disconnected.");
        }
    }
}