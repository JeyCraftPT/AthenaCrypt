package org.Messages;

import org.DataBase.DBConnect;
import org.Keys.RSAKeys;
import org.Server.TCPServerMain;
import org.Server.TCPServerMain;
import org.UserHandler.User;

import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

public class TCPServerThread implements Runnable {
    private Socket socket; // Client socket
    private TCPServerMain tcpServerMain; // Reference to the main server


    public TCPServerThread(Socket socket, TCPServerMain tcpServerMain) {
        this.socket = socket;
        this.tcpServerMain = tcpServerMain;
    }

    @Override
    public void run() {
        try {
            // Setup streams
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            // Generate RSA key pair for server-client encryption
            KeyPair serverKeyPair = RSAKeys.getKeyPair();
            PublicKey serverPublicKey = serverKeyPair.getPublic();
            PrivateKey serverPrivateKey = serverKeyPair.getPrivate();

            // Step 0: Send server public key to client
            out.writeObject(serverPublicKey);

            // Step 1: Receive login or register info (Base64-encoded byte[])
            Object authObject = in.readObject();
            if (!(authObject instanceof byte[])) {
                out.writeObject("❌ Invalid authentication format.");
                socket.close();
                return;
            }

            byte[] credentialsEncoded = (byte[]) authObject;
            byte[] decodedBytes = Base64.getDecoder().decode(credentialsEncoded);
            String decoded = new String(decodedBytes);

            String[] parts = decoded.split(":", 3);
            if (parts.length < 3) {
                out.writeObject("❌ Invalid format: missing fields.");
                socket.close();
                return;
            }

            String command = parts[0];
            String username = parts[1];
            String passHash = parts[2];
            boolean authenticated = false;

            if (command.equalsIgnoreCase("REGISTER") && parts.length == 3) {
                // Extract public key bytes safely
                /*byte[] publicKeyBytes = parts[3].getBytes(); // ideally decode Base64 here*/
                /*String result = DBConnect.RegiPOST(username, passHash, publicKeyBytes);*/
                String result = DBConnect.RegiPOST(username, passHash);
                out.writeObject(result);

                if (!result.equalsIgnoreCase("Username already in use")) {
                    authenticated = true;
                }

            } else if (command.equalsIgnoreCase("LOGIN") && parts.length == 3) {
                authenticated = DBConnect.LoginPOST(username, passHash);
                out.writeObject(authenticated ? "✅ Login successful" : "❌ Invalid credentials");
            } else {
                out.writeObject("❌ Unknown command or bad format.");
                socket.close();
                return;
            }

            if (!authenticated) {
                socket.close(); // Kick out unauthorized user
                return;
            }

            // Step 2: Receive client's actual public key object after auth
            PublicKey clientPublicKey = (PublicKey) in.readObject();

            // Step 3: Register user in memory
            User user = new User(username, socket, out, clientPublicKey);
            TCPServerMain.registerUser(username, user);

            // Step 4: Send welcome message
            out.writeObject("Welcome " + username + "! Users online: " + TCPServerMain.getUserList());

            // Step 5: Send user list
            out.writeObject("Users online:");
            for (String userName : TCPServerMain.getUserList()) {
                out.writeObject(userName);
            }

            // ✅ Now start listening for chat messages
            while (true) {
                Object incoming = in.readObject();

                if (incoming instanceof String message) {
                    if (message.startsWith("TO:")) {
                        String[] msgParts = message.substring(3).split("\\|", 2);
                        if (msgParts.length == 2) {
                            String receiverName = msgParts[0];
                            String messageText = msgParts[1];

                            User receiver = TCPServerMain.getUser(receiverName);
                            if (receiver != null) {
                                receiver.getOut().writeObject("Message from " + username + ": " + messageText);
                            } else {
                                out.writeObject("❌ User " + receiverName + " not found.");
                            }
                        } else {
                            out.writeObject("❌ Invalid message format. Use: TO:username|Your message");
                        }
                    } else {
                        out.writeObject("⚠️ Unknown command: " + message);
                    }
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}





/*

    public static void main(String[] args) {
        try {
            // Generate RSA key pair for the server
            KeyPair serverKeyPair = RSAKeys.generateKeyPair();
            PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
            PublicKey serverPublicKey = serverKeyPair.getPublic();

            // Start server socket
            ServerSocket serverSocket = new ServerSocket(PORT);
            System.out.println("Server started. Waiting for clients...");

            System.out.println(DBConnect.getConnection());

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

                byte[] receivedBytes = (byte[]) in1.readObject();

                // Decode Base64
                byte[] decoded = Base64.getDecoder().decode(receivedBytes);
                byte delimiter = (byte) ':';

                Object[] splitParts = splitDecodedBytes(decoded, delimiter, 4);

                String command = (String) splitParts[0];
                String username = (String) splitParts[1];
                String hashedPassword = (String) splitParts[2];
                byte[] pKey = (byte[]) splitParts[3];

                System.out.println("Command: " + command);
                System.out.println("Username: " + username);
                System.out.println("Hashed Password: " + hashedPassword);
                System.out.println("Public Key (bytes): " + Arrays.toString(pKey));

                String response;

                if (command.equalsIgnoreCase("REGISTER")) {
                    response = DBConnect.RegiPOST(username, hashedPassword, pKey);
                    out1.writeObject(response); // ✅ Send response back to client
                    out1.flush();

                } else if (command.equalsIgnoreCase("LOGIN")) {
                    // Placeholder for LOGIN logic
                    response = "Login not implemented yet";
                    out1.writeObject(response);
                    out1.flush();
                }


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
                byte[] encryptedMessageBase64 = (byte[]) input.readObject();
                if (clientOutputStreams.containsKey(receiver)) {
                    clientOutputStreams.get(receiver).writeObject(encryptedMessageBase64);
                    clientOutputStreams.get(receiver).flush();
                }
            }
        } catch (Exception e) {
            System.out.println("Client disconnected.");
        }
    }*/