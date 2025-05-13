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

            String[] parts = decoded.split(":", 4);
            if (parts.length < 4) {
                out.writeObject("❌ Invalid format: missing fields.");
                socket.close();
                return;
            }

            String command = parts[0].toLowerCase();
            String username = parts[1];
            String passHash = parts[2];
            String publicKeyByte = parts[3];
            boolean authenticated = false;

            while (!command.equalsIgnoreCase("register") && !command.equalsIgnoreCase("login")) {
                out.writeObject("Wrong command! Try again.");

            }
            out.writeObject("ola");
            /*command = in.readLine();*/
            if (command.equalsIgnoreCase("REGISTER") && parts.length == 4) {
                System.out.println("OOASFOANSOFBAISBGAIBFAISBD");
                out.writeObject("hello");
                // Extract public key bytes safely
                byte[] publicKeyBytes = parts[3].getBytes(); // ideally decode Base64 here
                String result = DBConnect.RegiPOST(username, passHash, publicKeyBytes);
                /*String result = DBConnect.RegiPOST(username, passHash);*/
                out.writeObject(result);

                if (!result.equalsIgnoreCase("Username already in use")) {
                    authenticated = true;
                }

            } else if (command.equalsIgnoreCase("LOGIN") && parts.length == 3) {
                byte[] returnPublicK = DBConnect.LoginPOST(username, passHash);
                byte[] Bad = "Wrong password!".getBytes();


                //TODO
                // Aqui tem de devolver alguma coisa tipo username e chave ou algo parecido


                out.writeObject(Arrays.equals(returnPublicK, Bad) ? "❌ Invalid credentials" : "✅ Login successful");
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
                out.writeObject("miau");
                out.writeObject(userName);
            }

            // ✅ Now start listening for chat messages
            // ✅ Now start listening for chat messages
            while (true) {
                Object incoming = in.readObject();

                if (incoming instanceof String message) {
                    if (message.equalsIgnoreCase("quit")) {
                        System.out.println("User " + username + " disconnected.");
                        TCPServerMain.removeUser(username); // Optional: cleanup user from active list
                        socket.close();
                        break; // Exit thread
                    }

                    if (message.startsWith("TO:")) {
                        String[] msgParts = message.substring(3).split("\\|", 2);
                        if (msgParts.length == 2) {
                            String receiverName = msgParts[0];
                            String messageText = msgParts[1];

                            User receiver = TCPServerMain.getUser(receiverName);
                            if (receiver != null) {
                                receiver.getOut().writeObject("FROM:" + username + "|" + messageText);
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
