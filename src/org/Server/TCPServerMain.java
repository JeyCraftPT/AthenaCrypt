package org.Server;

import org.Keys.RSAKeys;
import org.Messages.TCPServerThread;
import org.UserHandler.User;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

//TODO
// Implementar BD

// Save Before caos

//TODO
// Acrescentar login através do servidor
// Guardar chave pública do cliente na BD
// Guardar chave privada e chave AES num ficheiro


public class TCPServerMain {
    private static HashMap<Socket, ObjectOutputStream> clientOutputStreams = new HashMap<>();
    private static final Map<String, User> connectedUsers = Collections.synchronizedMap(new HashMap<>());

    private static final int PORT = 5000;

    public TCPServerMain() throws IOException{
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Porta 5000 is open");
        while (true){
            Socket socket = serverSocket.accept();

            TCPServerThread tcpServerThread = new TCPServerThread(socket,this);
            Thread thread = new Thread(tcpServerThread);
            thread.start();
        }
    }

    private int clientNumber = 1;

    public int getClientNumber(){
        return clientNumber++;
    }

    public static void registerUser(String username, User user) {
        connectedUsers.put(username, user);
    }

    public static List<String> getUserList() {
        return new ArrayList<>(connectedUsers.keySet());
    }

    public static User getUser(String username) {
        return connectedUsers.get(username);
    }


    public static void main(String[] args){
        try{
            // Generate RSA key pair for the server
            KeyPair serverKeyPair = RSAKeys.generateKeyPair();
            PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
            PublicKey serverPublicKey = serverKeyPair.getPublic();

            new TCPServerMain();
        }catch (Exception e){
            e.printStackTrace();
        }
    }
    /*public static Object[] splitDecodedBytes(byte[] data, byte delimiter, int expectedParts) {
        List<byte[]> parts = new ArrayList<>();
        int start = 0;

        for (int i = 0; i < data.length && parts.size() < expectedParts - 1; i++) {
            if (data[i] == delimiter) {
                parts.add(Arrays.copyOfRange(data, start, i));
                start = i + 1;
            }
        }

        // Add the last part (pKey)
        parts.add(Arrays.copyOfRange(data, start, data.length));

        // Prepare result: 3 strings + 1 byte[]
        String command = new String(parts.get(0), StandardCharsets.UTF_8);
        String username = new String(parts.get(1), StandardCharsets.UTF_8);
        String hashedPassword = new String(parts.get(2), StandardCharsets.UTF_8);
        byte[] pKey = parts.get(3);

        return new Object[] { command, username, hashedPassword, pKey };
    }



    public static void main(String[] args) {
        try {

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
}