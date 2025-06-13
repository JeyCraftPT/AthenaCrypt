package org.Client;

import org.Packets.*;

import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Scanner;

public class Main {

    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 5000;

    public static void main(String[] args) {
        try (
                Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
                ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
                Scanner scanner = new Scanner(System.in)
        ) {
            System.out.println("Connected to server: " + socket);

            // 1. Generate client key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair clientKeyPair = keyGen.generateKeyPair();
            PublicKey clientPublicKey = clientKeyPair.getPublic();
            PrivateKey clientPrivateKey = clientKeyPair.getPrivate();

            // 2. Receive server public key
            Object obj = input.readObject();
            if (!(obj instanceof PublicKeyPacket serverKeyPacket)) {
                throw new IOException("Did not receive server public key");
            }
            PublicKey serverPublicKey = serverKeyPacket.getPublicKey();
            System.out.println("Received server public key.");

            // 3. Send client public key
            output.writeObject(new PublicKeyPacket(clientPublicKey.getEncoded()));
            output.flush();
            System.out.println("Sent client public key.");

            // 4. Registration/Login loop
            boolean loggedIn = false;

            while (!loggedIn) {
                System.out.println("\nChoose an action: [register | login]");
                String choice = scanner.nextLine().trim().toLowerCase();

                switch (choice) {
                    case "register" -> {
                        System.out.print("Enter username: ");
                        String username = scanner.nextLine();
                        System.out.print("Enter password: ");
                        String password = scanner.nextLine();

                        RegisterPacket register = new RegisterPacket(username, password);
                        byte[] encrypted = PacketUtils.encryptPacket(register, serverPublicKey);
                        output.writeObject(encrypted);
                        output.flush();

                        Object encryptedObj = input.readObject();
                        if (!(encryptedObj instanceof byte[] encryptedBytes)) {
                            System.err.println("Expected byte[] but got: " + encryptedObj.getClass());
                            continue;
                        }

                        InfoPacket infoPacket = (InfoPacket) PacketUtils.decryptPacket(encryptedBytes, clientPrivateKey);
                        System.out.println("Server: " + infoPacket.getMessage());
                    }

                    case "login" -> {
                        System.out.print("Enter username: ");
                        String username = scanner.nextLine();
                        System.out.print("Enter password: ");
                        String password = scanner.nextLine();

                        LoginPacket login = new LoginPacket(username, password);
                        byte[] encrypted = PacketUtils.encryptPacket(login, serverPublicKey);
                        output.writeObject(encrypted);
                        output.flush();

                        loggedIn = true;
                    }

                    default -> System.out.println("Unknown command. Type 'register' or 'login'.");
                }
            }

            System.out.println("Waiting for user list ...");
            Object encryptedObj = input.readObject();
            if (!(encryptedObj instanceof byte[] encryptedBytes)) {
                System.err.println("Expected byte[] but got: " + encryptedObj.getClass());
                return;
            }


            UserListPacket userListPacket = (UserListPacket) PacketUtils.decryptPacket(encryptedBytes, clientPrivateKey);

            System.out.println("User list is : " + userListPacket.getUsers());

            // 5. Message loop
            System.out.println("You can now send messages. Type 'exit' to quit.");

            while (true) {
                System.out.print("> ");
                String message = scanner.nextLine();
                if (message.equalsIgnoreCase("exit")) break;

                MessagePacket msgPacket = new MessagePacket(message);
                byte[] encrypted = PacketUtils.encryptPacket(msgPacket, serverPublicKey);
                output.writeObject(encrypted);
                output.flush();

                Object response = input.readObject();
                if (response instanceof String) {
                    System.out.println("Server: " + response);
                }
            }

            System.out.println("Client shutting down.");

        } catch (IOException | ClassNotFoundException | GeneralSecurityException e) {
            e.printStackTrace();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
