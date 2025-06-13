package org.Server;

import org.Keys.RSAKeys;
import org.Packets.InfoPacket;
import org.Packets.Packet;
import org.Packets.UserListPacket;
import org.mariadb.jdbc.client.Client;

import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.function.Consumer;

public class Main implements ClientEventListener {

    List<String> clients = new ArrayList<>();

    public static int PORT = 5000;

    public static void main(String[] args){
        new Main().startServer(); // Use an instance so we can pass `this`
    }

    public void startServer() {
        try {
            KeyPair serverKeyPair = RSAKeys.generateKeyPair();
            PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
            PublicKey serverPublicKey = serverKeyPair.getPublic();

            System.out.println("Server started on port " + PORT);

            ServerSocket serverSocket = new ServerSocket(PORT);

            while (true) {
                System.out.println("Waiting for clients...");
                Socket clientSocket = serverSocket.accept();
                System.out.println("New client connected: " + clientSocket);

                ClientHandler clientHandler = new ClientHandler(clientSocket, this, serverPublicKey, serverPrivateKey); // `this` is the listener
                new Thread(clientHandler).start();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onClientAction(String action, String data) {
        System.out.println("Action: " + action + " Data: " + data);

        switch (action) {
            case "Logout":
                System.out.println("Removed " + data + " from user list.");
                clients.remove(data);

            default:
                System.out.println("Unknown action: " + action);
                break;
        }
    }

        @Override
        public void onClientAction(String action, Consumer<Packet> callback) {
            switch (action) {
                case "Register" -> {
                    Packet registerResponse = new InfoPacket("User registered.");
                    callback.accept(registerResponse);
                }
                default -> {
                    callback.accept(new InfoPacket("Unknown action."));
                }
            }
        }

    @Override
    public void onClientAction(String action, String username, Consumer<Packet> callback) {
        switch (action) {
            case "Login" -> {
                clients.add(clients.size(), username);
                UserListPacket userListPacket = new UserListPacket(clients);
                callback.accept(userListPacket);
            }
            default -> {
                callback.accept(new InfoPacket("Unknown action."));
            }
        }
    }


}
