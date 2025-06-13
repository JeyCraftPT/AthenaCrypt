package org.Server;

import org.DataBase.DBConnect;
import org.Packets.*;

import java.io.*;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.function.Consumer;

public class ClientHandler implements Runnable {
    private final Socket clientSocket;
    private final ClientEventListener eventListener;
    private final PublicKey serverPublicKey;
    private final PrivateKey serverPrivateKey;
    private PublicKey clientPublicKey;
    private String username;

    public ClientHandler(Socket clientSocket, ClientEventListener eventListener,
                         PublicKey serverPublicKey, PrivateKey serverPrivateKey) {
        this.clientSocket = clientSocket;
        this.eventListener = eventListener;
        this.serverPublicKey = serverPublicKey;
        this.serverPrivateKey = serverPrivateKey;
    }

    @Override
    public void run() {
        try (
                ObjectOutputStream output = new ObjectOutputStream(clientSocket.getOutputStream());
                ObjectInputStream input = new ObjectInputStream(clientSocket.getInputStream())
        ) {
            // 1. Send server public key first
            output.writeObject(new PublicKeyPacket(serverPublicKey.getEncoded()));
            output.flush();

            // 2. Expect client public key
            Object firstObj = input.readObject();
            if (!(firstObj instanceof PublicKeyPacket clientPkPacket)) {
                System.out.println("Client did not send public key, closing connection: " + clientSocket);
                clientSocket.close();
                return;
            }
            this.clientPublicKey = clientPkPacket.getPublicKey();
            System.out.println("Received client public key from: " + clientSocket);

            // 3. Encrypted message loop
            while (true) {
                try {
                    Object encryptedObj = input.readObject();
                    if (!(encryptedObj instanceof byte[] encryptedBytes)) {
                        System.err.println("Expected byte[] but got: " + encryptedObj.getClass());
                        continue;
                    }

                    Packet packet = PacketUtils.decryptPacket(encryptedBytes, serverPrivateKey);
                    handlePacket(packet, output);

                } catch (EOFException e) {
                    System.out.println("Client disconnected: " + clientSocket);

                    eventListener.onClientAction("Logout", this.username);

                    break;
                } catch (Exception e) {
                    e.printStackTrace();
                    // send back an error InfoPacket
                    InfoPacket err = new InfoPacket("Decryption or deserialization failed.");
                    byte[] resp = PacketUtils.encryptPacket(err, clientPublicKey);
                    output.writeObject(resp);
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void handlePacket(Packet packet, ObjectOutputStream output) throws Exception {
        switch (packet.getType()) {
            case "Register" -> {
                RegisterPacket reg = (RegisterPacket) packet;
                System.out.println("Register: " + reg.getUsername());
                eventListener.onClientAction("Register", sentPkt -> {
                    try {
                        String result = DBConnect.RegiPOST(reg.getUsername(), reg.getPassword(),
                                clientPublicKey.getEncoded(), 0);
                        InfoPacket info = new InfoPacket(result);
                        byte[] encrypted = PacketUtils.encryptPacket(info, clientPublicKey);
                        output.writeObject(encrypted);
                        output.flush();
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                });
            }

            case "Login" -> {
                LoginPacket loginPacket = (LoginPacket) packet;
                System.out.println("Login: " + loginPacket.getUsername());
                this.username = loginPacket.getUsername();

                // Pass a Consumer<Packet> that sends any Packet back to this client
                eventListener.onClientAction("Login", loginPacket.getUsername(), sentPkt -> {
                    try {
                        System.out.println("Consumer sending packet of :" + sentPkt.getType());

                        DBConnect.LoginPostResult result = DBConnect.LoginPOST(loginPacket.getUsername(), loginPacket.getPassword());
                        System.out.println("Login result: " + result.message);
                        PublicKeyPacket publicKeyPacket = new PublicKeyPacket(result.publicKeyBytes);
                        byte[] encrypted = PacketUtils.encryptPacket(sentPkt, publicKeyPacket.getPublicKey());
                        output.writeObject(encrypted);
                        System.out.println("User public key sent");
                        output.flush();
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                });
            }

            case "Message" -> {
                MessagePacket msg = (MessagePacket) packet;
                System.out.println("Message: " + msg.getMessage());
                eventListener.onClientAction("Message", sentPkt -> {
                    try {
                        InfoPacket ack = new InfoPacket("Message sent successfully.");
                        byte[] encrypted = PacketUtils.encryptPacket(ack, clientPublicKey);
                        output.writeObject(encrypted);
                        output.flush();
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                });
            }

            default -> {
                InfoPacket unknown = new InfoPacket("Unknown packet type.");
                byte[] encrypted = PacketUtils.encryptPacket(unknown, clientPublicKey);
                output.writeObject(encrypted);
                output.flush();
            }
        }
    }
}
