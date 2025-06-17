// src/org/Server/ClientHandler.java
package org.Server;

import org.DataBase.DBConnect;
import org.Packets.*;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;

public class ClientHandler implements Runnable {
    private final Socket clientSocket;
    private final ClientEventListener eventListener;
    private final PublicKey serverPub;
    private final PrivateKey serverPriv;
    private SecretKey sessionKey;
    private byte[] iv;
    private PublicKey clientPub;
    private String username;

    public ClientHandler(Socket sock, ClientEventListener lst,
                         PublicKey sp, PrivateKey spriv) {
        this.clientSocket   = sock;
        this.eventListener  = lst;
        this.serverPub      = sp;
        this.serverPriv     = spriv;
    }

    @Override
    public void run() {
        try (
                ObjectOutputStream output = new ObjectOutputStream(clientSocket.getOutputStream());
                ObjectInputStream  input  = new ObjectInputStream(clientSocket.getInputStream())
        ) {
            // 1) send server RSA public
            output.writeObject(new PublicKeyPacket(serverPub.getEncoded()));
            output.flush();

            // 2) receive AES handshake
            byte[] encKeyPkt = (byte[])input.readObject();
            byte[] keyPkt    = PacketUtils.decryptKeyPacket(encKeyPkt, serverPriv);

            ByteBuffer kb = ByteBuffer.wrap(keyPkt);
            byte[] keyBytes = new byte[kb.getInt()]; kb.get(keyBytes);
            this.iv        = new byte[kb.getInt()];      kb.get(iv);
            this.sessionKey= new SecretKeySpec(keyBytes, "AES");
            System.out.println("✅ Session key established.");

            // 3) Now all packets via AES
            while (true) {
                byte[] raw = (byte[])input.readObject();
                Packet pkt = PacketUtils.decryptPacketAES(raw, sessionKey, iv);
                handlePacket(pkt, output);
            }
        } catch (EOFException eof) {
            System.out.println("Client disconnected: " + username);
            DBConnect.goOffline(username);
            eventListener.onClientAction("Logout", username);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private void handlePacket(Packet packet, ObjectOutputStream output) throws Exception {
        switch (packet.getType()) {
            case "Register" -> {
                RegisterPacket reg = (RegisterPacket) packet;
                System.out.println("Register attempt: " + reg.getUsername());

                // 1) Call your DB layer to store username, password, and client's public key
                String dbResult = DBConnect.RegiPOST(
                        reg.getUsername(),
                        reg.getPassword(),
                        reg.getPublicKeyBytes(),  // make sure RegisterPacket carries this
                        0                         // whatever your "role" or flag parameter is
                );

                // 2) Build an InfoPacket with the DB's result message
                InfoPacket info = new InfoPacket(dbResult);

                // 3) AES‐encrypt it and send back to client
                byte[] resp = PacketUtils.encryptPacketAES(info, sessionKey, iv);
                output.writeObject(resp);
                output.flush();
            }
            case "Login" -> {
                LoginPacket lp = (LoginPacket)packet;
                this.username = lp.getUsername();
                DBConnect.LoginPostResult res = DBConnect.LoginPOST(lp.getUsername(), lp.getPassword());
                InfoPacket info = new InfoPacket(res.message);
                byte[] resp = PacketUtils.encryptPacketAES(info, sessionKey, iv);
                output.writeObject(resp);
                output.flush();
                if (!res.isSuccess()) return;

                DBConnect.goOnline(lp.getUsername());
                // reconstruct clientPub
                X509EncodedKeySpec spec = new X509EncodedKeySpec(res.publicKeyBytes);
                this.clientPub = KeyFactory.getInstance("RSA").generatePublic(spec);

                // send user list
                List<String> online = DBConnect.getOnlineUsers();
                UserListPacket ul = new UserListPacket(online);
                byte[] listEnc = PacketUtils.encryptPacketAES(ul, sessionKey, iv);
                output.writeObject(listEnc);
                output.flush();

                eventListener.onClientAction("Login", username);
            }
            case "Message" -> {
                MessagePacket msg = (MessagePacket)packet;
                eventListener.onClientAction("Message", username + ": " + msg.getMessage());
                // ack
                InfoPacket ack = new InfoPacket("Sent.");
                byte[] resp = PacketUtils.encryptPacketAES(ack, sessionKey, iv);
                output.writeObject(resp);
                output.flush();
            }

            case "UserListRequest" ->{
                List<String> online = DBConnect.getOnlineUsers();
                UserListPacket resp = new UserListPacket(online);
                byte[] enc = PacketUtils.encryptPacketAES(resp, sessionKey, iv);
                output.writeObject(enc);
                output.flush();
            }
            default -> {
                InfoPacket unk = new InfoPacket("Unknown packet.");
                byte[] resp = PacketUtils.encryptPacketAES(unk, sessionKey, iv);
                output.writeObject(resp);
                output.flush();
            }
        }
    }
}
