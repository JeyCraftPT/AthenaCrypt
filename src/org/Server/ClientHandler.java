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
    public ObjectOutputStream output;

    public ClientHandler(Socket sock, ClientEventListener lst,
                         PublicKey sp, PrivateKey spriv) {
        this.clientSocket   = sock;
        this.eventListener  = lst;
        this.serverPub      = sp;
        this.serverPriv     = spriv;
    }

    @Override
    public void run() {

        try {
            ObjectInputStream  input  = new ObjectInputStream(clientSocket.getInputStream());
            output = new ObjectOutputStream(clientSocket.getOutputStream());

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
                break;
            }
            System.out.println("miau");
            while (true){
                Object obj = input.readObject();
                if (!(obj instanceof Packet)) {
                    throw new IOException("Expected Packet, got " + obj.getClass());
                }
                Packet raw = (Packet) obj;
                handlePacket(raw, output);

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

                eventListener.onClientAction("Login", username, this.clientSocket, sentPacket -> {

                });
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
                /*byte[] enc = PacketUtils.encryptPacketAES(resp, sessionKey, iv);*/
                output.writeObject(resp);
                output.flush();
            }

            case "DirectMessage" ->{
                DirectMessagePacket msg = (DirectMessagePacket)packet;
                Socket s = Main.users.get(msg.getRecipient());
                ClientHandler a = Main.clientHandlers.get(s);

                //TODO
                // cena da cifra
                // verificar isto...?

                System.out.println(msg.getRecipient());
                System.out.println(s.getRemoteSocketAddress());
                a.output.writeObject(msg);

            }
            case "AESAnswer" ->{
                //TODO
                // confirmar isto

                AESAnswer c = (AESAnswer)packet;

                Socket s = Main.users.get(c.getRecipient());
                ClientHandler a = Main.clientHandlers.get(s);
                a.output.writeObject(c);
            }
            case "AESFinal" ->{
                //TODO
                // fazer isto tbm
                AESFinal fin = (AESFinal)packet;

                Socket s = Main.users.get(fin.getRecipient());
                ClientHandler a = Main.clientHandlers.get(s);

                a.output.writeObject(fin);

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
