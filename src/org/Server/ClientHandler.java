// src/org/Server/ClientHandler.java
package org.Server;

import org.DataBase.DBConnect;
import org.Packets.*;

import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.sql.SQLException;
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
                        reg.getRsaIdentityPub(),
                        reg.getX25519IdentityPub(),   // ← send the identity‐pub too
                        reg.getX25519SigningPub(),
                        reg.getSignature(),
                        0
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
            case "oneTimeKeysPacket" -> {
                oneTimeKeysPacket pkt = (oneTimeKeysPacket) packet;
                String user = pkt.getUser();
                byte[] pub  = pkt.getPublicKey();
                // save into the oneTimeKeys table
                String result = DBConnect.postOneTimeKey(user, pub);
                if (!"OK".equals(result)) {
                    System.err.println("❌ Failed to persist one‐time key for “" + user + "”: " + result);
                } else {
                    System.out.println("✅ Stored one‐time key for “" + user + "” in DB.");
                }
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

            case "DirectMessage" -> {
                DirectMessagePacket msg = (DirectMessagePacket) packet;
                Socket destSock = Main.users.get(msg.getRecipient());
                ClientHandler destHandler = Main.clientHandlers.get(destSock);
                if (destHandler == null) {
                    System.err.println("❌ No handler for user “" + msg.getRecipient() + "”");
                    break;
                }
                // AES-encrypt for that user’s session:
                byte[] wrapped = PacketUtils.encryptPacketAES(
                        msg,
                        destHandler.sessionKey,
                        destHandler.iv
                );
                destHandler.output.writeObject(wrapped);
                destHandler.output.flush();
            }



            case "AESAnswer" ->{

                AESAnswer c = (AESAnswer)packet;

                Socket s = Main.users.get(c.getRecipient());
                ClientHandler a = Main.clientHandlers.get(s);
                byte[] wrapped = PacketUtils.encryptPacketAES(c, a.sessionKey, a.iv);
                a.output.writeObject(wrapped);
                a.output.flush();
            }
            case "AESFinal" ->{

                AESFinal fin = (AESFinal)packet;

                Socket s = Main.users.get(fin.getRecipient());
                ClientHandler a = Main.clientHandlers.get(s);

                byte[] wrapped = PacketUtils.encryptPacketAES(fin, a.sessionKey, a.iv);
                a.output.writeObject(wrapped);
                a.output.flush();

            }
            case "BundleRequest" -> {
                BundleRequestPacket bp = (BundleRequestPacket)packet;
                String who = bp.getReceiver();
                try {
                    // fetch from DB (returns your org.Packets.KeyBundle or null)
                    KeyBundle bundle = DBConnect.getUserKeyBundle(who);
                    if (bundle == null) {
                        // no such user or no one‐time keys left
                        InfoPacket err = new InfoPacket(
                                "error: no key bundle available for “" + who + "”"
                        );
                        output.writeObject(err);
                    } else {
                        // send the bundle packet
                        output.writeObject(bundle);

                        // optionally, remove that one-time key row so it's single-use:
                        DBConnect.deleteOneTimeKey(who, bundle.getOneTimeKey());
                    }
                    output.flush();
                } catch (SQLException | IOException e) {
                    e.printStackTrace();
                    try {
                        output.writeObject(new InfoPacket(
                                "error: failed to fetch key bundle for “" + who + "”"
                        ));
                        output.flush();
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                }
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
