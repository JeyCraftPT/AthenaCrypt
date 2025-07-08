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

            List<DirectMessagePacket> queued = DBConnect.getOfflineMessages(username);
            for (DirectMessagePacket p : queued) {
                byte[] wrapped = PacketUtils.encryptPacketAES(p, sessionKey);
                output.writeObject(wrapped);
            }
            DBConnect.deleteOfflineMessages(username);

            // 3) Now all packets via AES
            while (true) {
                byte[] raw = (byte[])input.readObject();
                Packet pkt = PacketUtils.decryptPacketAES(raw, sessionKey);

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

                // 1) Store in DB
                String dbResult = DBConnect.RegiPOST(
                        reg.getUsername(),
                        reg.getPassword(),
                        reg.getRsaIdentityPub(),
                        reg.getX25519IdentityPub(),
                        reg.getX25519SigningPub(),
                        reg.getSignature(),
                        0
                );

                // 2) Send back the result
                InfoPacket info = new InfoPacket(dbResult);
                output.writeObject(PacketUtils.encryptPacketAES(info, sessionKey));
                output.flush();

                if (dbResult.toLowerCase().contains("success")) {
                    // 3) Mark online
                    this.username = reg.getUsername();
                    DBConnect.goOnline(this.username);

                    // 4) Tell the event listener “Login” so Main.users & handlers get populated
                    eventListener.onClientAction(
                            "Login",
                            this.username,
                            this.clientSocket,
                            sentPacket -> { /* no‐op */ }
                    );

                    // 5) Send the user list just like in Login
                    List<String> online = DBConnect.getOnlineUsers();
                    UserListPacket ul = new UserListPacket(online);
                    byte[] listEnc = PacketUtils.encryptPacketAES(ul, sessionKey);
                    output.writeObject(listEnc);
                    output.flush();
                }
            }

            case "Login" -> {
                LoginPacket lp = (LoginPacket)packet;
                this.username = lp.getUsername();
                DBConnect.LoginPostResult res = DBConnect.LoginPOST(lp.getUsername(), lp.getPassword());
                InfoPacket info = new InfoPacket(res.message);
                byte[] resp = PacketUtils.encryptPacketAES(info, sessionKey);
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
                byte[] listEnc = PacketUtils.encryptPacketAES(ul, sessionKey);
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
                    // store for offline delivery
                     DBConnect.storeOfflineMessage(
                         msg.getSender(),
                         msg.getRecipient(),
                         msg.getHeaderPub(),
                         msg.getIv(),
                         msg.getCiphertext()
                     );
                break;
                }
                // AES-encrypt for that user's session:
                byte[] wrapped = PacketUtils.encryptPacketAES(
                        msg,
                        destHandler.sessionKey
                );
                destHandler.output.writeObject(wrapped);
                destHandler.output.flush();
            }
            case "MadeHand" -> {
                MadeHand mh = (MadeHand) packet;
                boolean ok = DBConnect.storeMadeHand(mh);
                if (!ok) {
                    System.err.println("❌ Failed to store MadeHand for "
                            + mh.getInitiator() + "↔" + mh.getPeer());
                } else {
                    System.out.println("✅ Stored MadeHand for "
                            + mh.getInitiator() + "↔" + mh.getPeer());
                }
            }

            case "handshake" -> {
                HandShakePacket handshake = (HandShakePacket) packet;
                String initiator = handshake.getUsername();
                String receiver  = handshake.getPerson();

                // 1) grab the local bundle (has your slot + eph pub)
                KeyBundle localBundle = DBConnect.getUserKeyBundleLocal(receiver);
                if (localBundle == null) {
                    System.err.println("❌ No local KeyBundle for " + receiver);
                    break;
                }

                // 2) find the global oneTimeKeys.key_id
                int globalKeyId = DBConnect.getUserKeyBundle(receiver).getOneTimeKeyID();
                String result   = DBConnect.Touch(initiator, receiver, globalKeyId);

                if ("Added".equals(result)) {
                    // ─── A) send the bundle to the client ───────────────────────────
                    output.writeObject(localBundle);

                    // ─── B) persist the same globalKeyId + ephKey *before* deleting ──
                    MadeHand mh = new MadeHand(
                            initiator,
                            receiver,
                            globalKeyId,                    // ← the real key_id
                            localBundle.getOneTimeKey(),    // ← exactly what you just sent
                            localBundle.getX25519IdentityPub(),
                            localBundle.getX25519SigningPub()
                    );
                    try {
                        DBConnect.storeMadeHand(mh);
                    } catch (SQLException e) {
                        System.err.println("⚠️ Couldn’t store MadeHand: " + e.getMessage());
                    }

                    // ─── C) now consume the one-time-key so it can’t be re-used ─────
                    String del = DBConnect.deleteOneTimeKey(
                            receiver,
                            localBundle.getOneTimeKey()
                    );
                    if (!"OK".equals(del)) {
                        System.err.println("⚠️ Failed to delete one-time key: " + del);
                    }

                } else {
                    System.out.println("🔁 Handshake exists for " + initiator + "↔" + receiver + " (or vice-versa)");
                    try {
                        // first try the "natural" direction
                        MadeHand stored = DBConnect.getMadeHandBundle(initiator, receiver);
                        boolean swapped = false;

                        // if that returns null, try the flipped direction
                        if (stored == null) {
                            stored = DBConnect.getMadeHandBundle(receiver, initiator);
                            swapped = true;
                        }

                        if (stored == null) {
                            System.err.println("⚠️ No stored MadeHand in either direction; falling back to full bundle");
                            output.writeObject(localBundle);
                        } else {
                            // restore original roles
                            String origInitiator = swapped ? receiver  : initiator;
                            String origReceiver  = swapped ? initiator : receiver;
                            output.writeObject(new HandShakeAlreadyMade(
                                    origInitiator,
                                    origReceiver,
                                    stored.getKeyId(),
                                    stored.getEphKey(),
                                    stored.getInitiatorIdentityPub(),
                                    stored.getInitiatorSigningPub()
                            ));
                        }
                    } catch (SQLException e) {
                        System.err.println("❌ DB error fetching MadeHand: " + e.getMessage());
                        output.writeObject(localBundle);
                    }
                }
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
                byte[] resp = PacketUtils.encryptPacketAES(unk, sessionKey);
                output.writeObject(resp);
                output.flush();
            }
        }
    }
}
