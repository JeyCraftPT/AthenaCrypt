package org.Client;

import org.Keys.AESKeys;
import org.Keys.RSAKeys;
import org.Packets.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Main {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int    SERVER_PORT    = 5000;

    public static void main(String[] args) {
        try (
                Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
                ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream  input  = new ObjectInputStream(socket.getInputStream());
                Scanner scanner = new Scanner(System.in)
        ) {
            System.out.println("Connected to server.");

            // session store for ratchet states, keyed by Base64(rsaIdentityPub)
            final Map<String, DoubleRatchetState> sessionStore = new ConcurrentHashMap<>();
            final Map<String, List<DirectMessagePacket>> pendingMessages = new ConcurrentHashMap<>();
            // field somewhere:
            final AtomicReference<KeyBundle> selectedPeerKeyBundleRef = new AtomicReference<>();


            // user state
            String   username   = null;
            String   userPass   = null;
            PublicKey  userPub     = null;
            PrivateKey userPriv;

            // for register flow
            KeyPair userIKP  = null;
            KeyPair userSPKP = null;

            PrivateKey x25519IdentityPriv = null;
            PublicKey  x25519IdentityPub  = null;


            final AtomicReference<KeyPair>  userIKPRef                  = new AtomicReference<>();
            final AtomicReference<KeyPair>  userSPKPRef                 = new AtomicReference<>();



            // for selecting peers

            final AtomicReference<byte[]> selectedPeerIdPubBytesRef = new AtomicReference<>();
            final AtomicReference<String> selectedPeerUsernameRef = new AtomicReference<>();

            // 1) receive server RSA pubkey
            Object o = input.readObject();
            if (!(o instanceof PublicKeyPacket pk)) {
                throw new IOException("Expected PublicKeyPacket");
            }
            PublicKey serverPub = pk.getPublicKey();

            // 2) establish AES session
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            SecretKey sessionKey = kg.generateKey();
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);

            ByteBuffer kb = ByteBuffer.allocate(4 + sessionKey.getEncoded().length + 4 + iv.length);
            kb.putInt(sessionKey.getEncoded().length).put(sessionKey.getEncoded());
            kb.putInt(iv.length).put(iv);
            byte[] keyPacket = kb.array();

            byte[] encKeyPkt = PacketUtils.encryptKeyPacket(keyPacket, serverPub);
            output.writeObject(encKeyPkt);
            output.flush();
            System.out.println("✅ Exchanged AES session key.");

            // 3) register or login?
            System.out.print("Choose [register|login]: ");
            String action = scanner.nextLine().trim().toLowerCase();
            while (!action.equals("register") && !action.equals("login")) {
                System.out.print("Choose [register|login]: ");
                action = scanner.nextLine().trim().toLowerCase();
            }

            if (action.equals("register")) {
                // —— REGISTER FLOW ——
                System.out.print("New username: ");
                String u = scanner.nextLine();

                System.out.print("New password: ");
                String password = scanner.nextLine();

                // 1) Generate RSA identity keypair
                KeyPair userIdentityKeyPair = RSAKeys.generateKeyPair();

                // 2) Generate X25519 identity keypair
                KeyPair x25519IdentityKeyPair =
                        KeyPairGenerator.getInstance("X25519").generateKeyPair();
                // **store into your client‐wide fields** for the listener:
                x25519IdentityPriv = x25519IdentityKeyPair.getPrivate();
                x25519IdentityPub  = x25519IdentityKeyPair.getPublic();

                // 3) Generate X25519 signed‐pre‐key + signature
                KeyPair userSignedPreKeyPair =
                        KeyPairGenerator.getInstance("X25519").generateKeyPair();
                Signature signer = Signature.getInstance("SHA256withRSA");
                signer.initSign(userIdentityKeyPair.getPrivate());
                signer.update(userSignedPreKeyPair.getPublic().getEncoded());
                byte[] signedPreKeySignature = signer.sign();

                // 4) Save all your private keys to disk
                savePrivateKeyEncrypted(
                        userIdentityKeyPair.getPrivate(),
                        password,
                        u + "_private_key.enc"
                );
                savePrivateKeyEncrypted(
                        x25519IdentityKeyPair.getPrivate(),
                        password,
                        u + "_x25519_identity_key.enc"
                );
                Files.write(
                        Paths.get(u + "_x25519_identity_pub.enc"),
                        x25519IdentityKeyPair.getPublic().getEncoded()
                );
                savePrivateKeyEncrypted(
                        userSignedPreKeyPair.getPrivate(),
                        password,
                        u + "_x25519_sprv_key.enc"
                );
                Files.write(
                        Paths.get(u + "_x25519_sprv_pub.enc"),
                        userSignedPreKeyPair.getPublic().getEncoded()
                );
                System.out.println("🔐 Keys generated and saved.");

                // 5) Send the RegisterPacket
                RegisterPacket reg = new RegisterPacket(
                        u,
                        password.getBytes(UTF_8),
                        userIdentityKeyPair.getPublic().getEncoded(),
                        x25519IdentityKeyPair.getPublic().getEncoded(),
                        userSignedPreKeyPair.getPublic().getEncoded(),
                        signedPreKeySignature
                );
                output.writeObject(PacketUtils.encryptPacketAES(reg, sessionKey));
                output.flush();

                // 6) Handle server’s InfoPacket
                InfoPacket info = (InfoPacket) PacketUtils
                        .decryptPacketAES((byte[]) input.readObject(), sessionKey);
                System.out.println("[Server] " + info.getMessage());

                if (info.getMessage().toLowerCase().contains("success")) {
                    // 7) Send one‐time keys
                    int N = 100;
                    KeyPairGenerator otpGen = KeyPairGenerator.getInstance("X25519");
                    List<KeyPair> oneTimeKPs = new ArrayList<>(N);
                    for (int i = 0; i < N; i++) oneTimeKPs.add(otpGen.generateKeyPair());
                    for (KeyPair otp : oneTimeKPs) {
                        oneTimeKeysPacket pkt =
                                new oneTimeKeysPacket(u, otp.getPublic().getEncoded());
                        output.writeObject(PacketUtils.encryptPacketAES(pkt, sessionKey));
                    }
                    saveOneTimeKeysEncrypted(oneTimeKPs, password, u + "_onetime_keys.enc");
                    System.out.println("🔐 Saved " + N + " one-time keys.");

                    // ───── NEW ───── Wire up your X25519 keys into the ratchet refs:
                    userIKPRef.set(new KeyPair(
                            x25519IdentityPub,
                            x25519IdentityPriv
                    ));
                    userSPKPRef.set(new KeyPair(
                            userSignedPreKeyPair.getPublic(),
                            userSignedPreKeyPair.getPrivate()
                    ));

                    // ───── NEW ───── Immediately consume the UserListPacket:
                    UserListPacket ul = (UserListPacket) PacketUtils
                            .decryptPacketAES((byte[]) input.readObject(), sessionKey);
                    System.out.println("👥 Online users: " + ul.getUsers());

                    // 8) Finalize your local session fields:
                    username = u;
                    userPass = password;
                    userPriv  = userIdentityKeyPair.getPrivate();
                    userPub   = userIdentityKeyPair.getPublic();

                    // ───── NEW ───── Print your normal prompt so /select works:
                    System.out.println("Type: /select <user>, /message <text>, /refresh, exit");
                } else {
                    System.err.println("Registration failed; aborting.");
                    return;
                }
            }
            else {
                // —— LOGIN FLOW ——
                System.out.print("Username: ");
                String u = scanner.nextLine();
                System.out.print("Password: ");
                String p = scanner.nextLine();

                // load RSA private + derive public
                PrivateKey priv = loadPrivateKeyFromFile(p, u + "_private_key.enc");
                PublicKey pub = derivePublicKey(priv);
                System.out.println("🔑 Loaded private key.");
                userPriv = priv;

                // ← NEW: load X25519 identity keypair
                x25519IdentityPriv = loadX25519PrivateKey(p, u + "_x25519_identity_key.enc");
                byte[] idPubBytes = Files.readAllBytes(Paths.get(u + "_x25519_identity_pub.enc"));
                x25519IdentityPub = KeyFactory
                        .getInstance("X25519")
                        .generatePublic(new X509EncodedKeySpec(idPubBytes));
                System.out.println("🔑 Loaded X25519 identity keypair.");

                // Wire it into the KeyBundle handler:
                KeyPair identityKP = new KeyPair(x25519IdentityPub, x25519IdentityPriv);
                userIKPRef.set(identityKP);

                // ← ALSO load the signed-pre-key pair
                PrivateKey x25519Spriv = loadX25519PrivateKey(p, u + "_x25519_sprv_key.enc");
                byte[] spubBytes = Files.readAllBytes(Paths.get(u + "_x25519_sprv_pub.enc"));
                PublicKey x25519Spub = KeyFactory
                        .getInstance("X25519")
                        .generatePublic(new X509EncodedKeySpec(spubBytes));
                userSPKP = new KeyPair(x25519Spub, x25519Spriv);
                System.out.println("🔑 Loaded X25519 signed-pre-key pair.");

                // Wire that in, too:
                userSPKPRef.set(userSPKP);


                // send LoginPacket
                LoginPacket login = new LoginPacket(u, p);
                output.writeObject(PacketUtils.encryptPacketAES(login, sessionKey));
                output.flush();

                // handle login result
                InfoPacket info = (InfoPacket) PacketUtils
                        .decryptPacketAES((byte[]) input.readObject(), sessionKey);
                System.out.println("[Server] " + info.getMessage());
                if (!info.getMessage().toLowerCase().contains("success")) {
                    System.err.println("Login failed; aborting.");
                    return;
                }

                // read & show online users
                UserListPacket ul = (UserListPacket) PacketUtils
                        .decryptPacketAES((byte[]) input.readObject(), sessionKey);
                System.out.println("👥 Online users: " + ul.getUsers());

                // set session fields
                x25519IdentityPriv = loadX25519PrivateKey(p, u + "_x25519_identity_key.enc");
                byte[] pubBytes = Files.readAllBytes(Paths.get(u + "_x25519_identity_pub.enc"));
                x25519IdentityPub = KeyFactory
                        .getInstance("X25519")
                        .generatePublic(new X509EncodedKeySpec(pubBytes));
                System.out.println("🔑 Loaded X25519 identity keypair.");
                // assign identity keypair for ratchet
                userIKP = new KeyPair(x25519IdentityPub, x25519IdentityPriv);

                username = u;
                userPass = p;
                userPriv  = priv;
            }

            //
            // 4) start listener thread (AES + ratchet)
            //
            final String  uname = username;
            final String  pwd   = userPass;
            PrivateKey finalUserPriv = userPriv;
            PrivateKey finalX25519IdentityPriv = x25519IdentityPriv;
            PrivateKey finalX25519IdentityPriv1 = x25519IdentityPriv;

            String finalUsername = username;
            String finalUsername1 = username;
            PublicKey finalX25519IdentityPub = x25519IdentityPub;
            new Thread(() -> {
                try {
                    while (true) {
                        Object obj = input.readObject();
                        Packet raw;
                        if (obj instanceof byte[] enc) {
                            raw = PacketUtils.decryptPacketAES(enc, sessionKey);
                        } else {
                            raw = (Packet) obj;
                        }

                        switch (raw.getType()) {
                            case "Info" -> {
                                System.out.println("[Server] " + ((InfoPacket)raw).getMessage());
                            }
                            case "UserList" -> {
                                System.out.println("[Update] " + ((UserListPacket)raw).getUsers());
                            }
                            case "KeyBundle" -> {
                                KeyBundle kr = (KeyBundle) raw;
                                String peer = selectedPeerUsernameRef.get();
                                System.out.println("Got KeyBundle for " + peer);

                                // 1️⃣ Verify their signed-prekey under their RSA identity
                                PublicKey theirRsaId = KeyFactory.getInstance("RSA")
                                        .generatePublic(new X509EncodedKeySpec(kr.getRsaIdentityPub()));
                                Signature verifier = Signature.getInstance("SHA256withRSA");
                                verifier.initVerify(theirRsaId);
                                verifier.update(kr.getX25519SigningPub());
                                if (!verifier.verify(kr.getSignature())) {
                                    System.err.println("❌ SignedPreKey signature invalid.");
                                    break;
                                }
                                System.out.println("✅ SignedPreKey valid.");

                                // 2️⃣ Store their identity pub for later
                                selectedPeerIdPubBytesRef.set(kr.getX25519IdentityPub());
                                selectedPeerKeyBundleRef.set(kr);

                                // 3️⃣ Consume our one‐time key by mapping global→local via floorMod
                                int globalOtkId = kr.getOneTimeKeyID();
                                List<KeyPair> oneTimeKPs = loadOneTimeKeyPairsEncrypted(pwd, uname + "_onetime_keys.enc");
                                int batchSize = oneTimeKPs.size();
                                int localIndex = Math.floorMod(globalOtkId - 1, batchSize);
                                if (localIndex < 0 || localIndex >= batchSize) {
                                    System.err.println("❌ Invalid one-time key slot: global=" + globalOtkId);
                                    break;
                                }
                                KeyPair usedOtk = oneTimeKPs.remove(localIndex);
                                saveOneTimeKeysEncrypted(oneTimeKPs, pwd, uname + "_onetime_keys.enc");
                                System.out.println(String.format(
                                        "🔐 Used key #%d (global #%d); %d one-time keys remain.",
                                        localIndex + 1, globalOtkId, oneTimeKPs.size()
                                ));

                                // 4️⃣ Reconstruct peer’s three public keys
                                PublicKey theirIdPub   = bytesToX25519Pub(kr.getX25519IdentityPub());
                                PublicKey theirSPub    = bytesToX25519Pub(kr.getX25519SigningPub());
                                PublicKey theirOneTime = bytesToX25519Pub(kr.getOneTimeKey());

                                // 5️⃣ Perform X3DH: EKA, IK_A, SPK_A, OTK_B ephemerals
                                KeyPair ephKP = KeyPairGenerator.getInstance("X25519").generateKeyPair();
                                byte[] dh1 = x25519(finalX25519IdentityPriv, theirSPub);      // IK_B × SPK_A
                                byte[] dh2 = x25519(ephKP.getPrivate(),        theirIdPub);   // EKA   × IK_A
                                byte[] dh3 = x25519(ephKP.getPrivate(),        theirSPub);    // EKA   × SPK_A
                                byte[] dh4 = x25519(ephKP.getPrivate(),        theirOneTime); // EKA   × OTK_A

                                // ─── Build the 4-DH masterSecret ────────────────────────────────────────
                                ByteBuffer buf = ByteBuffer.allocate(dh1.length + dh2.length + dh3.length + dh4.length);
                                buf.put(dh1).put(dh2).put(dh3).put(dh4);
                                byte[] masterSecret = buf.array();

                                // 6️⃣ HKDF → rootKey, sendCK, recvCK
                                byte[] rootKey = hkdf(new byte[32], masterSecret, "X3DH".getBytes(UTF_8), 32);
                                byte[] sendCK  = hkdfExpand(rootKey, "send".getBytes(UTF_8), 32);
                                byte[] recvCK  = hkdfExpand(rootKey, "recv".getBytes(UTF_8), 32);

                                // 7️⃣ Initialize the Double Ratchet (initiator order)
                                DoubleRatchetState dr = new DoubleRatchetState(
                                        rootKey,
                                        ephKP,
                                        theirOneTime, // use peer’s ephemeral here
                                        sendCK,
                                        recvCK
                                );
                                String peerId = Base64.getEncoder().encodeToString(kr.getX25519IdentityPub());
                                sessionStore.put(peerId, dr);
                                System.out.println("✅ Double Ratchet initialized for " + peer);

                                // 8️⃣ Send back a MadeHand with the GLOBAL OTK ID
                                KeyPair userIKPCurrent  = userIKPRef.get();
                                KeyPair userSPKPCurrent = userSPKPRef.get();
                                if (userIKPCurrent == null || userSPKPCurrent == null) {
                                    System.err.println("❌ User keypairs not loaded!");
                                    throw new IllegalStateException("User keypairs are not loaded!");
                                }
                                MadeHand mh = new MadeHand(
                                        finalUsername,                  // initiator username
                                        peer,                           // receiver username
                                        globalOtkId,                    // global one-time-key ID
                                        ephKP.getPublic().getEncoded(), // YOUR ephemeral public key
                                        userIKPCurrent.getPublic().getEncoded(),  // YOUR identity public key
                                        userSPKPCurrent.getPublic().getEncoded()  // YOUR signed-prekey public key
                                );
                                output.writeObject(PacketUtils.encryptPacketAES(mh, sessionKey));
                                output.flush();

                                // 9️⃣ Replay any buffered messages
                                List<DirectMessagePacket> bufList = pendingMessages.remove(peerId);
                                if (bufList != null) {
                                    for (DirectMessagePacket old : bufList) {
                                        DoubleRatchetState.Message env =
                                                new DoubleRatchetState.Message(old.getHeaderPub(), old.getIv(), old.getCiphertext());
                                        byte[] plain = dr.decrypt(env);
                                        System.out.println("💬 " + old.getSender() + ": " + new String(plain, UTF_8));
                                        saveRatchetStateEncrypted(dr, pwd, uname + "_" + old.getSender() + ".ratchet");
                                    }
                                }
                            }



                            case "HandShake2Packet" -> {
                                HandShake2Packet p2 = (HandShake2Packet) raw;
                                String peer = selectedPeerUsernameRef.get();
                                System.out.println("Got HandShake2Packet for " + peer + ", keyId=" + p2.getKey());

                                // ❸ Retrieve the previously stored KeyBundle
                                KeyBundle kr = selectedPeerKeyBundleRef.get();
                                if (kr == null) {
                                    System.err.println("❌ No stored KeyBundle for " + peer);
                                    break;
                                }

                                // ❹ Consume the one-time key by its local index
                                int otkId = p2.getKey();
                                List<KeyPair> oneTimeKPs = loadOneTimeKeyPairsEncrypted(pwd, uname + "_onetime_keys.enc");
                                if (oneTimeKPs.isEmpty()) {
                                    System.err.println("❌ No one-time keys left!");
                                    break;
                                }
                                if (otkId < 1 || otkId > oneTimeKPs.size()) {
                                    System.err.println("❌ Invalid one-time key ID: " + otkId);
                                    break;
                                }
                                KeyPair usedOtk = oneTimeKPs.remove(otkId - 1);
                                saveOneTimeKeysEncrypted(oneTimeKPs, pwd, uname + "_onetime_keys.enc");
                                System.out.println("🔐 " + oneTimeKPs.size() + " one-time keys remain.");

                                // ❺ Perform the same X3DH DH operations
                                PublicKey theirX25519Id   = bytesToX25519Pub(kr.getX25519IdentityPub());
                                PublicKey theirX25519SPub = bytesToX25519Pub(kr.getX25519SigningPub());
                                PublicKey theirX25519OT   = bytesToX25519Pub(kr.getOneTimeKey());

                                KeyPair ephKP = KeyPairGenerator.getInstance("X25519").generateKeyPair();
                                byte[] dh1 = x25519(finalX25519IdentityPriv, theirX25519SPub);
                                byte[] dh2 = x25519(ephKP.getPrivate(),        theirX25519Id);
                                byte[] dh3 = x25519(ephKP.getPrivate(),        theirX25519SPub);
                                byte[] dh4 = x25519(usedOtk.getPrivate(),      theirX25519OT);

                                ByteBuffer buf = ByteBuffer.allocate(dh1.length + dh2.length + dh3.length + dh4.length);
                                buf.put(dh1).put(dh2).put(dh3).put(dh4);
                                byte[] masterSecret = buf.array();

                                // ❻ Derive root+chain keys, init ratchet, replay
                                byte[] rootKey = hkdf(new byte[32], masterSecret, "X3DH".getBytes(UTF_8), 32);
                                byte[] sendCK  = hkdfExpand(rootKey, "send".getBytes(UTF_8), 32);
                                byte[] recvCK  = hkdfExpand(rootKey, "recv".getBytes(UTF_8), 32);

                                DoubleRatchetState dr = new DoubleRatchetState(
                                        rootKey,
                                        ephKP,
                                        theirX25519SPub,
                                        sendCK,
                                        recvCK
                                );
                                String peerId = Base64.getEncoder().encodeToString(kr.getX25519IdentityPub());
                                sessionStore.put(peerId, dr);
                                System.out.println("✅ Double Ratchet initialized for " + peer);

                                List<DirectMessagePacket> bufList = pendingMessages.remove(peerId);
                                if (bufList != null) {
                                    for (DirectMessagePacket old : bufList) {
                                        DoubleRatchetState.Message env = new DoubleRatchetState.Message(
                                                old.getHeaderPub(),
                                                old.getIv(),
                                                old.getCiphertext()
                                        );
                                        byte[] plain = dr.decrypt(env);
                                        System.out.println("💬 " + old.getSender() + ": " + new String(plain, UTF_8));
                                        saveRatchetStateEncrypted(dr, pwd, uname + "_" + old.getSender() + ".ratchet");
                                    }
                                }
                            }

                            case "HandShakeAlreadyMade" -> {
                                HandShakeAlreadyMade hsam = (HandShakeAlreadyMade) raw;
                                String peer = hsam.getInitiator();
                                System.out.println("🔄 Got HandShakeAlreadyMade from " + peer);

                                // 1️⃣ Track who we're talking to
                                selectedPeerIdPubBytesRef.set(hsam.getPeerIdentityPub());

                                // 2️⃣ Consume our one-time X25519 keypair
                                int globalOtkId = hsam.getKeyId();
                                List<KeyPair> oneTimeKPs = loadOneTimeKeyPairsEncrypted(pwd, uname + "_onetime_keys.enc");
                                int batchSize    = oneTimeKPs.size();

                                // fold the global ID into [0..batchSize-1]
                                int localIndex = Math.floorMod(globalOtkId - 1, batchSize);

                                // sanity check (should never fail with floorMod)
                                if (localIndex < 0 || localIndex >= batchSize) {
                                    System.err.println("❌ Computed local key index out of range: " + localIndex);
                                    break;
                                }

                                KeyPair myEphKP = oneTimeKPs.remove(localIndex);
                                saveOneTimeKeysEncrypted(oneTimeKPs, pwd, uname + "_onetime_keys.enc");

                                int localId = localIndex + 1;
                                System.out.println(String.format(
                                        "🔐 Used key #%d (global #%d); %d one-time keys remain.",
                                        localId, globalOtkId, oneTimeKPs.size()
                                ));

                                System.out.println("🔐 " + oneTimeKPs.size() + " one-time keys remain.");

                                // 3️⃣ Reconstruct public keys from the packet
                                PublicKey theirIdPub  = bytesToX25519Pub(hsam.getPeerIdentityPub()); // IK_A
                                PublicKey theirSpub   = bytesToX25519Pub(hsam.getPeerSigningPub());  // SPK_A
                                PublicKey theirEphPub = bytesToX25519Pub(hsam.getOneTimeKey());      // EK_A

                                // 4️⃣ Grab B's own keypairs:
                                KeyPair  spkpPair = userSPKPRef.get();       // SPK_B
                                PrivateKey spkB   = spkpPair.getPrivate();
                                PrivateKey ikB    = finalX25519IdentityPriv; // IK_B
                                PrivateKey otkB   = myEphKP.getPrivate();    // OTK_B

                                // 5️⃣ Now do *B’s* four DHs in the spec order:
                                byte[] dh1 = x25519(spkB,    theirIdPub);    // SPK_B priv  vs IK_A pub
                                byte[] dh2 = x25519(ikB,     theirEphPub);   // IK_B priv   vs EK_A pub
                                byte[] dh3 = x25519(spkB,    theirEphPub);   // SPK_B priv  vs EK_A pub
                                byte[] dh4 = x25519(otkB,    theirEphPub);   // OTK_B priv  vs EK_A pub

                                // ─── Build the masterSecret ────────────────────────────────────────────────
                                ByteBuffer buf = ByteBuffer.allocate(
                                        dh1.length + dh2.length + dh3.length + dh4.length
                                );
                                buf.put(dh1).put(dh2).put(dh3).put(dh4);
                                byte[] masterSecret = buf.array();

                                // ─── Now you can derive root + chain keys ─────────────────────────────────

                                // 6️⃣ Derive root & chains (same as before)
                                byte[] rootKey = hkdf(new byte[32], masterSecret, "X3DH".getBytes(UTF_8), 32);
                                byte[] sendCK  = hkdfExpand(rootKey, "send".getBytes(UTF_8), 32);
                                byte[] recvCK  = hkdfExpand(rootKey, "recv".getBytes(UTF_8), 32);

                                // 7️⃣ Swap send/recv for the very first ratchet message:
                                DoubleRatchetState dr = new DoubleRatchetState(
                                        rootKey,
                                        myEphKP,
                                        theirEphPub,
                                        recvCK,
                                        sendCK
                                );



                                String peerId = Base64.getEncoder().encodeToString(hsam.getPeerIdentityPub());
                                sessionStore.put(peerId, dr);
                                System.out.println("✅ Double Ratchet initialized for " + peer);

                                // 8️⃣ Replay any buffered messages
                                List<DirectMessagePacket> bufList = pendingMessages.remove(peerId);
                                if (bufList != null) {
                                    for (DirectMessagePacket old : bufList) {
                                        DoubleRatchetState.Message env = new DoubleRatchetState.Message(
                                                old.getHeaderPub(), old.getIv(), old.getCiphertext()
                                        );
                                        byte[] plain = dr.decrypt(env);
                                        System.out.println("💬 " + old.getSender() + ": " + new String(plain, UTF_8));
                                        saveRatchetStateEncrypted(dr, pwd, uname + "_" + old.getSender() + ".ratchet");
                                    }
                                }
                            }



                            case "DirectMessage" -> {
                                // unwrap from AES first:
                                DirectMessagePacket inPkt = (DirectMessagePacket) raw;

                                String peerId = Base64.getEncoder().encodeToString(
                                        selectedPeerIdPubBytesRef.get()
                               );
                                DoubleRatchetState dr = sessionStore.get(peerId);

                                if (dr == null) {
                                    // buffer until after we do the handshake
                                    pendingMessages
                                            .computeIfAbsent(peerId, k -> new ArrayList<>())
                                            .add(inPkt);
                                } else {
                                    // reconstruct the Message object
                                    DoubleRatchetState.Message env = new DoubleRatchetState.Message(
                                            inPkt.getHeaderPub(),
                                            inPkt.getIv(),
                                            inPkt.getCiphertext()
                                    );
                                    // **Use the decrypt() method**:
                                    byte[] plain = dr.decrypt(env);
                                    System.out.println("💬 " + inPkt.getSender() + ": " + new String(plain, UTF_8));
                                    // persist ratchet state
                                    saveRatchetStateEncrypted(dr, pwd, uname + "_" + inPkt.getSender() + ".ratchet");
                                }
                            }


                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    System.out.println("Listener stopped.");
                }
            }, "Listener").start();

            //
            // 5) main loop: select, refresh, message
            //
            System.out.println("Type: /select <user>, /message <text>, /refresh, exit");
            while (true) {
                String line = scanner.nextLine().trim();
                if (line.equalsIgnoreCase("exit")) break;

                if (line.startsWith("/select ")) {
                    selectedPeerUsernameRef.set(line.substring(8).trim());
                    String peer = selectedPeerUsernameRef.get();
                    HandShakePacket mao = new HandShakePacket(username, peer);
                    output.writeObject(PacketUtils.encryptPacketAES(mao, sessionKey));
                    output.flush();
                    continue;
                }


                if (line.equalsIgnoreCase("/refresh")) {
                    UserListRequestPacket req = new UserListRequestPacket();
                    byte[] encReq = PacketUtils.encryptPacketAES(req, sessionKey);
                    output.writeObject(encReq);
                    output.flush();
                    continue;
                }

                if (line.startsWith("/message ")) {
                    // 1️⃣ fetch the peer you already selected
                    String peer = selectedPeerUsernameRef.get();
                    byte[] peerIdBytes = selectedPeerIdPubBytesRef.get();
                    if (peer == null || peerIdBytes == null) {
                        System.err.println("No peer selected or handshake incomplete. Use /select first.");
                        continue;
                    }

                    // 2️⃣ grab the plaintext after "/message "
                    String text = line.substring(9);

                    // 3️⃣ lookup your DoubleRatchetState
                    String peerId = Base64.getEncoder().encodeToString(peerIdBytes);
                    DoubleRatchetState dr = sessionStore.get(peerId);
                    if (dr == null) {
                        System.err.println("Ratchet not initialized for " + peer);
                        continue;
                    }

                    // 4️⃣ encrypt with the ratchet
                    DoubleRatchetState.Message env = dr.encrypt(text.getBytes(UTF_8));

                    // 5️⃣ wrap in your DirectMessagePacket
                    DirectMessagePacket outPkt = new DirectMessagePacket(
                            username,
                            peer,
                            env.headerPub,
                            env.iv,
                            env.ciphertext
                    );

                    // 6️⃣ AES-encrypt for transport
                    byte[] wrapped = PacketUtils.encryptPacketAES(outPkt, sessionKey);
                    output.writeObject(wrapped);
                    output.flush();

                    // 7️⃣ persist the updated ratchet state
                    saveRatchetStateEncrypted(dr, userPass, username + "_" + peer + ".ratchet");

                    System.out.println("→ Sent to " + peer + ": " + text);
                    continue;
                }



                System.out.println("Unknown command. Use /select, /message or /refresh.");
            }

            System.out.println("Client shutting down.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // --- all your save/load methods unchanged below ---

    private static void savePrivateKeyEncrypted(PrivateKey priv, String password, String filename) throws Exception {
        byte[] pkcs8 = priv.getEncoded();
        byte[] salt = new byte[16]; new SecureRandom().nextBytes(salt);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = f.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = c.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
        byte[] cipherText = c.doFinal(pkcs8);
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(salt); fos.write(iv); fos.write(cipherText);
        }
    }

    private static PrivateKey loadPrivateKeyFromFile(String password, String filename) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(filename));
        ByteBuffer buf = ByteBuffer.wrap(data);
        byte[] salt = new byte[16]; buf.get(salt);
        byte[] iv   = new byte[16]; buf.get(iv);
        byte[] cipherText = new byte[buf.remaining()]; buf.get(cipherText);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = f.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] pkcs8 = c.doFinal(cipherText);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    private static void saveOneTimeKeysEncrypted(
            List<KeyPair> keyPairs,
            String password,
            String filename
    ) throws Exception {
        // 1) Build a textual "1: key" listing, Base64-encoding each key
        StringBuilder sb = new StringBuilder();
        int index = 1;
        Base64.Encoder b64 = Base64.getEncoder();
        for (KeyPair kp : keyPairs) {
            // public key
            String pubB64 = b64.encodeToString(kp.getPublic().getEncoded());
            sb.append(index++)
                    .append(": ")
                    .append(pubB64)
                    .append(System.lineSeparator());

            // private key
            String privB64 = b64.encodeToString(kp.getPrivate().getEncoded());
            sb.append(index++)
                    .append(": ")
                    .append(privB64)
                    .append(System.lineSeparator());
        }
        byte[] plain = sb.toString().getBytes(StandardCharsets.UTF_8);

        // 2) Derive a salt and AES key from the password
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65_536, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

        // 3) Encrypt with AES/CBC/PKCS5Padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = cipher.getParameters()
                .getParameterSpec(IvParameterSpec.class)
                .getIV();
        byte[] ciphertext = cipher.doFinal(plain);

        // 4) Write out: [salt][iv][ciphertext]
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(salt);
            fos.write(iv);
            fos.write(ciphertext);
        }
    }

    public static PublicKey loadOneTimeX25519PublicKeyEncrypted(
            String filename,
            String password,
            int keyIndex
    ) throws Exception {
        if ((keyIndex & 1) == 0) {
            throw new IllegalArgumentException("X25519 loader only returns public keys; choose an odd index");
        }

        // 1) Read salt + iv + ciphertext
        byte[] salt = new byte[16];
        byte[] iv   = new byte[16];
        byte[] ciphertext;
        try (FileInputStream fis = new FileInputStream(filename)) {
            if (fis.read(salt)   != salt.length)   throw new IOException("Could not read salt");
            if (fis.read(iv)     != iv.length)     throw new IOException("Could not read IV");
            ciphertext = fis.readAllBytes();
        }

        // 2) Re-derive AES key with PBKDF2-HMAC-SHA256
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65_536, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

        // 3) Decrypt with AES/CBC/PKCS5Padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] plain = cipher.doFinal(ciphertext);

        // 4) Parse lines "index: Base64" → map
        String content = new String(plain, StandardCharsets.UTF_8);
        String[] lines = content.split("\\R");
        Base64.Decoder b64 = Base64.getDecoder();
        Map<Integer, byte[]> map = new HashMap<>();
        for (String line : lines) {
            if (line.isBlank()) continue;
            String[] parts = line.split(":", 2);
            int idx = Integer.parseInt(parts[0].trim());
            map.put(idx, b64.decode(parts[1].trim()));
        }

        // 5) Decode your chosen public key
        byte[] keyDer = map.get(keyIndex);
        if (keyDer == null) {
            throw new IllegalArgumentException("No key at index " + keyIndex);
        }

        // 6) Rebuild X25519 public key
        KeyFactory kf = KeyFactory.getInstance("X25519");
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(keyDer);
        return kf.generatePublic(pubSpec);
    }

    private static KeyPair loadOneTimeKeyPairEncrypted(
            String password,
            String filename,
            int pairNumber
    ) throws Exception {
        // 1) read file → salt | iv | ciphertext
        byte[] file = Files.readAllBytes(Paths.get(filename));
        ByteBuffer buf = ByteBuffer.wrap(file);

        byte[] salt = new byte[16];
        buf.get(salt);

        byte[] iv = new byte[16];
        buf.get(iv);

        byte[] cipherText = new byte[buf.remaining()];
        buf.get(cipherText);

        // 2) derive AES key from password + salt
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65_536, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

        // 3) decrypt
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] plain = cipher.doFinal(cipherText);

        // 4) split into lines
        String text = new String(plain, StandardCharsets.UTF_8).trim();
        String[] lines = text.split("\\R");  // split on any line break

        // 5) locate the two lines for this pair
        //    each pair i occupies lines[(i-1)*2] (pub) and [(i-1)*2 + 1] (priv)
        int pubLineIndex  = (pairNumber - 1) * 2;
        int privLineIndex = pubLineIndex + 1;

        if (pubLineIndex < 0 || privLineIndex >= lines.length) {
            throw new IllegalArgumentException(
                    "Requested pairNumber=" + pairNumber +
                            " is out of range; only " + (lines.length/2) + " pairs available."
            );
        }

        // 6) extract Base64 payload after the colon
        Base64.Decoder b64 = Base64.getDecoder();
        String pubB64  = lines[pubLineIndex].split(":", 2)[1].trim();
        String privB64 = lines[privLineIndex].split(":", 2)[1].trim();

        byte[] pubBytes  = b64.decode(pubB64);
        byte[] privBytes = b64.decode(privB64);

        // 7) rebuild X25519 key objects
        KeyFactory kf = KeyFactory.getInstance("X25519");
        PublicKey pubKey = kf.generatePublic(new X509EncodedKeySpec(pubBytes));
        PrivateKey privKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privBytes));

        return new KeyPair(pubKey, privKey);
    }

    private static List<KeyPair> loadOneTimeKeyPairsEncrypted(
            String password,
            String filename
    ) throws Exception {
        // 1) read file → salt | iv | ciphertext
        byte[] file = Files.readAllBytes(Paths.get(filename));
        ByteBuffer buf = ByteBuffer.wrap(file);

        byte[] salt = new byte[16];
        buf.get(salt);

        byte[] iv = new byte[16];
        buf.get(iv);

        byte[] cipherText = new byte[buf.remaining()];
        buf.get(cipherText);

        // 2) derive AES key
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65_536, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

        // 3) decrypt
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] plain = cipher.doFinal(cipherText);

        // 4) split & rebuild all pairs
        String text = new String(plain, StandardCharsets.UTF_8).trim();
        String[] lines = text.split("\\R");

        Base64.Decoder b64 = Base64.getDecoder();
        KeyFactory kf = KeyFactory.getInstance("X25519");
        List<KeyPair> pairs = new ArrayList<>();

        for (int i = 0; i < lines.length; i += 2) {
            // pub
            String pubB64  = lines[i].split(":", 2)[1].trim();
            byte[] pubBytes = b64.decode(pubB64);
            PublicKey pubKey = kf.generatePublic(new X509EncodedKeySpec(pubBytes));

            // priv
            String privB64 = lines[i+1].split(":", 2)[1].trim();
            byte[] privBytes = b64.decode(privB64);
            PrivateKey privKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privBytes));

            pairs.add(new KeyPair(pubKey, privKey));
        }

        return pairs;
    }


    private static byte[] x25519(PrivateKey sk, PublicKey pk) throws GeneralSecurityException {
        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(sk);
        ka.doPhase(pk, true);
        return ka.generateSecret();
    }

    private static PublicKey bytesToX25519Pub(byte[] raw) throws GeneralSecurityException {
        return KeyFactory.getInstance("X25519")
                .generatePublic(new X509EncodedKeySpec(raw));
    }

    private static PublicKey derivePublicKey(PrivateKey priv) throws Exception {
        RSAPrivateCrtKey crt = (RSAPrivateCrtKey) priv;
        RSAPublicKeySpec spec = new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent());
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    private static byte[] hkdfExtract(byte[] salt, byte[] ikm) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt != null ? salt : new byte[32], "HmacSHA256"));
        return mac.doFinal(ikm);
    }

    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        byte[] okm = new byte[length], t = new byte[0];
        int copied = 0; byte counter = 1;
        while (copied < length) {
            mac.reset();
            mac.update(t);
            if (info != null) mac.update(info);
            mac.update(counter++);
            t = mac.doFinal();
            int toCopy = Math.min(t.length, length - copied);
            System.arraycopy(t, 0, okm, copied, toCopy);
            copied += toCopy;
        }
        return okm;
    }

    private static byte[] hkdf(byte[] salt, byte[] ikm, byte[] info, int length)
            throws GeneralSecurityException {
        byte[] prk = hkdfExtract(salt, ikm);
        return hkdfExpand(prk, info, length);
    }

    public static void saveRatchetStateEncrypted(
            DoubleRatchetState state, String password, String filename
    ) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(state);
        }
        byte[] plain = baos.toByteArray();
        byte[] salt = new byte[16]; new SecureRandom().nextBytes(salt);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = f.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
        byte[] ciphertext = cipher.doFinal(plain);
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(salt); fos.write(iv); fos.write(ciphertext);
        }
    }

    public static DoubleRatchetState loadRatchetStateEncrypted(
            String password, String filename
    ) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(filename));
        ByteBuffer buf = ByteBuffer.wrap(data);
        byte[] salt = new byte[16]; buf.get(salt);
        byte[] iv   = new byte[16]; buf.get(iv);
        byte[] cipherText = new byte[buf.remaining()]; buf.get(cipherText);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = f.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] plain = cipher.doFinal(cipherText);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(plain))) {
            return (DoubleRatchetState) ois.readObject();
        }
    }

    private static PrivateKey loadX25519PrivateKey(String password, String filename) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(filename));
        ByteBuffer buf = ByteBuffer.wrap(data);

        byte[] salt = new byte[16]; buf.get(salt);
        byte[] iv   = new byte[16]; buf.get(iv);
        byte[] cipherText = new byte[buf.remaining()]; buf.get(cipherText);

        // derive AES key
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = f.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

        // decrypt
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] pkcs8 = c.doFinal(cipherText);

        // parse as X25519 private
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8);
        return KeyFactory.getInstance("X25519").generatePrivate(keySpec);
    }

}
