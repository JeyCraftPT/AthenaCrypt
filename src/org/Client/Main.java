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

            // user state
            String   username   = null;
            String   userPass   = null;
            PublicKey  userPub     = null;
            PrivateKey userPriv;

            // for register flow
            KeyPair userIKP  = null;
            KeyPair userSPKP = null;

            PrivateKey x25519IdentityPriv = null;


            // for selecting peers
            String   selectedPeerUsername   = null;
            //byte[]   selectedPeerIdPubBytes = null;
            final AtomicReference<byte[]> selectedPeerIdPubBytesRef = new AtomicReference<>();

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

                // 1) RSA identity-key
                KeyPair userIdentityKeyPair = RSAKeys.generateKeyPair();

                // 2) X25519 identity-key
                KeyPair x25519IdentityKeyPair =
                        KeyPairGenerator.getInstance("X25519").generateKeyPair();

                // 3) X25519 signed-pre-key + RSA signature
                KeyPair userSignedPreKeyPair =
                        KeyPairGenerator.getInstance("X25519").generateKeyPair();
                Signature signer = Signature.getInstance("SHA256withRSA");
                signer.initSign(userIdentityKeyPair.getPrivate());
                signer.update(userSignedPreKeyPair.getPublic().getEncoded());
                byte[] signedPreKeySignature = signer.sign();

                // 4) send RegisterPacket
                RegisterPacket reg = new RegisterPacket(
                        u,
                        password.getBytes(UTF_8),
                        userIdentityKeyPair.getPublic().getEncoded(),
                        x25519IdentityKeyPair.getPublic().getEncoded(),
                        userSignedPreKeyPair.getPublic().getEncoded(),
                        signedPreKeySignature
                );
                output.writeObject(PacketUtils.encryptPacketAES(reg, sessionKey, iv));
                output.flush();

                // 5) handle response
                InfoPacket info = (InfoPacket) PacketUtils
                        .decryptPacketAES((byte[]) input.readObject(), sessionKey, iv);
                System.out.println("[Server] " + info.getMessage());

                if (info.getMessage().toLowerCase().contains("success")) {
                    // save RSA identity private key
                    savePrivateKeyEncrypted(
                            userIdentityKeyPair.getPrivate(),
                            password,
                            u + "_private_key.enc"
                    );
                    System.out.println("🔐 Private key saved.");

                    // ← NEW: save X25519 identity private key
                    savePrivateKeyEncrypted(
                            x25519IdentityKeyPair.getPrivate(),
                            password,
                            u + "_x25519_identity_key.enc"
                    );
                    System.out.println("🔐 X25519 identity key saved.");
                    x25519IdentityPriv = x25519IdentityKeyPair.getPrivate();

                    // generate + send one-time keys
                    int N = 100;
                    List<KeyPair> oneTimeKPs = new ArrayList<>(N);
                    KeyPairGenerator otpGen = KeyPairGenerator.getInstance("X25519");
                    for (int i = 0; i < N; i++) {
                        oneTimeKPs.add(otpGen.generateKeyPair());
                    }
                    for (KeyPair otp : oneTimeKPs) {
                        oneTimeKeysPacket pkt =
                                new oneTimeKeysPacket(u, otp.getPublic().getEncoded());
                        byte[] encrypted = PacketUtils.encryptPacketAES(pkt, sessionKey, iv);
                        output.writeObject(encrypted);
                        output.flush();
                    }
                    saveOneTimeKeysEncrypted(oneTimeKPs, password,
                            u + "_onetime_keys.enc");
                    System.out.println("🔐 Saved "+N+" one-time keys.");

                    // set session fields
                    username = u;
                    userPass = password;
                    userPriv  = userIdentityKeyPair.getPrivate();
                    userPub   = userIdentityKeyPair.getPublic();
                    userIKP   = userIdentityKeyPair;
                    userSPKP  = userSignedPreKeyPair;
                } else {
                    userPriv = null;
                    System.err.println("Registration failed; aborting.");
                    return;
                }

            } else {
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

                // ← NEW: load X25519 private key
                x25519IdentityPriv = loadX25519PrivateKey(p, u + "_x25519_identity_key.enc");
                System.out.println("🔑 Loaded X25519 identity key.");

                // load one-time keys
                List<KeyPair> oneTimeKPs =
                        loadOneTimeKeyPairsEncrypted(p, u + "_onetime_keys.enc");
                System.out.println("🔑 Loaded " + oneTimeKPs.size() + " one-time keys.");

                // ← NEW: re-send one-time keys to server so they’re back in the DB
                for (KeyPair otp : oneTimeKPs) {
                    oneTimeKeysPacket pkt =
                            new oneTimeKeysPacket(u, otp.getPublic().getEncoded());
                    byte[] encrypted = PacketUtils.encryptPacketAES(pkt, sessionKey, iv);
                    output.writeObject(encrypted);
                    output.flush();
                }
                System.out.println("🔁 Re-sent one-time keys to server.");

                // send LoginPacket
                LoginPacket login = new LoginPacket(u, p);
                output.writeObject(PacketUtils.encryptPacketAES(login, sessionKey, iv));
                output.flush();

                // handle login result
                InfoPacket info = (InfoPacket) PacketUtils
                        .decryptPacketAES((byte[]) input.readObject(), sessionKey, iv);
                System.out.println("[Server] " + info.getMessage());
                if (!info.getMessage().toLowerCase().contains("success")) {
                    System.err.println("Login failed; aborting.");
                    return;
                }

                // read & show online users
                UserListPacket ul = (UserListPacket) PacketUtils
                        .decryptPacketAES((byte[]) input.readObject(), sessionKey, iv);
                System.out.println("👥 Online users: " + ul.getUsers());

                // set session fields
                username = u;
                userPass = p;
                userPriv  = priv;
                userPub   = pub;
            }

            //
            // 4) start listener thread (AES + ratchet)
            //
            final String  uname = username;
            final String  pwd   = userPass;
            PrivateKey finalUserPriv = userPriv;
            PrivateKey finalX25519IdentityPriv = x25519IdentityPriv;
            PrivateKey finalX25519IdentityPriv1 = x25519IdentityPriv;
            new Thread(() -> {
                try {
                    while (true) {
                        Packet raw = (Packet) input.readObject();
                        switch (raw.getType()) {
                            case "Info" -> {
                                System.out.println("[Server] " + ((InfoPacket)raw).getMessage());
                            }
                            case "UserList" -> {
                                System.out.println("[Update] " + ((UserListPacket)raw).getUsers());
                            }
                            case "KeyBundle" -> {
                                KeyBundle kr = (KeyBundle) raw;
                                // verify signature
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

                                // capture peer ID bytes for later messaging
                                selectedPeerIdPubBytesRef.set(kr.getRsaIdentityPub());

                                // consume one-time key
                                List<KeyPair> oneTimeKPs = loadOneTimeKeyPairsEncrypted(pwd, uname + "_onetime_keys.enc");
                                if (oneTimeKPs.isEmpty()) {
                                    System.err.println("❌ No one-time keys left!");
                                    break;
                                }
                                oneTimeKPs.remove(0);
                                saveOneTimeKeysEncrypted(oneTimeKPs, pwd, uname + "_onetime_keys.enc");
                                System.out.println("🔐 " + oneTimeKPs.size() + " one-time keys remain.");

                                // DH inputs
                                PublicKey theirX25519Id   = bytesToX25519Pub(kr.getX25519IdentityPub());
                                PublicKey theirX25519SPub = bytesToX25519Pub(kr.getX25519SigningPub());
                                PublicKey theirX25519OT   = bytesToX25519Pub(kr.getOneTimeKey());

                                // our ephemeral
                                KeyPair ephKP = KeyPairGenerator.getInstance("X25519").generateKeyPair();
                                byte[] dh1 = x25519(finalX25519IdentityPriv1, theirX25519SPub);
                                byte[] dh2 = x25519(ephKP.getPrivate(),   theirX25519Id);
                                byte[] dh3 = x25519(ephKP.getPrivate(),   theirX25519SPub);
                                byte[] dh4 = x25519(ephKP.getPrivate(),   theirX25519OT);

                                // build master secret
                                ByteBuffer buf = ByteBuffer.allocate(dh1.length + dh2.length + dh3.length + dh4.length);
                                buf.put(dh1).put(dh2).put(dh3).put(dh4);
                                byte[] masterSecret = buf.array();

                                // HKDF → root + chain keys
                                byte[] rootKey = hkdf(new byte[32], masterSecret, "X3DH".getBytes(UTF_8), 32);
                                byte[] sendCK  = hkdfExpand(rootKey, "send".getBytes(UTF_8), 32);
                                byte[] recvCK  = hkdfExpand(rootKey, "recv".getBytes(UTF_8), 32);

                                // init ratchet
                                DoubleRatchetState dr = new DoubleRatchetState(
                                        rootKey,
                                        ephKP.getPrivate(),
                                        theirX25519SPub,
                                        sendCK,
                                        recvCK
                                );
                                String peerId = Base64.getEncoder().encodeToString(kr.getRsaIdentityPub());
                                sessionStore.put(peerId, dr);
                                System.out.println("✅ Double Ratchet initialized.");

                                // ▶ replay any buffered messages
                                List<DirectMessagePacket> bufList = pendingMessages.remove(peerId);
                                if (bufList != null) {
                                    for (DirectMessagePacket old : bufList) {
                                        DoubleRatchetState.Message env =
                                                new DoubleRatchetState.Message(
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
                            case "DirectMessage" -> {
                                DirectMessagePacket in = (DirectMessagePacket) raw;
                                String peerId = Base64.getEncoder().encodeToString(in.getHeaderPub());
                                DoubleRatchetState dr = sessionStore.get(peerId);

                                if (dr == null) {
                                    // buffer until after handshake
                                    pendingMessages
                                            .computeIfAbsent(peerId, k -> new ArrayList<>())
                                            .add(in);
                                } else {
                                    // decrypt & print
                                    DoubleRatchetState.Message env =
                                            new DoubleRatchetState.Message(
                                                    in.getHeaderPub(),
                                                    in.getIv(),
                                                    in.getCiphertext()
                                            );
                                    byte[] plain = dr.decrypt(env);
                                    System.out.println("💬 " + in.getSender() + ": " + new String(plain, UTF_8));
                                    saveRatchetStateEncrypted(dr, pwd, uname + "_" + in.getSender() + ".ratchet");
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
                    selectedPeerUsername = line.substring(8).trim();
                    output.writeObject(PacketUtils.encryptPacketAES(
                            new BundleRequestPacket(username, selectedPeerUsername),
                            sessionKey, iv
                    ));
                    output.flush();
                    System.out.println("-- Requested KeyBundle for " + selectedPeerUsername);
                    continue;
                }

                if (line.equalsIgnoreCase("/refresh")) {
                    UserListRequestPacket req = new UserListRequestPacket();
                    byte[] encReq = PacketUtils.encryptPacketAES(req, sessionKey, iv);
                    output.writeObject(encReq);
                    output.flush();
                    continue;
                }

                if (line.startsWith("/message ")) {
                    byte[] peerIdBytes = selectedPeerIdPubBytesRef.get();
                    if (selectedPeerUsername == null || peerIdBytes == null) {
                        System.err.println("No peer selected or handshake incomplete. Use /select first.");
                        continue;
                    }
                    String text = line.substring(9);
                    String peerId = Base64.getEncoder().encodeToString(peerIdBytes);
                    DoubleRatchetState dr = sessionStore.get(peerId);
                    if (dr == null) {
                        System.err.println("Ratchet not initialized for " + selectedPeerUsername);
                        continue;
                    }
                    DoubleRatchetState.Message env = dr.encrypt(text.getBytes(UTF_8));
                    DirectMessagePacket outPkt = new DirectMessagePacket(
                            username,
                            selectedPeerUsername,
                            env.headerPub,
                            env.iv,
                            env.ciphertext
                    );
                    output.writeObject(PacketUtils.encryptPacketAES(outPkt, sessionKey, iv));
                    output.flush();
                    saveRatchetStateEncrypted(dr, userPass, username + "_" + selectedPeerUsername + ".ratchet");
                    System.out.println("→ Sent to " + selectedPeerUsername + ": " + text);
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

    private static void saveOneTimeKeysEncrypted(List<KeyPair> keyPairs, String password, String filename) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        for (KeyPair kp : keyPairs) {
            byte[] pub = kp.getPublic().getEncoded();
            dos.writeInt(pub.length); dos.write(pub);
            byte[] pkcs8 = kp.getPrivate().getEncoded();
            dos.writeInt(pkcs8.length); dos.write(pkcs8);
        }
        dos.flush();
        byte[] plain = baos.toByteArray();
        byte[] salt = new byte[16]; new SecureRandom().nextBytes(salt);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
        byte[] ciphertext = cipher.doFinal(plain);
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(salt); fos.write(iv); fos.write(ciphertext);
        }
    }

    private static List<KeyPair> loadOneTimeKeyPairsEncrypted(String password, String filename) throws Exception {
        byte[] file = Files.readAllBytes(Paths.get(filename));
        ByteBuffer buf = ByteBuffer.wrap(file);
        byte[] salt = new byte[16]; buf.get(salt);
        byte[] iv   = new byte[16]; buf.get(iv);
        byte[] cipherText = new byte[buf.remaining()]; buf.get(cipherText);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] plain = cipher.doFinal(cipherText);
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(plain));
        List<KeyPair> pairs = new ArrayList<>();
        while (dis.available() > 0) {
            int pubLen = dis.readInt();
            byte[] pub = new byte[pubLen]; dis.readFully(pub);
            PublicKey pubKey = KeyFactory.getInstance("X25519")
                    .generatePublic(new X509EncodedKeySpec(pub));
            int privLen = dis.readInt();
            byte[] pkcs8 = new byte[privLen]; dis.readFully(pkcs8);
            PrivateKey privKey = KeyFactory.getInstance("X25519")
                    .generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
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
