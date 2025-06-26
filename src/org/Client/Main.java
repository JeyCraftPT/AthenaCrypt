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
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;


import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;

import static java.nio.charset.StandardCharsets.UTF_8;

//TODO
// remove typo "reciver" to "receiver"

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

            final Map<String, DoubleRatchetState> sessionStore = new ConcurrentHashMap<>();
            String username = null; //username
            PublicKey userPub = null; //IdentityKey
            PrivateKey userPriv = null; //IdentityPrivKey
            PublicKey userSPub = null; //SignedPreKey
            PrivateKey userPrivSPub = null; //SignedPreKey Priv
            String userPass = null;

            // 1) Receive RSA server public key
            Object o = input.readObject();
            if (!(o instanceof PublicKeyPacket pk)) {
                throw new IOException("Expected PublicKeyPacket");
            }
            PublicKey serverPub = pk.getPublicKey();

            // 2) Generate one-time AES session key + IV
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            SecretKey sessionKey = kg.generateKey();
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);

            // package key+IV
            ByteBuffer kb = ByteBuffer.allocate(4 + sessionKey.getEncoded().length + 4 + iv.length);
            kb.putInt(sessionKey.getEncoded().length).put(sessionKey.getEncoded());
            kb.putInt(iv.length).put(iv);
            byte[] keyPacket = kb.array();

            // RSA-encrypt & send it
            byte[] encKeyPkt = PacketUtils.encryptKeyPacket(keyPacket, serverPub);
            output.writeObject(encKeyPkt);
            output.flush();
            System.out.println("✅ Exchanged AES session key.");

            // 3) choose register or login, then all packets via AES:
            System.out.print("Choose [register|login]: ");
            String action = scanner.nextLine().trim().toLowerCase();
            while (!action.equals("register") && !action.equals("login")) {
                System.out.print("Choose [register|login]: ");
                action = scanner.nextLine().trim().toLowerCase();
            }

            // REGISTER
            if (action.equals("register")) {

                System.out.print("New username: ");  String u = scanner.nextLine();
                System.out.print("New password: ");  String p = scanner.nextLine();

                KeyPair userIKP = RSAKeys.generateKeyPair(); //IdentityKey
                KeyPair userSKP = RSAKeys.generateKeyPair(); //PreKey
                byte[] userSKPbytes = userSKP.getPublic().getEncoded();

                // 1) Sign the signing‐pub with the identity‐priv
                Signature signer = Signature.getInstance("SHA256withRSA");
                signer.initSign(userIKP.getPrivate());
                signer.update(userSKPbytes);
                byte[] signature = signer.sign(); //Signature of PreKey

                //TODO
                // por pass em hash tf

                // send RegisterPacket under AES, including public key bytes
                RegisterPacket reg = new RegisterPacket(u, p, userIKP.getPublic().getEncoded(), userSKP.getPublic().getEncoded(), signature);
                byte[] enc = PacketUtils.encryptPacketAES(reg, sessionKey, iv);
                output.writeObject(enc);
                output.flush();

                // receive response via AES
                byte[] respEnc = (byte[]) input.readObject();
                InfoPacket info = (InfoPacket) PacketUtils.decryptPacketAES(respEnc, sessionKey, iv);
                System.out.println("[Server] " + info.getMessage());

                // save private key locally if successful
                String msg = info.getMessage().toLowerCase();
                if (!msg.contains("error") && !msg.contains("fail")) {
                    String filename = u + "_private_key.enc";
                    savePrivateKeyEncrypted(userIKP.getPrivate(), p, filename);
                    System.out.println("🔐 Private key saved to: " + filename);
                    //TODO
                    // por isto decente <3
                    // guardar as privKeys num ficheiro cifrado com pass

                    int N = 100;  // or 10, or whatever you like
                    List<KeyPair> oneTimeKPs = new ArrayList<>(N);
                    for (int i = 0; i < N; i++) {
                        oneTimeKPs.add(RSAKeys.generateKeyPair());
                    }

                    // send only the PUBLIC halves to the server, just like before
                    for (KeyPair otp : oneTimeKPs) {
                        oneTimeKeysPacket pkt =
                                new oneTimeKeysPacket(u, otp.getPublic().getEncoded());
                        output.writeObject(pkt);
                        output.flush();
                    }

                    // now persist all the PRIVATE halves in one encrypted file
                    String otFilename = u + "_onetime_keys.enc";
                    saveOneTimeKeysEncrypted(oneTimeKPs, p, otFilename);
                    System.out.println("🔐 Saved "+N+" one-time keys to: " + otFilename);


                } else {
                    System.err.println("Registration failed; private key not saved.");
                    return;
                }

                userPub = userIKP.getPublic();
                username = u;
                userPriv = userIKP.getPrivate();
                userSPub = userSKP.getPublic();
                userPrivSPub = userSKP.getPrivate();
            }
            // LOGIN
            else {
                System.out.print("Username: ");  String u = scanner.nextLine();
                System.out.print("Password: ");  String p = scanner.nextLine();

                // load private key and derive public (not resent)
                PrivateKey userPrivF = loadPrivateKeyFromFile(p, u + "_private_key.enc");
                PublicKey userPubF = derivePublicKey(userPrivF);
                System.out.println("🔑 Loaded private RSA key from " + u + "_private_key.enc");

                // === load all of your one-time private keys ===
                String otFilename = u + "_onetime_keys.enc";
                List<PrivateKey> oneTimePrivs = loadOneTimeKeysEncrypted(p, otFilename);
                System.out.println("🔑 Loaded " + oneTimePrivs.size()
                        + " one-time private keys from: " + otFilename);

                // (Optional) if you need full KeyPair objects:
                /*List<KeyPair> oneTimeKPs = new ArrayList<>(oneTimePrivs.size());
                for (PrivateKey priv : oneTimePrivs) {
                    PublicKey pub = derivePublicKey(priv);
                    oneTimeKPs.add(new KeyPair(pub, priv));
                }*/

                // send LoginPacket under AES
                LoginPacket login = new LoginPacket(u, p);
                byte[] encLogin = PacketUtils.encryptPacketAES(login, sessionKey, iv);
                output.writeObject(encLogin);
                output.flush();

                // read InfoPacket (login result)
                byte[] infoEnc = (byte[]) input.readObject();
                Packet maybeInfo = PacketUtils.decryptPacketAES(infoEnc, sessionKey, iv);
                if (!(maybeInfo instanceof InfoPacket info)) {
                    throw new IOException("Expected InfoPacket after login, got: " + maybeInfo.getType());
                }
                System.out.println("[Server] " + info.getMessage());
                if (!info.getMessage().toLowerCase().contains("success")) {
                    System.err.println("Login failed, aborting.");
                    return;
                }

                // read UserListPacket
                byte[] listEnc = (byte[]) input.readObject();
                Packet maybeList = PacketUtils.decryptPacketAES(listEnc, sessionKey, iv);
                if (!(maybeList instanceof UserListPacket ul)) {
                    throw new IOException("Expected UserListPacket, got: " + maybeList.getType());
                }
                System.out.println("👥 Online users: " + ul.getUsers());

                userPub = userPubF;
                username = u;
                userPriv = userPrivF;
                userPass = p;
            }

            // 4) start listener thread (AES)
            PrivateKey finalUserPriv = userPriv;
            String finalUsername = username;
            String finalUsername1 = username;
            PublicKey finalUserPub = userPub;
            PrivateKey finalUserPriv1 = userPriv;
            String finalUsername2 = username;
            String finalUsername3 = username;
            String finalUserPass = userPass;
            new Thread(() -> {
                try {
                    while (true) {
                        Object obj = input.readObject();
                        Packet raw = (Packet) obj;

                        //TODO
                        // metodo para salvar chave usada/recebida

                        switch (raw.getType()) {
                            case "Info"     -> System.out.println("[Server] " + ((InfoPacket)raw).getMessage());
                            case "UserList" -> System.out.println("[Update] " + ((UserListPacket)raw).getUsers());
                            //case "DirectMessage" -> System.out.println("[Direct Message] " + ((DirectMessagePacket)raw).getMessage());
                            case "DirectMessage" ->{
                                System.out.println("Direct Message Packet");
                                String sender = ((DirectMessagePacket)raw).getSender();
                                System.out.println("[Server] " + sender);

                                byte[] message = AESKeys.decrypt(((DirectMessagePacket)raw).getMessage(), sessionKey);

                            }
                            case "AesResquest" -> {
                                System.out.println("AesRequest Packet");

                                String who = ((AESRequest)raw).getSender();
                                System.out.println("[Sender] " + who);

                                PublicKey cena = ((AESRequest)raw).getSenderPub();

                                SecretKey miau = AESKeys.generateSessionKey();

                                // Packet com sender/reciver/senderPub/senderAES
                                AESAnswer kms = new AESAnswer(finalUsername1, who, finalUserPub, RSAKeys.encrypt(miau.getEncoded(),cena));

                                output.writeObject(kms);


                                /*// who this key is for:
                                String reci = ((AESRequest) raw).getSender();
                                System.out.println("[Server] recipient = " + reci);

                                // decrypt the AES session key bytes with your RSA private key
                                byte[] sessionKeyBytes = RSAKeys
                                        .decrypt(((AESRequest) raw).getSecretKey().getEncoded(), finalUserPriv);

                                // build the filename and the line to write
                                String filename = finalUsername + "_SessionKeyCrp.enc";
                                String line     = reci + " : "
                                        + Base64.getEncoder().encodeToString(sessionKeyBytes);

                                // append this mapping to the file (creates it if necessary)
                                try (FileWriter fw = new FileWriter(filename, true)) {
                                    fw.write(line);
                                    fw.write(System.lineSeparator());
                                } catch (IOException e) {
                                    System.err.println("❌ Failed to save session key: " + e.getMessage());
                                }

                                System.out.println("🔐 Saved session key entry to: " + filename);
*/


                            }
                            case "AESAnswer_Cena" ->{
                                System.out.println("AESAnswer_Cena Packet");
                                System.out.println("criar chave AES");

                                SecretKey myAES = AESKeys.generateSessionKey();

                                System.out.println("I am: " + ((AESAnswer)raw).getRecipient());
                                System.out.println("This person sent the packet: " + ((AESAnswer)raw).getSender());
                                String respond = ((AESAnswer)raw).getSender();

                                System.out.println("Getting AES secret key");
                                PublicKey senderPub = ((AESAnswer)raw).getPublicKey();
                                byte[] senderEncAES = ((AESAnswer)raw).getSecretKey();
                                byte[] senderDecAES = RSAKeys.decrypt(senderEncAES, finalUserPriv1);

                                SecretKey senderAES = AESKeys.getKeyFromBytes(senderDecAES);


                                byte[] myEncAES = RSAKeys.encrypt(myAES.getEncoded(), senderPub);
                                AESFinal finaltrade = new AESFinal(finalUsername2, respond, myEncAES );

                                output.writeObject(finaltrade);
                                output.flush();


                            }

                            case "AESFinal" ->{
                                System.out.println("AESFinal Packet");
                                System.out.println("I am: " + ((AESFinal)raw).getRecipient());

                            }
                            case "KeyBundle" -> {
                                System.out.println("KeyBundle Packet");
                                KeyBundle kr = (KeyBundle) raw;

                                //
                                // 1) VERIFY THE SIGNED PREKEY
                                //
                                KeyFactory rsaKf = KeyFactory.getInstance("RSA");
                                PublicKey theirIdPub = rsaKf.generatePublic(
                                        new X509EncodedKeySpec(kr.getIdentityPub())
                                );

                                Signature verifier = Signature.getInstance("SHA256withRSA");
                                verifier.initVerify(theirIdPub);
                                verifier.update(kr.getSigningPub());
                                if (!verifier.verify(kr.getSignature())) {
                                    System.err.println("❌ SignedPreKey signature invalid—aborting handshake.");
                                    break;
                                }
                                System.out.println("✅ SignedPreKey signature valid.");

                                //
                                // 2) CONSUME ONE-TIME KEY
                                //
                                String otFilename = finalUsername3 + "_onetime_keys.enc";
                                List<PrivateKey> privs = loadOneTimeKeysEncrypted(finalUserPass, otFilename);
                                if (privs.isEmpty()) {
                                    System.err.println("❌ No one-time private keys left!");
                                    break;
                                }

                                PrivateKey firstPriv = privs.get(0);
                                PublicKey derived = derivePublicKey(firstPriv);
                                if (!Arrays.equals(derived.getEncoded(), kr.getOneTimeKey())) {
                                    System.err.println("❌ One-time key mismatch—aborting.");
                                    break;
                                }
                                System.out.println("✅ One-time key matches; removing.");

                                privs.remove(0);
                                List<KeyPair> remaining = new ArrayList<>(privs.size());
                                for (PrivateKey p : privs) {
                                    remaining.add(new KeyPair(derivePublicKey(p), p));
                                }
                                saveOneTimeKeysEncrypted(remaining, finalUserPass, otFilename);
                                System.out.println("🔐 Persisted " + remaining.size() + " one-time keys remaining.");

                                //
                                // 3) X3DH → FOUR-WAY DH, HKDF, ROOT + CHAIN KEYS, INIT RATCHET
                                //
                                PublicKey theirX25519Id   = bytesToX25519Pub(kr.getIdentityPub());
                                PublicKey theirX25519SPub = bytesToX25519Pub(kr.getSigningPub());
                                PublicKey theirX25519OT   = bytesToX25519Pub(kr.getOneTimeKey());

                                // our fresh ephemeral
                                KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
                                KeyPair ephKP = kpg.generateKeyPair();
                                PrivateKey ourEpriv = ephKP.getPrivate();

                                byte[] dh1 = x25519(finalUserPriv,    theirX25519SPub); // IK_A × SPK_B
                                byte[] dh2 = x25519(ourEpriv,         theirX25519Id);   // EK_A × IK_B
                                byte[] dh3 = x25519(ourEpriv,         theirX25519SPub); // EK_A × SPK_B
                                byte[] dh4 = x25519(ourEpriv,         theirX25519OT);   // EK_A × OPK_B

                                // concat all DH outputs
                                ByteBuffer buf = ByteBuffer.allocate(dh1.length + dh2.length + dh3.length + dh4.length);
                                buf.put(dh1).put(dh2).put(dh3).put(dh4);
                                byte[] masterSecret = buf.array();

                                // HKDF extract+expand → 32-byte root key
                                byte[] rootKey = hkdf(new byte[32], masterSecret, "X3DH".getBytes(UTF_8), 32);

                                // split into send/recv chain keys
                                byte[] sendCK = hkdfExpand(rootKey, "send".getBytes(UTF_8), 32);
                                byte[] recvCK = hkdfExpand(rootKey, "recv".getBytes(UTF_8), 32);

                                // initialize your ratchet (replace with your actual class)
                                DoubleRatchetState dr = new DoubleRatchetState(
                                        rootKey,
                                        ourEpriv,
                                        theirX25519SPub,  // using SPub as the initial ratchet pub
                                        sendCK,
                                        recvCK
                                );
                                String peerId = Base64.getEncoder().encodeToString( kr.getIdentityPub() );
                                sessionStore.put(peerId, dr);
                                System.out.println("✅ X3DH + Double Ratchet initialized.");
                            }


                        }
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                    System.out.println("Listener stopped.");
                }
            }, "Listener").start();

            // 5) message loop
            System.out.println("Type messages ('exit' to quit, 'refresh' to refresh all users):");
            while (true) {
                String msg = scanner.nextLine().trim();
                if (msg.equalsIgnoreCase("exit")) break;
                else if (msg.equalsIgnoreCase("refresh")) {
                    UserListRequestPacket req = new UserListRequestPacket();
                   /* byte[] encReq = PacketUtils.encryptPacketAES(req, sessionKey, iv);*/
                    output.writeObject(req);
                    output.flush();
                    continue;
                } else if (msg.equalsIgnoreCase("select")) {
                    System.out.print("Enter recipient: ");
                    String recipient = scanner.nextLine().trim();

                    //AESRequest raw = new AESRequest(username, recipient, userPub);

                    BundleRequestPacket raw = new BundleRequestPacket(username, recipient);

                    output.writeObject(raw);
                    output.flush();

                    //TODO
                    // fazer com que isto faça o DH para a troca de chaves com as chaves da outra pessoa
                }
                //TODO
                // add /msg para poder estar a mandar msg a pessoas e poder sair com um comando específico
                // o /select serve para a troca de chaves ig...?

                ;
                MessagePacket mp = new MessagePacket(msg);
                byte[] encMsg = PacketUtils.encryptPacketAES(mp, sessionKey, iv);
                output.writeObject(encMsg);
                output.flush();
            }

            System.out.println("Client shutting down.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //TODO
    // send this to other files

    /**
     * Saves a PKCS#8 encoding of the private key, encrypted with AES/CBC using PBKDF2.
     */
    private static void savePrivateKeyEncrypted(PrivateKey priv,
                                                String password,
                                                String filename) throws Exception {
        byte[] pkcs8 = priv.getEncoded();
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = f.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = c.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
        byte[] cipherText = c.doFinal(pkcs8);

        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(salt);
            fos.write(iv);
            fos.write(cipherText);
        }
    }

    /**
     * Loads and decrypts the RSA private key from file.
     */
    private static PrivateKey loadPrivateKeyFromFile(String password,
                                                     String filename) throws Exception {
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



    /**
     * Gather the PKCS#8 bytes of each private key,
     * prefix each with a 4-byte length, encrypt the whole
     * with AES/CBC/PKCS5Padding (PBKDF2(secret)), and write:
     *   [salt:16][iv:16][cipherText...]
     */
    private static void saveOneTimeKeysEncrypted(List<KeyPair> keyPairs,
                                                 String password,
                                                 String filename) throws Exception {
        // 1) build a single unencrypted blob
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        for (KeyPair kp : keyPairs) {
            byte[] pkcs8 = kp.getPrivate().getEncoded();
            dos.writeInt(pkcs8.length);
            dos.write(pkcs8);
        }
        dos.flush();
        byte[] plain = baos.toByteArray();

        // 2) salt + PBKDF2 → AES key
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

        // 3) encrypt
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = cipher.getParameters()
                .getParameterSpec(IvParameterSpec.class)
                .getIV();
        byte[] ciphertext = cipher.doFinal(plain);

        // 4) write out salt‖iv‖cipher
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(salt);
            fos.write(iv);
            fos.write(ciphertext);
        }
    }

    /**
     * Load and decrypt the one-time-keys file, returning the List<PrivateKey>.
     * You can then reconstruct KeyPair if you also store modulus/exponent or derive pub via CRT.
     */
    private static List<PrivateKey> loadOneTimeKeysEncrypted(String password,
                                                             String filename) throws Exception {
        byte[] file = Files.readAllBytes(Paths.get(filename));
        ByteBuffer buf = ByteBuffer.wrap(file);

        byte[] salt = new byte[16]; buf.get(salt);
        byte[] iv   = new byte[16]; buf.get(iv);
        byte[] cipherText = new byte[buf.remaining()];
        buf.get(cipherText);

        // derive
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

        // decrypt
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] plain = cipher.doFinal(cipherText);

        // split back into individual priv-keys
        List<PrivateKey> privs = new ArrayList<>();
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(plain));
        while (dis.available() > 0) {
            int len = dis.readInt();
            byte[] pkcs8 = new byte[len];
            dis.readFully(pkcs8);
            PKCS8EncodedKeySpec specPK = new PKCS8EncodedKeySpec(pkcs8);
            PrivateKey priv = KeyFactory.getInstance("RSA")
                    .generatePrivate(specPK);
            privs.add(priv);
        }
        return privs;
    }

    //------

    // X25519 DH
    private static byte[] x25519(PrivateKey sk, PublicKey pk) throws GeneralSecurityException {
        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(sk);
        ka.doPhase(pk, true);
        return ka.generateSecret();
    }

    // decode raw bytes into an X25519 public key
    private static PublicKey bytesToX25519Pub(byte[] raw) throws GeneralSecurityException {
        return KeyFactory.getInstance("X25519")
                .generatePublic(new X509EncodedKeySpec(raw));
    }

    // derive RSA public from private (you already have this)
    private static PublicKey derivePublicKey(PrivateKey priv) throws Exception {
        RSAPrivateCrtKey crt = (RSAPrivateCrtKey) priv;
        RSAPublicKeySpec spec = new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent());
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    // HKDF-Extract: PRK = HMAC-SHA256(salt, ikm)
    private static byte[] hkdfExtract(byte[] salt, byte[] ikm) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(
                salt != null ? salt : new byte[32], "HmacSHA256"
        );
        mac.init(keySpec);
        return mac.doFinal(ikm);
    }

    // HKDF-Expand: OKM of desired length
    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        byte[] okm = new byte[length];
        byte[] t = new byte[0];
        int copied = 0;
        byte counter = 1;
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

    // Convenience: HKDF Extract+Expand in one call
    private static byte[] hkdf(byte[] salt, byte[] ikm, byte[] info, int length)
            throws GeneralSecurityException {
        byte[] prk = hkdfExtract(salt, ikm);
        return hkdfExpand(prk, info, length);
    }


    //---------

    public static void saveRatchetStateEncrypted(
            DoubleRatchetState state,
            String password,
            String filename
    ) throws Exception {
        // 1) serialize to bytes
        ByteArrayOutputStream   baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(state);
        }
        byte[] plain = baos.toByteArray();

        // 2) derive AES key via PBKDF2
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(), salt, 65536, 256
        );
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = f.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

        // 3) encrypt with AES/CBC/PKCS5Padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = cipher.getParameters()
                .getParameterSpec(IvParameterSpec.class)
                .getIV();
        byte[] ciphertext = cipher.doFinal(plain);

        // 4) write salt‖iv‖ciphertext
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(salt);
            fos.write(iv);
            fos.write(ciphertext);
        }
    }

    /**
     * Load, decrypt and deserialize DoubleRatchetState from file encrypted
     * with PBKDF2/AES/CBC under the given password.
     */
    public static DoubleRatchetState loadRatchetStateEncrypted(
            String password,
            String filename
    ) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(filename));
        ByteBuffer buf = ByteBuffer.wrap(data);

        byte[] salt = new byte[16]; buf.get(salt);
        byte[] iv   = new byte[16]; buf.get(iv);
        byte[] cipherText = new byte[buf.remaining()];
        buf.get(cipherText);

        // 1) derive AES key
        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(), salt, 65536, 256
        );
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = f.generateSecret(spec).getEncoded();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

        // 2) decrypt
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] plain = cipher.doFinal(cipherText);

        // 3) deserialize
        try (ObjectInputStream ois =
                     new ObjectInputStream(new ByteArrayInputStream(plain))) {
            return (DoubleRatchetState) ois.readObject();
        }
    }
}

