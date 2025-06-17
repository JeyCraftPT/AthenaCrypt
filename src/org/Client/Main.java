package org.Client;

import org.Packets.*;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Scanner;

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

                // generate identity RSA keypair
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair userKP = kpg.generateKeyPair();

                // send RegisterPacket under AES, including public key bytes
                RegisterPacket reg = new RegisterPacket(u, p, userKP.getPublic().getEncoded());
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
                    savePrivateKeyEncrypted(userKP.getPrivate(), p, filename);
                    System.out.println("🔐 Private key saved to: " + filename);
                } else {
                    System.err.println("Registration failed; private key not saved.");
                    return;
                }
            }
            // LOGIN
            else {
                System.out.print("Username: ");  String u = scanner.nextLine();
                System.out.print("Password: ");  String p = scanner.nextLine();

                // load private key and derive public (not resent)
                PrivateKey userPriv = loadPrivateKeyFromFile(p, u + "_private_key.enc");
                PublicKey userPub = derivePublicKey(userPriv);
                System.out.println("🔑 Loaded key from " + u + "_private_key.enc");

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
            }

            // 4) start listener thread (AES)
            new Thread(() -> {
                try {
                    while (true) {
                        byte[] raw = (byte[]) input.readObject();
                        Packet pkt = PacketUtils.decryptPacketAES(raw, sessionKey, iv);
                        switch (pkt.getType()) {
                            case "Info"     -> System.out.println("[Server] " + ((InfoPacket)pkt).getMessage());
                            case "UserList" -> System.out.println("[Update] " + ((UserListPacket)pkt).getUsers());
                        }
                    }
                } catch (Exception e) {
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
                    byte[] encReq = PacketUtils.encryptPacketAES(req, sessionKey, iv);
                    output.writeObject(encReq);
                    output.flush();
                    continue;
                };
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
     * Derives the RSA public key from a PKCS#8 private key.
     */
    private static PublicKey derivePublicKey(PrivateKey priv) throws Exception {
        RSAPrivateCrtKey crt = (RSAPrivateCrtKey) priv;
        RSAPublicKeySpec spec = new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent());
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }
}
