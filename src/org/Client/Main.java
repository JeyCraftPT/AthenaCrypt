package org.Client;

import org.Keys.AESKeys;
import org.Keys.RSAKeys;
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

            String username = null;
            PublicKey userPub = null;
            PrivateKey userPriv = null;

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

                userPub = userKP.getPublic();
                username = u;
                userPriv = userKP.getPrivate();
            }
            // LOGIN
            else {
                System.out.print("Username: ");  String u = scanner.nextLine();
                System.out.print("Password: ");  String p = scanner.nextLine();

                // load private key and derive public (not resent)
                PrivateKey userPrivF = loadPrivateKeyFromFile(p, u + "_private_key.enc");
                PublicKey userPubF = derivePublicKey(userPriv);
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

                userPub = userPubF;
                username = u;
                userPriv = userPrivF;
            }

            // 4) start listener thread (AES)
            PrivateKey finalUserPriv = userPriv;
            String finalUsername = username;
            String finalUsername1 = username;
            PublicKey finalUserPub = userPub;
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
                                AESAnswer_Cena kms = new AESAnswer_Cena(finalUsername1, who, finalUserPub, RSAKeys.encrypt(miau.getEncoded(),cena));

                                output.writeObject(kms);

                                //TODO
                                // Adicionar metodo para adicionar a chave AES num ficheiro chamado username_SessionKey_denc.enc
                                // chaves neste ficheiro serão usadas para decifrar mensages
                                // cifrar ficheiro com pass do user

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
                                //TODO
                                // fazer packet que tenha (sender, reci, RSA(AES))
                                // dar refactor aos nomes dos packets
                                // acrescentar packets no ClientHandler.java
                            }

                        }
                    }
                    //TODO
                    // da exception porque o package n vem cifrado
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

                    AESRequest raw = new AESRequest(username, recipient, userPub);

                    //TODO
                    // trocar isto por verificar a chave no ficheiro
                    // caso chave existar avisar e n fazer nada

                    try {
                        Thread.sleep(2000);  // 1000ms
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt(); // restore interrupt
                    }



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

/*
else if (msg.equalsIgnoreCase("select")) {
        System.out.print("Enter recipient: ");
String recipient = scanner.nextLine().trim();

// where we persist DCP keys
String dcpFilename = username + "_SessionKeyDCP.enc";
SecretKey dcpKey = null;

// 1) Try to load an existing key from file
File keyFile = new File(dcpFilename);
                    if (keyFile.exists()) {
        try (BufferedReader br = new BufferedReader(new FileReader(keyFile))) {
String line;
                            while ((line = br.readLine()) != null) {
String[] parts = line.split(" : ");
                                if (parts.length == 2 && parts[0].equals(recipient)) {
byte[] keyBytes = Base64.getDecoder().decode(parts[1]);
dcpKey = new SecretKeySpec(keyBytes, "AES");
                                    System.out.println("🔑 Loaded existing DCP key for “" + recipient + "”.");
                                    break;
                                            }
                                            }
                                            } catch (IOException e) {
        System.err.println("⚠️ Error reading DCP key file: " + e.getMessage());
        }
        }

        // 2) If no key was found, generate + send it and save it
        if (dcpKey == null) {
        System.out.println("🔐 Generating new DCP AES key for “" + recipient + "”.");
kg = KeyGenerator.getInstance("AES");
                        kg.init(256);
dcpKey = kg.generateKey();
byte[] dcpKeyBytes = dcpKey.getEncoded();

// wrap & send the key to server
//TODO
// mandar este package cifrado...?
// sacar chave publica ao bacano
// tinha de sacar chave AES somehow para conseguir cifrar tudo
// ou só mandar chave AES depois
// posso sacar a chave AES session key que usa com o servidor (pouco seguro)
// posso mandar package para ter uma "session key" para trocar este pacotes iniciais
AESRequest aesReq = new AESRequest(username, recipient, userPub, dcpKeyBytes);
byte[] encReq = PacketUtils.encryptPacketAES(aesReq, sessionKey, iv);
                        output.writeObject(encReq);
                        output.flush();
                        System.out.println("✅ Sent new DCP key to server.");

// append to file
                        try (FileWriter fw = new FileWriter(dcpFilename, true)) {
String line = recipient + " : " + Base64.getEncoder().encodeToString(dcpKeyBytes);
                            fw.write(line);
                            fw.write(System.lineSeparator());
        System.out.println("💾 Saved DCP key to “" + dcpFilename + "”.");
                        } catch (IOException e) {
        System.err.println("❌ Failed to save DCP key: " + e.getMessage());
        }
        }

        // 3) Now send the actual direct message
        System.out.print("Enter message: ");
String message = scanner.nextLine();

// you might want to encrypt 'message' with dcpKey here, if that's your protocol
DirectMessagePacket req = new DirectMessagePacket(recipient, message, username);
byte[] encMsg = PacketUtils.encryptPacketAES(req, sessionKey, iv);
                    output.writeObject(encMsg);
                    output.flush();

                    continue;
                            }
*/
