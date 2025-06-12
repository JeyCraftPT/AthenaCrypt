package org.Messages;

import org.DataBase.DBConnect;
import org.Keys.RSAKeys;
import org.Server.TCPServerMain;
import org.Server.TCPServerMain;
import org.UserHandler.User;

import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

public class TCPServerThread implements Runnable {
    private Socket socket; // Client socket
    private TCPServerMain tcpServerMain; // Reference to the main server


    public TCPServerThread(Socket socket, TCPServerMain tcpServerMain) {
        this.socket = socket;
        this.tcpServerMain = tcpServerMain;
    }

    @Override
    public void run() {
        try {
            // Setup streams
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            // Generate RSA key pair for server-client encryption
            KeyPair serverKeyPair = RSAKeys.getKeyPair();
            PublicKey serverPublicKey = serverKeyPair.getPublic();
            PrivateKey serverPrivateKey = serverKeyPair.getPrivate();

            // Step 0: Send server public key to client
            out.writeObject(serverPublicKey);

            // Step 1: Receive login or register info (Base64-encoded byte[])
            Object authObject = in.readObject();
            if (!(authObject instanceof byte[])) {
                out.writeObject("❌ Invalid authentication format.");
                socket.close();
                return;
            }


            //TODO
            // Try to optimize part splitting based on login or register

            byte[] credentialsEncoded = (byte[]) authObject;
            byte[] decodedBytes = Base64.getDecoder().decode(credentialsEncoded);
            String decoded = new String(decodedBytes);

            String[] parts = decoded.split(":", 5);
            if (parts.length < 5) {
                out.writeObject("❌ Invalid format: missing fields.");
                socket.close();
                return;
            }

            String command = parts[0].toLowerCase();
            String username = parts[1];
            String passHash = parts[2];
            String publicKeyByte = parts[3];
            byte online = Byte.parseByte(parts[4]);
            /*boolean authenticated = false;*/

            while (!command.equalsIgnoreCase("register") && !command.equalsIgnoreCase("login")) {
                out.writeObject("Wrong command! Try again.");

            }
            out.writeObject("passou verificação de login/register");

            if (command.equalsIgnoreCase("REGISTER") && parts.length == 5) {
                System.out.println("Entrou no resgister");
                out.writeObject("registering");
                // Extract public key bytes safely
                byte[] publicKeyBytes = parts[3].getBytes(); // ideally decode Base64 here
                String result = DBConnect.RegiPOST(username, passHash, publicKeyBytes, online);
                /*String result = DBConnect.RegiPOST(username, passHash);*/
                out.writeObject(result);



            } else if (command.equalsIgnoreCase("LOGIN") && parts.length == 4) {
                byte[] returnPublicK = DBConnect.LoginPOST(username, passHash);
                byte[] Bad = "Wrong password!".getBytes();


                //TODO
                // Aqui tem de devolver alguma coisa tipo username e chave ou algo parecido (WIP - must check if working)


                if(Arrays.equals(returnPublicK, Bad)){
                    out.writeObject("Wrong Password!");
                }else{
                    out.writeObject(returnPublicK);
                    System.out.println(returnPublicK);
                }

            }



            // Step 2: Receive client's actual public key object after auth
            PublicKey clientPublicKey = (PublicKey) in.readObject();

            // Step 3: Register user in memory
            User user = new User(username, socket, out, clientPublicKey);
            TCPServerMain.registerUser(username, user);

            // Step 4: Send welcome message
            out.writeObject("Welcome " + username + "! Users online: " + TCPServerMain.getUserList());

            // Step 5: Send user list

            //TODO
            // Remove this shit and use db client_online and query (WIP- CHECK IF WORKING)
            out.writeObject("users online:" + DBConnect.getOnline());

            //TODO
            // Adicionar metodo de escolher com quem falar

            String message = in.readLine();
            String regex = "[:\\.\\s]";
            String[] splitter =  message.split(regex);
            String receiver =  splitter[1];


            // ✅ Now start listening for chat messages
            while (true) {
                Object incoming = in.readObject();

                if (incoming instanceof String message) {
                    if (message.equalsIgnoreCase("quit")) {
                        System.out.println("User " + username + " disconnected.");
                        DBConnect.goOffline(username);
                        System.out.println(DBConnect.goOffline(username));
                        socket.close();
                        break; // Exit thread
                    }


                        //TODO
                        // Check this for shits and giggles
                        String[] msgParts = message.substring(3).split("\\|", 2);
                        if (msgParts.length == 2) {
                            String receiverName = receiver;
                            String messageText = msgParts[1];

                            User receiver = TCPServerMain.getUser(receiverName);
                            if (receiver != null) {
                                receiver.getOut().writeObject("FROM:" + username + "|" + messageText);
                            } else {
                                out.writeObject("❌ User " + receiverName + " not found.");
                            }
                        } else {
                            out.writeObject("❌ Invalid message format. Use: TO:username|Your message");
                        }
                    } else {
                        out.writeObject("⚠️ Unknown command: " + message);
                    }
                }



        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
