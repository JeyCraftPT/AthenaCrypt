//package org.Server;
//
//import org.Keys.RSAKeys;
//import org.Messages.TCPServerThread;
//import org.UserHandler.User;
//
//import java.io.*;
//import java.net.ServerSocket;
//import java.net.Socket;
//import java.security.KeyPair;
//import java.security.PrivateKey;
//import java.security.PublicKey;
//import java.util.*;
//
//
////TODO
//// Metodo para sair da aplicação, fechar socket e sair da lista de online
//
////TODO
//// Acrescentar login através do servidor
//// Guardar chave privada e chave AES num ficheiro
//
//
//public class TCPServerMain {
//    private static HashMap<Socket, ObjectOutputStream> clientOutputStreams = new HashMap<>();
//    private static final Map<String, User> connectedUsers = Collections.synchronizedMap(new HashMap<>());
//
//    private static final int PORT = 5000;
//
//    public TCPServerMain() throws IOException{
//        ServerSocket serverSocket = new ServerSocket(PORT);
//
//        System.out.println("Porta 5000 is open");
//
//        while (true){
//            System.out.println("Server started, waiting for clients");
//            Socket clientSocket = serverSocket.accept();
//            System.out.println("New client connected: " + clientSocket);
//
//
//            TCPServerThread tcpServerThread = new TCPServerThread(clientSocket,this);
//            Thread thread = new Thread(tcpServerThread);
//            thread.start();
//
//        }
//    }
//
//    private int clientNumber = 1;
//
//    public int getClientNumber(){
//        return clientNumber++;
//    }
//
//    public static void registerUser(String username, User user) {
//        connectedUsers.put(username, user);
//    }
//
//    public static List<String> getUserList() {
//        return new ArrayList<>(connectedUsers.keySet());
//    }
//
//    public static User getUser(String username) {
//        return connectedUsers.get(username);
//    }
//
//    public static void removeUser(String username) {
//        connectedUsers.remove(username);
//    }
//
//
//
//    public static void main(String[] args){
//        try{
//            // Generate RSA key pair for the server
//            KeyPair serverKeyPair = RSAKeys.generateKeyPair();
//            PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
//            PublicKey serverPublicKey = serverKeyPair.getPublic();
//
//            new TCPServerMain();
//        }catch (Exception e){
//            e.printStackTrace();
//        }
//    }
//}