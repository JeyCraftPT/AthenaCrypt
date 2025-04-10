package org.UserHandler;

import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.PublicKey;

public class User {
    private String username;
    private Socket socket;
    private ObjectOutputStream out;
    private PublicKey publicKey;

    public User(String username, Socket socket, ObjectOutputStream out, PublicKey publicKey) {
        this.username = username;
        this.socket = socket;
        this.out = out;
        this.publicKey = publicKey;
    }

    // Getters
    public String getUsername() { return username; }
    public Socket getSocket() { return socket; }
    public ObjectOutputStream getOut() { return out; }
    public PublicKey getPublicKey() { return publicKey; }
}