package org.Packets;

public class RegisterPacket extends Packet {
    private String username;
    private String password;
    private byte[] publicKeyBytes;

    public RegisterPacket(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() { return username; }
    public String getPassword() { return password; }

    @Override
    public String getType() {
        return "Register";
    }
}
