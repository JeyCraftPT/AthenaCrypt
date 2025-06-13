package org.Packets;

public class LoginPacket extends Packet {
    private String username;
    private String password;

    public LoginPacket(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() { return username; }
    public String getPassword() { return password; }

    @Override
    public String getType() {
        return "Login";
    }
}
