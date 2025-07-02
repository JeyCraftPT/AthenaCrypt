package org.Packets;

public class HandShakePacket extends Packet {
    final String username;
    final String person;

    public HandShakePacket(String username, String person) {
        this.username = username;
        this.person = person;
    }

    public String getUsername() {
        return username;
    }
    public String getPerson() {
        return person;
    }

    @Override
    public String getType(){
        return "handshake";
    }
}
