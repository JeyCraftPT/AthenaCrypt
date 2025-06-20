// src/org/Packets/UserListRequestPacket.java
package org.Packets;

public class UserListRequestPacket extends Packet {
    public UserListRequestPacket() { }

    @Override
    public String getType() {
        return "UserListRequest";
    }
}
