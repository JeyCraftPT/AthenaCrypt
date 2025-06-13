package org.Packets;

import java.io.Serializable;
import java.util.List;

public class UserListPacket extends Packet implements Serializable {
    private final List<String> users;

    public UserListPacket(List<String> users) {
        this.users = users;
    }

    public List<String> getUsers() {
        return users;
    }

    @Override
    public String getType() {
        return "UserList";
    }
}
