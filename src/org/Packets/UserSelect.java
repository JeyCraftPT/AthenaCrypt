package org.Packets;

import java.io.Serializable;

public class UserSelect extends Packet  implements Serializable {
    private final String recipient;

    public UserSelect(String recipient) {
        this.recipient = recipient;
    }

    public String getRecipient() {
        return recipient;
    }
    @Override
    public String getType(){
        return "UserSelect";
    }
}
