package org.Packets;

import java.io.Serializable;

public abstract class Packet implements Serializable {
    public abstract String getType();
}
