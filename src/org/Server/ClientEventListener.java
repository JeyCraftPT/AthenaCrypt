package org.Server;

import org.Packets.Packet;

import java.util.function.Consumer;

public interface ClientEventListener {
    void onClientAction(String action, String data);
    void onClientAction(String action, Consumer<Packet> callback);
    void onClientAction(String action, String username, Consumer<Packet> callback);
}
