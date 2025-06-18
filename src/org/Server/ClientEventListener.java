package org.Server;

import org.Packets.Packet;

import java.net.Socket;
import java.util.function.Consumer;

public interface ClientEventListener {
    void onClientAction(String action, String data);
    void onClientAction(String action, Consumer<Packet> callback);
    /*void onClientAction(String action, String username, Consumer<Packet> callback);*/
    void onClientAction(String action, String username, Socket socket, Consumer<Packet> callback);

    /*void onClientAction(String login, String username, Socket clientSocket);*/
}
