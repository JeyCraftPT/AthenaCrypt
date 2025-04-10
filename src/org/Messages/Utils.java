package org.Messages;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Utils {

    public static Object[] splitDecodedBytes(byte[] data, byte delimiter, int expectedParts) {
        List<byte[]> parts = new ArrayList<>();
        int start = 0;

        for (int i = 0; i < data.length && parts.size() < expectedParts - 1; i++) {
            if (data[i] == delimiter) {
                parts.add(Arrays.copyOfRange(data, start, i));
                start = i + 1;
            }
        }

        // Add the last part (pKey)
        parts.add(Arrays.copyOfRange(data, start, data.length));

        // Prepare result: 3 strings + 1 byte[]
        String command = new String(parts.get(0), StandardCharsets.UTF_8);
        String username = new String(parts.get(1), StandardCharsets.UTF_8);
        String hashedPassword = new String(parts.get(2), StandardCharsets.UTF_8);
        byte[] pKey = parts.get(3);

        return new Object[] { command, username, hashedPassword, pKey };
    }


}
