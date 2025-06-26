package org.DataBase;

import org.Packets.KeyBundle;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class DBConnect {

    private static final String JDBC_DRIVER = "org.mariadb.jdbc.Driver";
    private static final String DB_URL = "jdbc:mariadb://127.0.0.1:3306/ProjetoFinal";

    private static final String USER = "root";
    private static final String PASSWORD = "";

    public static Connection getConnection() {
        try {
            Class.forName("org.mariadb.jdbc.Driver");
            Connection conn = DriverManager.getConnection(DB_URL, USER, PASSWORD );
            System.out.println("✅ Connected to MariaDB successfully!");
            return conn;
        } catch (SQLException e) {
            System.err.println("❌ Connection failed: " + e.getMessage());
            throw new RuntimeException(e);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }


    public static String RegiPOST(String Username, String Pass, byte[] publicKey, byte[] preKey, byte[] signature, int online) throws ClassNotFoundException {
        String checkSQL = "SELECT 1 FROM client WHERE client_name = ?";
        String insertSQL = "INSERT INTO client (client_name, client_pass, client_IPKey, client_SPKey, client_signature, client_online) VALUES (?, ?, ?, ?, ?, ?)";

        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASSWORD)) {

            // First, check if username exists
            try (PreparedStatement checkStmt = conn.prepareStatement(checkSQL)) {
                checkStmt.setString(1, Username);
                ResultSet rs = checkStmt.executeQuery();

                if (rs.next()) {
                    // Username already exists
                    return "Username already in use";

                }
            }

            // Username is available — insert new user
            try (PreparedStatement insertStmt = conn.prepareStatement(insertSQL)) {
                insertStmt.setString(1, Username);
                insertStmt.setString(2, Pass);
                insertStmt.setBytes(3, publicKey);
                insertStmt.setBytes(4, preKey);
                insertStmt.setBytes(5, signature);
                insertStmt.setInt(6, online);

                int rowsAffected = insertStmt.executeUpdate();
                return "Inserted rows: " + rowsAffected;

            }

        } catch (SQLException e) {
            return "Error: " + e.getMessage();
        }
    }

    public static class LoginPostResult {
        public final boolean success;
        public final String message;
        public final byte[] publicKeyBytes;

        public LoginPostResult(String message) {
            this.success        = false;
            this.message        = message;
            this.publicKeyBytes = null;
        }

        public LoginPostResult(String message, byte[] publicKeyBytes) {
            this.success        = (publicKeyBytes != null);
            this.message        = message;
            this.publicKeyBytes = publicKeyBytes;
        }

        public boolean isSuccess() {
            return success;
        }
    }


    public static LoginPostResult LoginPOST(String Username, String Pass) {
        String query = "SELECT client_pKey, client_pass FROM client WHERE client_name = ?";

        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASSWORD)) {
            try (PreparedStatement stmt = conn.prepareStatement(query)) {
                stmt.setString(1, Username);
                ResultSet rs = stmt.executeQuery();

                if (rs.next()) {
                    String storedPass = rs.getString("client_pass");
                    if (storedPass.equals(Pass)) {
                        //TODO
                        // no need to get anything from DB
                        return new LoginPostResult("Login successfully", rs.getBytes("client_pKey"));  // return the BLOB as byte[]


                    }else{
                        return new LoginPostResult("error: Wrong password", null);
                    }
                }
                return new LoginPostResult("fail: No user found", null);
            }
        } catch (SQLException e) {
            System.err.println("Login failed: " + e.getMessage());
        }
        return null;  // Return null if login fails
    }


    public static void goOnline(String username) {
        String sql = "UPDATE client SET client_online = ? WHERE client_name = ?";
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
                    ps.setByte(1, (byte)1);
                    ps.setString(2, username);
                    ps.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to set user online: " + e.getMessage());
        }
    }

    public static String goOffline(String username) {
        String query = "UPDATE client SET client_online = ? WHERE client_name = ?";

        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASSWORD);
            PreparedStatement stmt = conn.prepareStatement(query)) {

            stmt.setByte(1, (byte) 0);
            stmt.setString(2, username);
            int rows = stmt.executeUpdate();
            return rows + " user set offline";

        } catch (SQLException e) {
            System.err.println("Query failed: " + e.getMessage());
            return null;
        }
    }

    public static List<String> getOnlineUsers() {
        String query = "SELECT client_name FROM client WHERE client_online = ?";
        List<String> onlineUsers = new ArrayList<>();

        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASSWORD);
             PreparedStatement stmt = conn.prepareStatement(query)) {

            stmt.setByte(1, (byte) 1);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                onlineUsers.add(rs.getString("client_name"));
            }

        } catch (SQLException e) {
            throw new RuntimeException("Failed to fetch online users", e);
        }

        return onlineUsers;
    }


    /**
     * Inserts a one-time public key blob for the given username.
     * @param username      the client_name in your client table
     * @param oneTimeKey    the public key bytes to store
     * @return              "OK" on success, or an error message
     */
    public static String postOneTimeKey(String username, byte[] oneTimeKey) {
        String findSql   = "SELECT client_id FROM client WHERE client_name = ?";
        String insertSql = "INSERT INTO oneTimeKeys (client_id, client_one_time_key) VALUES (?, ?)";

        try (Connection conn = getConnection()) {
            // 1) look up the client_id
            Integer clientId = null;
            try (PreparedStatement ps = conn.prepareStatement(findSql)) {
                ps.setString(1, username);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        clientId = rs.getInt("client_id");
                    } else {
                        return "Error: no such user “" + username + "”";
                    }
                }
            }

            // 2) insert the one-time key
            try (PreparedStatement ps = conn.prepareStatement(insertSql)) {
                ps.setInt   (1, clientId);
                ps.setBytes (2, oneTimeKey);
                int rows = ps.executeUpdate();
                if (rows == 1) {
                    return "OK";
                } else {
                    return "Error: inserted " + rows + " rows";
                }
            }

        } catch (SQLException e) {
            return "DB error: " + e.getMessage();
        }
    }


    /**
     * Fetches the given user’s identity key, signing key, and one one-time key.
     * @param username  the client_name
     * @return          a UserKeyBundle if the user (and at least one one-time key) exist,
     *                  or null if not found.
     * @throws SQLException on DB errors
     */
    public static KeyBundle getUserKeyBundle(String username) throws SQLException {
        String findClient =
                "SELECT client_id, client_IPKey, client_SPKey " +
                        "FROM client WHERE client_name = ?";
        //TODO
        // Em vez de estar sequencial mudar para random tendo tempo
        String findOneTime =
                "SELECT client_one_time_key " +
                        "FROM oneTimeKeys " +
                        "WHERE client_id = ? " +
                        "ORDER BY key_ID ASC " +
                        "LIMIT 1";

        try (Connection conn = getConnection();
             PreparedStatement pstClient = conn.prepareStatement(findClient)) {

            pstClient.setString(1, username);
            try (ResultSet rsClient = pstClient.executeQuery()) {
                if (!rsClient.next()) {
                    // no such user
                    return null;
                }
                int clientId   = rsClient.getInt("client_id");
                byte[] ipKey   = rsClient.getBytes("client_IPKey");
                byte[] spKey   = rsClient.getBytes("client_SPKey");
                byte[] signature = rsClient.getBytes("signature");

                // now get one one-time key
                try (PreparedStatement pstOTK = conn.prepareStatement(findOneTime)) {
                    pstOTK.setInt(1, clientId);
                    try (ResultSet rsOTK = pstOTK.executeQuery()) {
                        if (!rsOTK.next()) {
                            // user has no one-time keys available
                            return null;
                        }
                        byte[] otk = rsOTK.getBytes("client_one_time_key");
                        return new KeyBundle(ipKey, spKey, signature, otk);
                    }
                }
            }
        }
    }
}
