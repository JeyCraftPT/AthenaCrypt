package org.DataBase;

import org.Packets.KeyBundle;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.sql.*;
import java.util.ArrayList;
import java.util.Arrays;
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


    public static String RegiPOST(
            String   Username,
            byte[]   passwordBytes,
            byte[]   rsaIdentityPub,      // was “publicKey”
            byte[]   x25519IdentityPub,   // ← new!
            byte[]   x25519SigningPub,    // was “preKey”
            byte[]   signature,
            int      online
    ) throws ClassNotFoundException {
    String checkSQL  = "SELECT 1 FROM client WHERE client_name = ?";
        String insertSQL = "INSERT INTO client " +
                "(client_name, client_pass, client_IPKey, client_x25519IdentityKey, client_SPKey, client_signature, client_online) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?)";
        try (Connection conn = getConnection()) {
            // 1) check username
            try (PreparedStatement checkStmt = conn.prepareStatement(checkSQL)) {
                checkStmt.setString(1, Username);
                try (ResultSet rs = checkStmt.executeQuery()) {
                    if (rs.next()) {
                        return "Username already in use";
                    }
                }
            }

            // 2) derive salted hash of the password
            //    [ salt(16) || PBKDF2-HMAC-SHA256(password, salt) ]
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);

            PBEKeySpec spec = new PBEKeySpec(
                    new String(passwordBytes, StandardCharsets.UTF_8).toCharArray(),
                    salt,
                    100_000,   // iteration count
                    256        // key length
            );
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = skf.generateSecret(spec).getEncoded();

            byte[] saltedHash = ByteBuffer.allocate(salt.length + hash.length)
                    .put(salt)
                    .put(hash)
                    .array();

            // 3) insert user record
            try (PreparedStatement insertStmt = conn.prepareStatement(insertSQL)) {
                insertStmt.setString(1, Username);
                insertStmt.setBytes (2, saltedHash);
                insertStmt.setBytes (3, rsaIdentityPub);
                insertStmt.setBytes (4, x25519IdentityPub);   // NEW
                insertStmt.setBytes (5, x25519SigningPub);
                insertStmt.setBytes (6, signature);
                insertStmt.setInt   (7, online);

                int rowsAffected = insertStmt.executeUpdate();
                if (rowsAffected == 1) {
                    return "Registration successful";
                } else {
                    return "Error: inserted " + rowsAffected + " rows";
                }
            }
        } catch (SQLException | GeneralSecurityException e) {
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


    public static LoginPostResult LoginPOST(String Username, String password) {
        String query =
                "SELECT client_pass, client_IPKey " +
                        "FROM client WHERE client_name = ?";
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASSWORD);
             PreparedStatement ps = conn.prepareStatement(query)) {

            ps.setString(1, Username);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    // no such user
                    return new LoginPostResult("fail: No user found", null);
                }

                // 1) pull the stored salt||hash blob
                byte[] stored = rs.getBytes("client_pass");
                // stored = [16-byte salt][32-byte hash]
                byte[] salt = Arrays.copyOfRange(stored, 0, 16);
                byte[] hash = Arrays.copyOfRange(stored, 16, stored.length);

                // 2) re-derive hash from supplied password
                PBEKeySpec spec = new PBEKeySpec(
                        password.toCharArray(), salt, 100_000, 256
                );
                SecretKeyFactory skf =
                        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                byte[] check = skf.generateSecret(spec).getEncoded();

                // 3) constant-time compare
                if (!MessageDigest.isEqual(hash, check)) {
                    return new LoginPostResult("error: Wrong password", null);
                }

                // 4) success — return the identity public key bytes
                byte[] publicKeyBytes = rs.getBytes("client_IPKey");
                return new LoginPostResult("Login successful", publicKeyBytes);
            }
        } catch (SQLException e) {
            return new LoginPostResult("error: DB error – " + e.getMessage(), null);
        } catch (GeneralSecurityException e) {
            return new LoginPostResult("error: Crypto error – " + e.getMessage(), null);
        }
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
        // now include the X25519 identity key column
        String findClient =
                "SELECT client_id, client_IPKey, client_x25519IdentityKey, client_SPKey, client_signature " +
                        "  FROM client WHERE client_name = ?";
        String findOneTime =
                "SELECT client_one_time_key " +
                        "  FROM oneTimeKeys WHERE client_id = ? " +
                        "  ORDER BY key_ID ASC LIMIT 1";

        try (Connection conn = getConnection();
             PreparedStatement pstClient = conn.prepareStatement(findClient)) {

            pstClient.setString(1, username);
            try (ResultSet rsClient = pstClient.executeQuery()) {
                if (!rsClient.next()) return null;

                int    clientId     = rsClient.getInt   ("client_id");
                byte[] rsaIdPub     = rsClient.getBytes ("client_IPKey");
                byte[] x25519IdPub  = rsClient.getBytes ("client_x25519IdentityKey");
                byte[] spkPub       = rsClient.getBytes ("client_SPKey");
                byte[] signature    = rsClient.getBytes ("client_signature");

                // pull one one-time key as before
                try (PreparedStatement pstOTK = conn.prepareStatement(findOneTime)) {
                    pstOTK.setInt(1, clientId);
                    try (ResultSet rsOTK = pstOTK.executeQuery()) {
                        if (!rsOTK.next()) return null;
                        byte[] otk = rsOTK.getBytes("client_one_time_key");

                        // **now call the 5-arg KeyBundle ctor**
                        return new KeyBundle(
                                rsaIdPub,
                                x25519IdPub,
                                spkPub,
                                signature,
                                otk
                        );
                    }
                }
            }
        }
    }



    /**
     * Deletes a specific one-time public key for the given user.
     *
     * @param username     the client_name in your client table
     * @param oneTimeKey   the exact blob to delete
     * @return             "OK" on success, or an error message
     */
    public static String deleteOneTimeKey(String username, byte[] oneTimeKey) {
        String findSql   = "SELECT client_id FROM client WHERE client_name = ?";
        String deleteSql = "DELETE FROM oneTimeKeys WHERE client_id = ? AND client_one_time_key = ?";
        try (Connection conn = getConnection()) {
            // 1) look up the client_id
            Integer clientId = null;
            try (PreparedStatement ps = conn.prepareStatement(findSql)) {
                ps.setString(1, username);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        clientId = rs.getInt("client_id");
                    } else {
                        return "Error: no such user \"" + username + "\"";
                    }
                }
            }
            // 2) delete the one-time key row
            try (PreparedStatement ps = conn.prepareStatement(deleteSql)) {
                ps.setInt(1, clientId);
                ps.setBytes(2, oneTimeKey);
                int rows = ps.executeUpdate();
                if (rows == 1) {
                    return "OK";
                } else if (rows == 0) {
                    return "No matching one-time key found for user";
                } else {
                    return "Warning: deleted " + rows + " rows";
                }
            }
        } catch (SQLException e) {
            return "DB error: " + e.getMessage();
        }
    }
}
