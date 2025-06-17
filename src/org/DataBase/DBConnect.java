package org.DataBase;

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


    public static String RegiPOST(String Username, String Pass, byte[] publicKey, int online) throws ClassNotFoundException {
        String checkSQL = "SELECT 1 FROM client WHERE client_name = ?";
        String insertSQL = "INSERT INTO client (client_name, client_pass, client_pKey, client_online) VALUES (?, ?, ?, ?)";

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
                insertStmt.setInt(4, online);


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
                        return new LoginPostResult("Login successfully", rs.getBytes("client_pKey"));  // return the BLOB as byte[]


                    }else{
                        return new LoginPostResult("Wrong password", null);
                    }
                }
                return new LoginPostResult("No user found", null);
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


}
