package org.DataBase;

import java.sql.*;

public class DBConnect {

    private static final String JDBC_DRIVER = "org.mariadb.jdbc.Driver";
    private static final String DB_URL = "jdbc:mariadb://127.0.0.1:3306/ProjetoFinal";

    private static final String USER = "root";
    private static final String PASSWORD = "Bolas132";

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

    /*public static String RegiPOST(String Username, String Pass, byte[] PKey) {
        String checkSQL = "SELECT 1 FROM client WHERE client_name = ?";
        String insertSQL = "INSERT INTO client (client_name, client_pass, client_IKey) VALUES (?, ?, ?)";

        try (Connection conn = DriverManager.getConnection(JDBC_DRIVER, USER, PASSWORD)) {

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
                insertStmt.setBytes(3, PKey);

                int rowsAffected = insertStmt.executeUpdate();
                return "Inserted rows: " + rowsAffected;
            }

        } catch (SQLException e) {
            return "Error: " + e.getMessage();
        }
    }*/

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

    public static byte[] LoginPOST(String Username, String Pass) {
        String query = "SELECT client_pKey, client_pass FROM client WHERE client_name = ?";

        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASSWORD)) {
            try (PreparedStatement stmt = conn.prepareStatement(query)) {
                stmt.setString(1, Username);
                ResultSet rs = stmt.executeQuery();

                if (rs.next()) {
                    String storedPass = rs.getString("client_pass");
                    if (storedPass.equals(Pass)) {
                        return rs.getBytes("client_pKey");  // return the BLOB as byte[]


                    }else{
                        return "Wrong password!".getBytes();
                    }
                }
            }
        } catch (SQLException e) {
            System.err.println("Login failed: " + e.getMessage());
        }
        return null;  // Return null if login fails
    }




}
