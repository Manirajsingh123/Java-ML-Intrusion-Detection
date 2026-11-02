package com.ids.db;

import java.sql.Connection;
import java.sql.DriverManager;

public class DatabaseConnection {

    private static final String URL =
            "jdbc:mysql://localhost:3306/java_ids";

    private static final String USER =
            "root";

    private static final String PASSWORD =
            "";

    public static Connection getConnection()
            throws Exception {

        return DriverManager.getConnection(
                URL,
                USER,
                PASSWORD
        );
    }

    public static void main(String[] args) {

        try {

            Connection connection =
                    getConnection();

            System.out.println(
                    "MySQL Connected Successfully!"
            );

            connection.close();

        } catch (Exception e) {

            e.printStackTrace();
        }
    }
}