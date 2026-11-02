package com.ids.ml;

import com.ids.db.DatabaseConnection;
import com.ids.security.UserSession;

import java.sql.Connection;
import java.sql.PreparedStatement;

public class DetectionDatabaseLogger {

    public static void log(
            int packetNumber,
            String result
    ) throws Exception {

        if (!UserSession.isLoggedIn()) {
            return;
        }

        String prediction;

        if (result.startsWith("ATTACK")) {
            prediction = "ATTACK";
        } else {
            prediction = "NORMAL";
        }

        String confidence = "0";

        int start = result.indexOf("(");
        int end = result.indexOf("%");

        if (start >= 0 && end > start) {

            confidence =
                    result.substring(
                            start + 1,
                            end
                    );
        }

        double confidenceValue =
                Double.parseDouble(confidence);

        String status;

        if (prediction.equals("ATTACK")) {
            status = "ALERT";
        } else {
            status = "SAFE";
        }

        String sql =
                "INSERT INTO detection_logs " +
                        "(user_id, packet_number, prediction, confidence, status) " +
                        "VALUES (?, ?, ?, ?, ?)";

        try (
                Connection connection =
                        DatabaseConnection.getConnection();

                PreparedStatement statement =
                        connection.prepareStatement(sql)
        ) {

            statement.setInt(
                    1,
                    UserSession.getUserId()
            );

            statement.setInt(
                    2,
                    packetNumber
            );

            statement.setString(
                    3,
                    prediction
            );

            statement.setDouble(
                    4,
                    confidenceValue
            );

            statement.setString(
                    5,
                    status
            );

            statement.executeUpdate();
        }
    }
}