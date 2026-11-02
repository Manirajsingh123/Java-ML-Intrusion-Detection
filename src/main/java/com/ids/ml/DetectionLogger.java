package com.ids.ml;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class DetectionLogger {

    private static final String LOG_FILE =
            "data/detection_logs.csv";

    private static final DateTimeFormatter FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static void log(
            int packetNumber,
            String result
    ) throws Exception {

        File file = new File(LOG_FILE);

        boolean newFile = !file.exists();

        try (PrintWriter writer =
                     new PrintWriter(
                             new FileWriter(file, true))) {

            if (newFile) {
                writer.println(
                        "Time,Packet,Prediction,Confidence,Status"
                );
            }

            String prediction;
            String confidence;

            if (result.startsWith("ATTACK")) {
                prediction = "ATTACK";
            } else {
                prediction = "NORMAL";
            }

            int start = result.indexOf("(");
            int end = result.indexOf("%");

            if (start >= 0 && end > start) {
                confidence =
                        result.substring(
                                start + 1,
                                end
                        );
            } else {
                confidence = "N/A";
            }

            String status =
                    prediction.equals("ATTACK")
                            ? "ALERT"
                            : "SAFE";

            writer.println(
                    LocalDateTime.now().format(FORMAT)
                            + ","
                            + packetNumber
                            + ","
                            + prediction
                            + ","
                            + confidence
                            + ","
                            + status
            );
        }
    }
}