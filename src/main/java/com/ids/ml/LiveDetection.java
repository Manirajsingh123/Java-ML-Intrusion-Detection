package com.ids.ml;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class LiveDetection {

    private final ModelService service;

    // =========================================
    // CONSTRUCTOR
    // =========================================

    public LiveDetection() {

        service = new ModelService();
    }


    // =========================================
    // START LIVE DETECTION
    // =========================================

    public void startDetection(String csvPath)
            throws Exception {

        // Load trained Random Forest model
        service.load();

        System.out.println();
        System.out.println(
                "======================================"
        );

        System.out.println(
                "       LIVE INTRUSION DETECTION"
        );

        System.out.println(
                "======================================"
        );

        System.out.println(
                "Monitoring file: " + csvPath
        );

        System.out.println();


        // =========================================
        // READ CSV FILE
        // =========================================

        List<String> fileLines =
                Files.readAllLines(
                        Path.of(csvPath)
                );


        // Check data
        if (fileLines.size() < 2) {

            System.out.println(
                    "No traffic data found!"
            );

            return;
        }


        // =========================================
        // CSV HEADER
        // =========================================

        String header =
                fileLines.get(0);


        // =========================================
        // TRAFFIC ROWS
        // =========================================

        List<String> rows =
                fileLines.subList(
                        1,
                        fileLines.size()
                );


        // =========================================
        // COUNTERS
        // =========================================

        int normal = 0;

        int attack = 0;

        int packetNumber = 1;


        // =========================================
        // PROCESS TRAFFIC ONE BY ONE
        // =========================================

        for (String row : rows) {


            // Skip empty rows
            if (row.trim().isEmpty()) {

                continue;
            }


            System.out.println(
                    "--------------------------------------"
            );


            System.out.println(
                    "Traffic Packet "
                            + packetNumber
            );


            System.out.println(
                    "Incoming traffic detected..."
            );


            // =========================================
            // SMALL PROCESSING DELAY
            // =========================================

            Thread.sleep(500);


            // =========================================
            // ML PREDICTION
            // =========================================

            String result =
                    service.predictSingleRow(
                            header,
                            row
                    );
            DetectionLogger.log(
                    packetNumber,
                    result
            );


            System.out.println();

            System.out.println(
                    "Prediction Result:"
            );

            System.out.println(
                    result
            );


            // =========================================
            // CHECK RESULT
            // =========================================

            if (result.startsWith("ATTACK")) {

                attack++;

                System.out.println();

                System.out.println(
                        "⚠ ALERT: ATTACK DETECTED"
                );

            } else {

                normal++;

                System.out.println();

                System.out.println(
                        "✓ NORMAL TRAFFIC"
                );
            }


            // =========================================
            // CURRENT STATISTICS
            // =========================================

            System.out.println();

            System.out.println(
                    "Current Normal : "
                            + normal
            );

            System.out.println(
                    "Current Attack : "
                            + attack
            );


            System.out.println();


            // =========================================
            // NEXT PACKET
            // =========================================

            packetNumber++;


            // =========================================
            // DEMO LIMIT
            // =========================================

            // Process maximum 10 packets
            if (packetNumber > 10) {

                break;
            }
        }


        // =========================================
        // FINAL REPORT
        // =========================================

        System.out.println(
                "======================================"
        );

        System.out.println(
                "       LIVE MONITORING COMPLETED"
        );

        System.out.println(
                "======================================"
        );


        int totalTraffic =
                packetNumber - 1;


        System.out.println(
                "Total Traffic : "
                        + totalTraffic
        );

        System.out.println(
                "Normal        : "
                        + normal
        );

        System.out.println(
                "Attack        : "
                        + attack
        );


        // =========================================
        // THREAT STATUS
        // =========================================

        System.out.println();

        if (attack > 0) {

            System.out.println(
                    "⚠ THREAT DETECTED!"
            );

        } else {

            System.out.println(
                    "✓ SYSTEM SAFE"
            );
        }


        System.out.println();

        System.out.println(
                "Live detection session ended."
        );
    }


    // =========================================
    // MAIN METHOD
    // =========================================

    public static void main(
            String[] args)
            throws Exception {

        LiveDetection detector =
                new LiveDetection();


        detector.startDetection(
                "data/test_input.csv"
        );
    }
}