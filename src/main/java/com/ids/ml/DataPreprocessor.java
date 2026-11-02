package com.ids.ml;

import java.io.*;
import java.nio.file.*;
import java.util.*;

public class DataPreprocessor {

    private static final int MAX_PER_CLASS = 10000;
    private static final Random RANDOM = new Random(42);

    private static final List<String[]> normalRows = new ArrayList<>();
    private static final List<String[]> attackRows = new ArrayList<>();

    public static void main(String[] args) {

        String[] files = {
                "data/Friday-WorkingHours-Morning.pcap_ISCX.csv",
                "data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
                "data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
        };

        String output = "data/ids_training.csv";

        try {

            String header = null;

            for (String file : files) {

                System.out.println("Reading: " + file);

                try (BufferedReader br =
                             Files.newBufferedReader(Path.of(file))) {

                    String line = br.readLine();

                    if (line == null) {
                        continue;
                    }

                    // ==========================================
                    // FIRST FILE HEADER
                    // ==========================================

                    if (header == null) {

                        String[] headerColumns =
                                line.split(",", -1);

                        // Make header names unique
                        makeUniqueHeaders(headerColumns);

                        header = String.join(
                                ",",
                                headerColumns
                        );
                    }

                    int total = 0;
                    int accepted = 0;

                    while ((line = br.readLine()) != null) {

                        total++;

                        String[] values =
                                line.split(",", -1);

                        // Expected:
                        // 78 features + 1 Label = 79
                        if (values.length != 79) {
                            continue;
                        }

                        String label =
                                values[78].trim();

                        String newLabel;

                        // ==========================================
                        // LABEL CONVERSION
                        // ==========================================

                        if (label.equalsIgnoreCase("BENIGN")) {

                            newLabel = "NORMAL";

                        } else if (
                                label.equalsIgnoreCase("DDoS")
                                        ||
                                        label.equalsIgnoreCase("PortScan")
                        ) {

                            newLabel = "ATTACK";

                        } else {

                            continue;
                        }

                        // ==========================================
                        // NUMERIC FEATURE VALIDATION
                        // ==========================================

                        boolean valid = true;

                        for (int i = 0; i < 78; i++) {

                            String value =
                                    values[i].trim();

                            if (
                                    value.isEmpty()
                                            ||
                                            value.equalsIgnoreCase("Infinity")
                                            ||
                                            value.equalsIgnoreCase("-Infinity")
                                            ||
                                            value.equalsIgnoreCase("NaN")
                            ) {

                                valid = false;
                                break;
                            }

                            try {

                                double number =
                                        Double.parseDouble(value);

                                if (!Double.isFinite(number)) {

                                    valid = false;
                                    break;
                                }

                            } catch (NumberFormatException e) {

                                valid = false;
                                break;
                            }
                        }

                        if (!valid) {
                            continue;
                        }

                        // Change label
                        values[78] = newLabel;

                        // ==========================================
                        // BALANCED SAMPLING
                        // ==========================================

                        if (newLabel.equals("NORMAL")) {

                            addRandom(
                                    normalRows,
                                    values
                            );

                        } else {

                            addRandom(
                                    attackRows,
                                    values
                            );
                        }

                        accepted++;
                    }

                    System.out.println(
                            "Rows read: " + total
                                    + " | Accepted: "
                                    + accepted
                    );
                }
            }

            // ==========================================
            // DATA SUMMARY
            // ==========================================

            System.out.println();

            System.out.println(
                    "NORMAL samples: "
                            + normalRows.size()
            );

            System.out.println(
                    "ATTACK samples: "
                            + attackRows.size()
            );

            int finalSize =
                    Math.min(
                            normalRows.size(),
                            attackRows.size()
                    );

            if (finalSize == 0) {

                System.out.println(
                        "ERROR: No usable data found."
                );

                return;
            }

            // ==========================================
            // SHUFFLE
            // ==========================================

            Collections.shuffle(
                    normalRows,
                    RANDOM
            );

            Collections.shuffle(
                    attackRows,
                    RANDOM
            );

            // ==========================================
            // WRITE OUTPUT
            // ==========================================

            try (BufferedWriter writer =
                         Files.newBufferedWriter(
                                 Path.of(output)
                         )) {

                writer.write(header);
                writer.newLine();

                for (int i = 0; i < finalSize; i++) {

                    writer.write(
                            String.join(
                                    ",",
                                    normalRows.get(i)
                            )
                    );

                    writer.newLine();

                    writer.write(
                            String.join(
                                    ",",
                                    attackRows.get(i)
                            )
                    );

                    writer.newLine();
                }
            }

            // ==========================================
            // FINAL RESULT
            // ==========================================

            System.out.println();

            System.out.println(
                    "================================"
            );

            System.out.println(
                    "PREPROCESSING COMPLETE"
            );

            System.out.println(
                    "================================"
            );

            System.out.println(
                    "Output file: " + output
            );

            System.out.println(
                    "NORMAL: " + finalSize
            );

            System.out.println(
                    "ATTACK: " + finalSize
            );

            System.out.println(
                    "TOTAL: " + (finalSize * 2)
            );

        } catch (Exception e) {

            e.printStackTrace();
        }
    }


    // ==========================================
    // MAKE HEADER NAMES UNIQUE
    // ==========================================

    private static void makeUniqueHeaders(
            String[] headers) {

        Map<String, Integer> count =
                new HashMap<>();

        for (int i = 0;
             i < headers.length;
             i++) {

            String original =
                    headers[i].trim();

            if (!count.containsKey(original)) {

                count.put(original, 1);

                headers[i] = original;

            } else {

                int number =
                        count.get(original) + 1;

                count.put(
                        original,
                        number
                );

                headers[i] =
                        original + "_" + number;
            }
        }
    }


    // ==========================================
    // RANDOM SAMPLING
    // ==========================================

    private static void addRandom(
            List<String[]> list,
            String[] row) {

        if (list.size() < MAX_PER_CLASS) {

            list.add(
                    row.clone()
            );

        } else {

            int index =
                    RANDOM.nextInt(
                            list.size()
                    );

            if (index < MAX_PER_CLASS) {

                list.set(
                        index,
                        row.clone()
                );
            }
        }
    }
}