package com.ids;

import com.ids.ml.ModelService;

public class Main {

    public static void main(String[] args) {

        System.out.println(
                "===================================="
        );
        System.out.println(
                "JAVA ML INTRUSION DETECTION SYSTEM"
        );
        System.out.println(
                "===================================="
        );

        ModelService service =
                new ModelService();

        try {

            if (args.length == 0) {

                System.out.println();
                System.out.println("Usage:");
                System.out.println("  train");
                System.out.println("  predict <csv>");
                System.out.println("  gui");

                return;
            }


            // ==========================================
            // TRAIN
            // ==========================================

            if (args[0].equalsIgnoreCase("train")) {

                System.out.println();
                System.out.println(
                        "Starting model training..."
                );

                service.train();

                System.out.println();
                System.out.println(
                        "Training completed successfully!"
                );

                return;
            }


            // ==========================================
            // PREDICT
            // ==========================================

            if (args[0].equalsIgnoreCase("predict")) {

                if (args.length < 2) {

                    System.out.println(
                            "Please provide CSV file path."
                    );

                    System.out.println(
                            "Example:"
                    );

                    System.out.println(
                            "predict data/test_input.csv"
                    );

                    return;
                }

                service.predict(args[1]);

                return;
            }


            // ==========================================
            // GUI
            // ==========================================

            if (args[0].equalsIgnoreCase("gui")) {

                com.ids.ui.Dashboard.main(
                        new String[]{}
                );

                return;
            }


            // ==========================================
            // UNKNOWN COMMAND
            // ==========================================

            System.out.println(
                    "Unknown command: "
                            + args[0]
            );

            System.out.println();
            System.out.println("Available commands:");
            System.out.println("  train");
            System.out.println("  predict <csv>");
            System.out.println("  gui");

        } catch (Exception e) {

            System.out.println();
            System.out.println(
                    "ERROR:"
            );

            System.out.println(
                    e.getMessage()
            );

            e.printStackTrace();
        }
    }
}