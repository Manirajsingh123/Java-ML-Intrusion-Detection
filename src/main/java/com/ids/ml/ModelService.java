package com.ids.ml;

import weka.classifiers.Evaluation;
import weka.classifiers.trees.RandomForest;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.SerializationHelper;
import weka.core.converters.CSVLoader;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;

public class ModelService {

    private RandomForest model;

    private final String DATASET =
            "data/ids_training.csv";

    private final String MODEL_FILE =
            "models/ids_random_forest.model";


    // =========================================================
    // TRAIN MODEL
    // =========================================================

    public void train() throws Exception {

        System.out.println("=================================");
        System.out.println("JAVA ML INTRUSION DETECTION SYSTEM");
        System.out.println("=================================");
        System.out.println();

        System.out.println("Loading training dataset...");

        File datasetFile = new File(DATASET);

        if (!datasetFile.exists()) {
            throw new Exception(
                    "Training dataset not found: "
                            + DATASET
            );
        }

        CSVLoader loader = new CSVLoader();

        loader.setSource(datasetFile);

        Instances data = loader.getDataSet();

        if (data == null || data.numInstances() == 0) {
            throw new Exception(
                    "Training dataset is empty!"
            );
        }

        // Last column = Label
        data.setClassIndex(
                data.numAttributes() - 1
        );


        // =====================================================
        // DATASET INFORMATION
        // =====================================================

        System.out.println(
                "Total instances: "
                        + data.numInstances()
        );

        System.out.println(
                "Total attributes: "
                        + data.numAttributes()
        );

        System.out.println(
                "Class attribute: "
                        + data.classAttribute().name()
        );


        // =====================================================
        // RANDOMIZE DATA
        // =====================================================

        data.randomize(
                new Random(42)
        );


        // =====================================================
        // 80% TRAINING - 20% TESTING
        // =====================================================

        int trainSize =
                (int) (
                        data.numInstances()
                                * 0.80
                );

        int testSize =
                data.numInstances()
                        - trainSize;


        Instances trainData =
                new Instances(
                        data,
                        0,
                        trainSize
                );


        Instances testData =
                new Instances(
                        data,
                        trainSize,
                        testSize
                );


        trainData.setClassIndex(
                trainData.numAttributes() - 1
        );

        testData.setClassIndex(
                testData.numAttributes() - 1
        );


        System.out.println();

        System.out.println(
                "Training samples: "
                        + trainSize
        );

        System.out.println(
                "Testing samples: "
                        + testSize
        );


        // =====================================================
        // RANDOM FOREST
        // =====================================================

        System.out.println();
        System.out.println(
                "Training Random Forest..."
        );

        model = new RandomForest();

        // Number of trees
        model.setNumIterations(100);

        model.buildClassifier(
                trainData
        );

        System.out.println(
                "Training completed successfully."
        );


        // =====================================================
        // MODEL EVALUATION
        // =====================================================

        Evaluation evaluation =
                new Evaluation(trainData);

        evaluation.evaluateModel(
                model,
                testData
        );


        /*
         * IMPORTANT:
         *
         * Weka Evaluation does NOT have:
         *
         * evaluation.accuracy()
         *
         * Therefore use:
         *
         * evaluation.pctCorrect()
         *
         * pctCorrect() returns percentage.
         */

        double accuracy =
                evaluation.pctCorrect();

        double precision =
                evaluation.weightedPrecision();

        double recall =
                evaluation.weightedRecall();

        double f1 =
                evaluation.weightedFMeasure();


        // =====================================================
        // DISPLAY RESULTS
        // =====================================================

        System.out.println();
        System.out.println(
                "================================="
        );

        System.out.println(
                "MODEL EVALUATION"
        );

        System.out.println(
                "================================="
        );

        System.out.printf(
                "Test samples : %d%n",
                testSize
        );

        System.out.printf(
                "Accuracy     : %.2f%%%n",
                accuracy
        );

        System.out.printf(
                "Precision    : %.4f%n",
                precision
        );

        System.out.printf(
                "Recall       : %.4f%n",
                recall
        );

        System.out.printf(
                "F1 Score     : %.4f%n",
                f1
        );


        // =====================================================
        // CONFUSION MATRIX
        // =====================================================

        System.out.println();
        System.out.println(
                "Confusion Matrix:"
        );

        System.out.println(
                evaluation.toMatrixString()
        );


        // =====================================================
        // SAVE MODEL
        // =====================================================

        File modelFolder =
                new File("models");

        if (!modelFolder.exists()) {
            boolean created =
                    modelFolder.mkdirs();

            if (!created) {
                throw new Exception(
                        "Could not create models folder."
                );
            }
        }


        SerializationHelper.write(
                MODEL_FILE,
                model
        );


        System.out.println();

        System.out.println(
                "Model saved successfully!"
        );

        System.out.println(
                "Model file: "
                        + MODEL_FILE
        );

        System.out.println();
    }


    // =========================================================
    // LOAD MODEL
    // =========================================================

    public void load() throws Exception {

        File file =
                new File(MODEL_FILE);

        if (!file.exists()) {

            throw new Exception(
                    "Model not found!\n"
                            + "Please train the model first."
            );
        }


        model =
                (RandomForest)
                        SerializationHelper.read(
                                MODEL_FILE
                        );


        System.out.println(
                "Model loaded successfully."
        );
    }


    // =========================================================
    // PREDICT CSV FILE
    // =========================================================

    public void predict(
            String csvPath
    ) throws Exception {

        // Load model if not already loaded
        if (model == null) {
            load();
        }


        File csvFile =
                new File(csvPath);

        if (!csvFile.exists()) {
            throw new Exception(
                    "Prediction CSV file not found: "
                            + csvPath
            );
        }


        CSVLoader loader =
                new CSVLoader();

        loader.setSource(
                csvFile
        );


        Instances data =
                loader.getDataSet();


        if (
                data == null
                        || data.numInstances() == 0
        ) {

            throw new Exception(
                    "No data found in CSV file."
            );
        }


        // Last column = Label
        data.setClassIndex(
                data.numAttributes() - 1
        );


        System.out.println();
        System.out.println(
                "Prediction Results"
        );

        System.out.println(
                "--------------------------------"
        );


        // =====================================================
        // PREDICT EACH ROW
        // =====================================================

        for (
                int i = 0;
                i < data.numInstances();
                i++
        ) {

            Instance instance =
                    data.instance(i);


            double prediction =
                    model.classifyInstance(
                            instance
                    );


            String label =
                    data.classAttribute()
                            .value(
                                    (int) prediction
                            );


            double[] probability =
                    model.distributionForInstance(
                            instance
                    );


            double confidence = 0.0;


            int predictionIndex =
                    (int) prediction;


            if (
                    predictionIndex >= 0
                            && predictionIndex
                            < probability.length
            ) {

                confidence =
                        probability[
                                predictionIndex
                                ] * 100.0;
            }


            System.out.printf(
                    "Row %d -> %s (%.2f%% confidence)%n",
                    i + 1,
                    label,
                    confidence
            );
        }
    }


    // =========================================================
    // SINGLE ROW PREDICTION
    // =========================================================

    public String predictSingleRow(
            String header,
            String row
    ) throws Exception {

        // Load model if required
        if (model == null) {
            load();
        }


        // =====================================================
        // LOAD TRAINING STRUCTURE
        // =====================================================

        File datasetFile =
                new File(DATASET);

        if (!datasetFile.exists()) {
            throw new Exception(
                    "Training dataset not found."
            );
        }


        CSVLoader trainingLoader =
                new CSVLoader();

        trainingLoader.setSource(
                datasetFile
        );


        Instances structure =
                trainingLoader.getDataSet();


        if (
                structure == null
                        || structure.numInstances() == 0
        ) {

            throw new Exception(
                    "Training structure not found."
            );
        }


        structure.setClassIndex(
                structure.numAttributes() - 1
        );


        // =====================================================
        // TEMPORARY CSV FILE
        // =====================================================

        File dataFolder =
                new File("data");

        if (!dataFolder.exists()) {
            dataFolder.mkdirs();
        }


        String tempFile =
                "data/live_temp.csv";


        try (
                PrintWriter writer =
                        new PrintWriter(
                                new FileWriter(
                                        tempFile
                                )
                        )
        ) {

            writer.println(header);

            writer.println(row);
        }


        // =====================================================
        // LOAD LIVE DATA
        // =====================================================

        CSVLoader liveLoader =
                new CSVLoader();

        liveLoader.setSource(
                new File(tempFile)
        );


        Instances liveData =
                liveLoader.getDataSet();


        if (
                liveData == null
                        || liveData.numInstances() == 0
        ) {

            deleteTempFile(tempFile);

            throw new Exception(
                    "No live traffic data found."
            );
        }


        liveData.setClassIndex(
                liveData.numAttributes() - 1
        );


        // =====================================================
        // CHECK FEATURE COUNT
        // =====================================================

        if (
                liveData.numAttributes()
                        != structure.numAttributes()
        ) {

            deleteTempFile(tempFile);

            throw new Exception(
                    "Feature count mismatch.\n"
                            + "Training features: "
                            + structure.numAttributes()
                            + "\nLive features: "
                            + liveData.numAttributes()
            );
        }


        // =====================================================
        // GET LIVE INSTANCE
        // =====================================================

        Instance liveInstance =
                liveData.instance(0);


        double[] values =
                new double[
                        structure.numAttributes()
                        ];


        // =====================================================
        // COPY FEATURES
        // =====================================================

        for (
                int i = 0;
                i < structure.numAttributes() - 1;
                i++
        ) {

            values[i] =
                    liveInstance.value(i);
        }


        // =====================================================
        // TEMPORARY CLASS VALUE
        // =====================================================

        int normalIndex =
                structure.classAttribute()
                        .indexOfValue(
                                "NORMAL"
                        );


        /*
         * If NORMAL does not exist,
         * use first class value.
         */

        if (normalIndex < 0) {
            normalIndex = 0;
        }


        values[
                structure.numAttributes() - 1
                ] = normalIndex;


        // =====================================================
        // CREATE NEW INSTANCE
        // =====================================================

        DenseInstance instance =
                new DenseInstance(
                        1.0,
                        values
                );


        instance.setDataset(
                structure
        );


        // =====================================================
        // MAKE PREDICTION
        // =====================================================

        double prediction =
                model.classifyInstance(
                        instance
                );


        String label =
                structure.classAttribute()
                        .value(
                                (int) prediction
                        );


        // =====================================================
        // CONFIDENCE
        // =====================================================

        double[] probabilities =
                model.distributionForInstance(
                        instance
                );


        int predictionIndex =
                (int) prediction;


        double confidence = 0.0;


        if (
                predictionIndex >= 0
                        && predictionIndex
                        < probabilities.length
        ) {

            confidence =
                    probabilities[
                            predictionIndex
                            ] * 100.0;
        }


        // =====================================================
        // DELETE TEMPORARY FILE
        // =====================================================

        deleteTempFile(tempFile);


        // =====================================================
        // RETURN RESULT
        // =====================================================

        return String.format(
                "%s (%.2f%% confidence)",
                label,
                confidence
        );
    }


    // =========================================================
    // DELETE TEMP FILE
    // =========================================================

    private void deleteTempFile(
            String filePath
    ) {

        try {

            Files.deleteIfExists(
                    Path.of(filePath)
            );

        } catch (Exception ignored) {
            // Ignore cleanup error
        }
    }
}