# Java ML Intrusion Detection System

College-project reference implementation using Java 17 + Maven + Weka RandomForest.

## Features
- Train a Random Forest classifier from CSV/ARFF data
- Evaluate with accuracy, precision, recall, F1 and confusion matrix
- Save/load the trained model
- Predict a new CSV row
- Simple Swing dashboard
- Uses a small included demo dataset so the project runs immediately

## Run
1. Install JDK 17+ and Maven.
2. From the project folder:
   `mvn clean compile`
3. Train/evaluate:
   `mvn exec:java -Dexec.args="train"`
4. Predict:
   `mvn exec:java -Dexec.args="predict data/sample_input.csv"`
5. GUI:
   `mvn exec:java -Dexec.args="gui"`

For a serious experiment, replace `data/demo_ids.csv` with a properly prepared public IDS dataset and keep train/test data separated.
