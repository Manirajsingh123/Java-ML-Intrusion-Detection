# Project Guide

## Objective
Detect whether a network-flow record should be classified as NORMAL or ATTACK using a supervised ML classifier.

## ML
Random Forest is used as the baseline classifier. Weka is a Java machine-learning toolkit; its libraries are designed to be called from Java applications.

## Important academic point
The included dataset is only a tiny synthetic demo dataset so the source code can be run without downloading a large dataset. Do NOT report its accuracy as a real-world IDS result. For your final evaluation, use a recognized IDS dataset, document its preprocessing, train/test split, class balance, and results.

## Suggested extensions
1. Add protocol/service categorical fields and Weka encoding.
2. Add train/test CSV selection in the GUI.
3. Add MySQL logging.
4. Add charts for confusion matrix and class distribution.
5. Compare Random Forest, J48 and Naive Bayes.
6. Add a threshold-based alert level.
7. Add authentication and role-based access for an actual deployment.

## Safety
This project is designed for defensive/educational intrusion detection and should be tested only with data and systems you are authorized to monitor.
