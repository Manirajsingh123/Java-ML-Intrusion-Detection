package com.ids.ml;

import java.io.*;
import java.nio.file.*;
import java.util.*;

public class TestDataCreator {

    public static void main(String[] args) throws Exception {

        String input = "data/ids_training.csv";
        String output = "data/test_input.csv";

        List<String> lines = Files.readAllLines(Path.of(input));

        if (lines.size() < 11) {
            System.out.println("Not enough data!");
            return;
        }

        List<String> result = new ArrayList<>();

        // Header
        result.add(lines.get(0));

        // First 5 NORMAL samples
        for (int i = 1; i <= 5; i++) {
            result.add(lines.get(i));
        }

        // Last 5 ATTACK samples
        for (int i = lines.size() - 5; i < lines.size(); i++) {
            result.add(lines.get(i));
        }

        Files.write(Path.of(output), result);

        System.out.println("=================================");
        System.out.println("TEST CSV CREATED");
        System.out.println("=================================");
        System.out.println("File: " + output);
        System.out.println("Samples: " + (result.size() - 1));
    }
}