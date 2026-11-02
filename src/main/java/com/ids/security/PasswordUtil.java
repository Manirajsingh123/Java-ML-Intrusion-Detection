package com.ids.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class PasswordUtil {

    public static String hashPassword(String password)
            throws Exception {

        MessageDigest md =
                MessageDigest.getInstance("SHA-256");

        byte[] hash =
                md.digest(
                        password.getBytes(
                                StandardCharsets.UTF_8
                        )
                );

        StringBuilder hex =
                new StringBuilder();

        for (byte b : hash) {
            hex.append(
                    String.format("%02x", b)
            );
        }

        return hex.toString();
    }
}