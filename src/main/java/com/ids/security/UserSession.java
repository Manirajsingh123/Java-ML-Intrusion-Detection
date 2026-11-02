package com.ids.security;

public class UserSession {

    private static int userId;
    private static String name;
    private static String username;

    private UserSession() {
        // Prevent object creation
    }

    public static void createSession(
            int id,
            String userName,
            String userUsername
    ) {
        userId = id;
        name = userName;
        username = userUsername;
    }

    public static int getUserId() {
        return userId;
    }

    public static String getName() {
        return name;
    }

    public static String getUsername() {
        return username;
    }

    public static boolean isLoggedIn() {
        return userId > 0;
    }

    public static void logout() {
        userId = 0;
        name = null;
        username = null;
    }
}