package com.ids.ui;

import com.ids.db.DatabaseConnection;
import com.ids.security.PasswordUtil;
import com.ids.security.UserSession;

import javax.swing.*;
import java.awt.*;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class LoginFrame extends JFrame {

    private JTextField usernameField;
    private JPasswordField passwordField;

    public LoginFrame() {

        setTitle("Java ML IDS - Login");

        setSize(450, 450);

        setLocationRelativeTo(null);

        setDefaultCloseOperation(
                JFrame.EXIT_ON_CLOSE
        );

        setResizable(false);

        buildUI();
    }

    private void buildUI() {

        JPanel mainPanel = new JPanel();

        mainPanel.setLayout(
                new BoxLayout(
                        mainPanel,
                        BoxLayout.Y_AXIS
                )
        );

        mainPanel.setBorder(
                BorderFactory.createEmptyBorder(
                        35,
                        50,
                        30,
                        50
                )
        );

        // =========================
        // TITLE
        // =========================

        JLabel title =
                new JLabel("JAVA ML IDS");

        title.setFont(
                new Font(
                        "Arial",
                        Font.BOLD,
                        28
                )
        );

        title.setAlignmentX(
                Component.CENTER_ALIGNMENT
        );

        mainPanel.add(title);

        mainPanel.add(
                Box.createVerticalStrut(8)
        );

        JLabel subtitle =
                new JLabel(
                        "INTRUSION DETECTION SYSTEM"
                );

        subtitle.setAlignmentX(
                Component.CENTER_ALIGNMENT
        );

        subtitle.setForeground(
                Color.GRAY
        );

        mainPanel.add(subtitle);

        mainPanel.add(
                Box.createVerticalStrut(30)
        );

        // =========================
        // USERNAME
        // =========================

        JLabel usernameLabel =
                new JLabel("Username");

        usernameLabel.setAlignmentX(
                Component.CENTER_ALIGNMENT
        );

        mainPanel.add(usernameLabel);

        mainPanel.add(
                Box.createVerticalStrut(5)
        );

        usernameField =
                new JTextField();

        usernameField.setMaximumSize(
                new Dimension(
                        Integer.MAX_VALUE,
                        38
                )
        );

        mainPanel.add(usernameField);

        mainPanel.add(
                Box.createVerticalStrut(18)
        );

        // =========================
        // PASSWORD
        // =========================

        JLabel passwordLabel =
                new JLabel("Password");

        passwordLabel.setAlignmentX(
                Component.CENTER_ALIGNMENT
        );

        mainPanel.add(passwordLabel);

        mainPanel.add(
                Box.createVerticalStrut(5)
        );

        passwordField =
                new JPasswordField();

        passwordField.setMaximumSize(
                new Dimension(
                        Integer.MAX_VALUE,
                        38
                )
        );

        mainPanel.add(passwordField);

        mainPanel.add(
                Box.createVerticalStrut(25)
        );

        // =========================
        // LOGIN BUTTON
        // =========================

        JButton loginButton =
                new JButton("LOGIN");

        loginButton.setAlignmentX(
                Component.CENTER_ALIGNMENT
        );

        loginButton.setPreferredSize(
                new Dimension(
                        220,
                        40
                )
        );

        loginButton.setMaximumSize(
                new Dimension(
                        220,
                        40
                )
        );

        loginButton.addActionListener(
                e -> login()
        );

        mainPanel.add(loginButton);

        mainPanel.add(
                Box.createVerticalStrut(15)
        );

        // =========================
        // SIGNUP BUTTON
        // =========================

        JButton signupButton =
                new JButton(
                        "Create New Account"
                );

        signupButton.setAlignmentX(
                Component.CENTER_ALIGNMENT
        );

        signupButton.setBorderPainted(false);

        signupButton.setContentAreaFilled(false);

        signupButton.setCursor(
                new Cursor(
                        Cursor.HAND_CURSOR
                )
        );

        signupButton.addActionListener(e -> {

            dispose();

            new SignupFrame()
                    .setVisible(true);
        });

        mainPanel.add(signupButton);

        mainPanel.add(
                Box.createVerticalStrut(10)
        );

        JLabel infoLabel =
                new JLabel(
                        "Secure ML-based Intrusion Detection"
                );

        infoLabel.setFont(
                new Font(
                        "Arial",
                        Font.PLAIN,
                        11
                )
        );

        infoLabel.setForeground(
                Color.GRAY
        );

        infoLabel.setAlignmentX(
                Component.CENTER_ALIGNMENT
        );

        mainPanel.add(infoLabel);

        add(mainPanel);
    }

    // ==================================================
    // LOGIN METHOD
    // ==================================================

    private void login() {

        String username =
                usernameField
                        .getText()
                        .trim();

        String password =
                new String(
                        passwordField
                                .getPassword()
                );

        // =========================
        // VALIDATION
        // =========================

        if (username.isEmpty()
                || password.isEmpty()) {

            JOptionPane.showMessageDialog(
                    this,
                    "Please enter username and password.",
                    "Login Error",
                    JOptionPane.ERROR_MESSAGE
            );

            return;
        }

        String passwordHash;

        try {

            passwordHash =
                    PasswordUtil.hashPassword(
                            password
                    );

        } catch (Exception e) {

            JOptionPane.showMessageDialog(
                    this,
                    "Password processing failed.",
                    "Error",
                    JOptionPane.ERROR_MESSAGE
            );

            return;
        }

        // =========================
        // DATABASE QUERY
        // =========================

        String sql =
                "SELECT id, name, username " +
                        "FROM users " +
                        "WHERE username = ? " +
                        "AND password_hash = ?";

        try (
                Connection connection =
                        DatabaseConnection
                                .getConnection();

                PreparedStatement statement =
                        connection.prepareStatement(
                                sql
                        )
        ) {

            statement.setString(
                    1,
                    username
            );

            statement.setString(
                    2,
                    passwordHash
            );

            ResultSet result =
                    statement.executeQuery();

            // =========================
            // LOGIN SUCCESS
            // =========================

            if (result.next()) {

                int userId =
                        result.getInt(
                                "id"
                        );

                String name =
                        result.getString(
                                "name"
                        );

                String databaseUsername =
                        result.getString(
                                "username"
                        );

                // Create user session
                UserSession.createSession(
                        userId,
                        name,
                        databaseUsername
                );

                // Save successful login
                logLogin(
                        databaseUsername,
                        "SUCCESS"
                );

                JOptionPane.showMessageDialog(
                        this,
                        "Login successful!\n\n"
                                + "Welcome, "
                                + name
                                + "!",
                        "Login Successful",
                        JOptionPane.INFORMATION_MESSAGE
                );

                // Clear password from memory reference
                passwordField.setText("");

                // Close login window
                dispose();

                // Open dashboard
                new Dashboard()
                        .setVisible(true);

            }

            // =========================
            // LOGIN FAILED
            // =========================

            else {

                logLogin(
                        username,
                        "FAILED"
                );

                JOptionPane.showMessageDialog(
                        this,
                        "Invalid username or password.",
                        "Login Failed",
                        JOptionPane.ERROR_MESSAGE
                );

                passwordField.setText("");

                passwordField.requestFocus();
            }

        } catch (Exception e) {

            JOptionPane.showMessageDialog(
                    this,
                    "Database connection error:\n\n"
                            + e.getMessage(),
                    "Database Error",
                    JOptionPane.ERROR_MESSAGE
            );

            e.printStackTrace();
        }
    }

    // ==================================================
    // LOGIN LOG
    // ==================================================

    private void logLogin(
            String username,
            String status
    ) {

        String sql =
                "INSERT INTO login_logs "
                        + "(username, status) "
                        + "VALUES (?, ?)";

        try (
                Connection connection =
                        DatabaseConnection
                                .getConnection();

                PreparedStatement statement =
                        connection.prepareStatement(
                                sql
                        )
        ) {

            statement.setString(
                    1,
                    username
            );

            statement.setString(
                    2,
                    status
            );

            statement.executeUpdate();

        } catch (Exception e) {

            System.out.println(
                    "Login log error: "
                            + e.getMessage()
            );
        }
    }

    // ==================================================
    // MAIN
    // ==================================================

    public static void main(
            String[] args
    ) {

        SwingUtilities.invokeLater(() -> {

            LoginFrame loginFrame =
                    new LoginFrame();

            loginFrame.setVisible(true);
        });
    }
}