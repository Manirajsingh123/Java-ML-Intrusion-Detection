package com.ids.ui;

import com.ids.db.DatabaseConnection;
import com.ids.security.PasswordUtil;

import javax.swing.*;
import java.awt.*;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class SignupFrame extends JFrame {

    private JTextField nameField;
    private JTextField usernameField;
    private JPasswordField passwordField;
    private JPasswordField confirmPasswordField;

    public SignupFrame() {

        setTitle("Java ML IDS - Sign Up");
        setSize(450, 500);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setResizable(false);

        buildUI();
    }

    private void buildUI() {

        JPanel mainPanel =
                new JPanel();

        mainPanel.setLayout(
                new BoxLayout(
                        mainPanel,
                        BoxLayout.Y_AXIS
                )
        );

        mainPanel.setBorder(
                BorderFactory.createEmptyBorder(
                        30, 45, 30, 45
                )
        );

        JLabel title =
                new JLabel("CREATE ACCOUNT");

        title.setFont(
                new Font(
                        "Arial",
                        Font.BOLD,
                        24
                )
        );

        title.setAlignmentX(
                Component.CENTER_ALIGNMENT
        );

        mainPanel.add(title);
        mainPanel.add(
                Box.createVerticalStrut(25)
        );

        nameField =
                new JTextField();

        usernameField =
                new JTextField();

        passwordField =
                new JPasswordField();

        confirmPasswordField =
                new JPasswordField();

        addField(
                mainPanel,
                "Full Name",
                nameField
        );

        addField(
                mainPanel,
                "Username",
                usernameField
        );

        addField(
                mainPanel,
                "Password",
                passwordField
        );

        addField(
                mainPanel,
                "Confirm Password",
                confirmPasswordField
        );

        mainPanel.add(
                Box.createVerticalStrut(20)
        );

        JButton signupButton =
                new JButton("CREATE ACCOUNT");

        signupButton.setAlignmentX(
                Component.CENTER_ALIGNMENT
        );

        signupButton.setPreferredSize(
                new Dimension(250, 40)
        );

        signupButton.addActionListener(
                e -> signup()
        );

        mainPanel.add(signupButton);

        mainPanel.add(
                Box.createVerticalStrut(15)
        );

        JButton loginButton =
                new JButton("Already have an account? Login");

        loginButton.setAlignmentX(
                Component.CENTER_ALIGNMENT
        );

        loginButton.setBorderPainted(false);
        loginButton.setContentAreaFilled(false);

        loginButton.addActionListener(e -> {

            dispose();

            new LoginFrame().setVisible(true);
        });

        mainPanel.add(loginButton);

        add(mainPanel);
    }

    private void addField(
            JPanel panel,
            String label,
            JComponent field
    ) {

        JLabel jLabel =
                new JLabel(label);

        jLabel.setAlignmentX(
                Component.CENTER_ALIGNMENT
        );

        panel.add(jLabel);

        panel.add(
                Box.createVerticalStrut(5)
        );

        field.setMaximumSize(
                new Dimension(
                        Integer.MAX_VALUE,
                        35
                )
        );

        panel.add(field);

        panel.add(
                Box.createVerticalStrut(12)
        );
    }

    private void signup() {

        String name =
                nameField.getText().trim();

        String username =
                usernameField.getText().trim();

        String password =
                new String(
                        passwordField.getPassword()
                );

        String confirmPassword =
                new String(
                        confirmPasswordField.getPassword()
                );

        if (name.isEmpty()
                || username.isEmpty()
                || password.isEmpty()
                || confirmPassword.isEmpty()) {

            JOptionPane.showMessageDialog(
                    this,
                    "Please fill all fields.",
                    "Error",
                    JOptionPane.ERROR_MESSAGE
            );

            return;
        }

        if (!password.equals(confirmPassword)) {

            JOptionPane.showMessageDialog(
                    this,
                    "Passwords do not match.",
                    "Error",
                    JOptionPane.ERROR_MESSAGE
            );

            return;
        }

        if (password.length() < 6) {

            JOptionPane.showMessageDialog(
                    this,
                    "Password must contain at least 6 characters.",
                    "Error",
                    JOptionPane.ERROR_MESSAGE
            );

            return;
        }

        String checkSQL =
                "SELECT id FROM users WHERE username = ?";

        String insertSQL =
                "INSERT INTO users " +
                        "(name, username, password_hash) " +
                        "VALUES (?, ?, ?)";

        try (
                Connection connection =
                        DatabaseConnection.getConnection();

                PreparedStatement checkStatement =
                        connection.prepareStatement(checkSQL)
        ) {

            checkStatement.setString(
                    1,
                    username
            );

            ResultSet result =
                    checkStatement.executeQuery();

            if (result.next()) {

                JOptionPane.showMessageDialog(
                        this,
                        "Username already exists.",
                        "Signup Failed",
                        JOptionPane.ERROR_MESSAGE
                );

                return;
            }

            String passwordHash =
                    PasswordUtil.hashPassword(
                            password
                    );

            try (
                    PreparedStatement statement =
                            connection.prepareStatement(
                                    insertSQL
                            )
            ) {

                statement.setString(
                        1,
                        name
                );

                statement.setString(
                        2,
                        username
                );

                statement.setString(
                        3,
                        passwordHash
                );

                statement.executeUpdate();
            }

            JOptionPane.showMessageDialog(
                    this,
                    "Account created successfully!",
                    "Success",
                    JOptionPane.INFORMATION_MESSAGE
            );

            dispose();

            new LoginFrame().setVisible(true);

        } catch (Exception e) {

            JOptionPane.showMessageDialog(
                    this,
                    "Database error:\n"
                            + e.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE
            );

            e.printStackTrace();
        }
    }

    public static void main(String[] args) {

        SwingUtilities.invokeLater(() -> {

            new SignupFrame().setVisible(true);

        });
    }
}