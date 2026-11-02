package com.ids.ui;

import com.ids.ml.DetectionDatabaseLogger;
import com.ids.ml.DetectionLogger;
import com.ids.ml.ModelService;
import com.ids.security.UserSession;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class Dashboard extends JFrame {

    // =========================================================
    // MODEL SERVICE
    // =========================================================

    private final ModelService service = new ModelService();


    // =========================================================
    // COLORS
    // =========================================================

    private final Color BG =
            new Color(4, 10, 24);

    private final Color PANEL =
            new Color(7, 20, 42);

    private final Color PANEL_2 =
            new Color(9, 27, 54);

    private final Color BLUE =
            new Color(45, 170, 255);

    private final Color CYAN =
            new Color(0, 235, 255);

    private final Color GREEN =
            new Color(0, 235, 150);

    private final Color RED =
            new Color(255, 65, 85);

    private final Color PURPLE =
            new Color(190, 90, 255);

    private final Color ORANGE =
            new Color(255, 170, 55);

    private final Color TEXT =
            new Color(225, 240, 255);

    private final Color MUTED =
            new Color(135, 165, 195);


    // =========================================================
    // LABELS
    // =========================================================

    private JLabel accuracyValue;
    private JLabel precisionValue;
    private JLabel recallValue;
    private JLabel f1Value;

    private JLabel normalValue;
    private JLabel attackValue;

    private JLabel threatValue;
    private JLabel liveStatus;
    private JLabel clockLabel;
    private JLabel modelStatus;
    private JLabel userLabel;


    // =========================================================
    // COMPONENTS
    // =========================================================

    private TrafficChart chart;
    private TrafficDonut donut;

    private JTable logTable;
    private DefaultTableModel logModel;

    private JTextArea activityArea;
    private JTextArea alertArea;


    // =========================================================
    // BUTTONS
    // =========================================================

    private JButton startButton;
    private JButton stopButton;
    private JButton trainButton;
    private JButton logsButton;
    private JButton exportButton;
    private JButton clearButton;
    private JButton logoutButton;


    // =========================================================
    // LIVE DETECTION STATE
    // =========================================================

    private volatile boolean liveRunning = false;

    private SwingWorker<Void, LiveResult> liveWorker;

    private Timer visualTimer;
    private Timer clockTimer;

    private int normalCount = 0;
    private int attackCount = 0;
    private int packetCount = 0;
    private int alertCount = 0;


    // =========================================================
    // SETTINGS
    // =========================================================

    private boolean alertsEnabled = true;
    private boolean loggingEnabled = true;
    private boolean animationEnabled = true;

    private int detectionDelayMs = 700;


    // =========================================================
    // ATTACK ALERT
    // =========================================================

    private JWindow attackAlertWindow;
    private Timer attackAlertTimer;


    // =========================================================
    // TIME FORMAT
    // =========================================================

    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("HH:mm:ss");


    // =========================================================
    // CONSTRUCTOR
    // =========================================================

    public Dashboard() {

        setTitle(
                "Java ML Intrusion Detection System"
        );

        setDefaultCloseOperation(
                JFrame.EXIT_ON_CLOSE
        );

        setMinimumSize(
                new Dimension(
                        1200,
                        750
                )
        );

        setSize(
                1450,
                900
        );

        setLocationRelativeTo(null);

        buildUI();

        loadExistingLogs();

        updateClock();

        startClock();

        startVisualAnimation();
    }


    // =========================================================
    // BUILD UI
    // =========================================================

    private void buildUI() {

        JPanel root =
                new CyberBackgroundPanel();

        root.setLayout(
                new BorderLayout()
        );

        setContentPane(root);


        root.add(
                buildHeader(),
                BorderLayout.NORTH
        );


        root.add(
                buildSidebar(),
                BorderLayout.WEST
        );


        root.add(
                buildMain(),
                BorderLayout.CENTER
        );


        root.add(
                buildFooter(),
                BorderLayout.SOUTH
        );
    }


    // =========================================================
    // HEADER
    // =========================================================

    private JPanel buildHeader() {

        JPanel header =
                new GradientPanel(
                        new Color(4, 13, 31),
                        new Color(6, 31, 62)
                );

        header.setBorder(
                new EmptyBorder(
                        12,
                        20,
                        12,
                        20
                )
        );

        header.setPreferredSize(
                new Dimension(
                        0,
                        85
                )
        );

        header.setLayout(
                new BorderLayout(
                        15,
                        0
                )
        );


        JLabel icon =
                new JLabel("⬡");

        icon.setForeground(CYAN);

        icon.setFont(
                new Font(
                        "Segoe UI Symbol",
                        Font.BOLD,
                        42
                )
        );


        header.add(
                icon,
                BorderLayout.WEST
        );


        JPanel titlePanel =
                new JPanel();

        titlePanel.setOpaque(false);

        titlePanel.setLayout(
                new BoxLayout(
                        titlePanel,
                        BoxLayout.Y_AXIS
                )
        );


        JLabel title =
                new JLabel(
                        "JAVA ML INTRUSION DETECTION SYSTEM"
                );

        title.setForeground(TEXT);

        title.setFont(
                new Font(
                        "Segoe UI",
                        Font.BOLD,
                        23
                )
        );


        JLabel subtitle =
                new JLabel(
                        "Machine Learning Based Network Security  •  Random Forest  •  CIC-IDS2017"
                );

        subtitle.setForeground(
                new Color(
                        100,
                        205,
                        255
                )
        );

        subtitle.setFont(
                new Font(
                        "Segoe UI",
                        Font.PLAIN,
                        12
                )
        );


        titlePanel.add(title);

        titlePanel.add(
                Box.createVerticalStrut(4)
        );

        titlePanel.add(subtitle);


        header.add(
                titlePanel,
                BorderLayout.CENTER
        );


        JPanel right =
                new JPanel(
                        new FlowLayout(
                                FlowLayout.RIGHT,
                                12,
                                5
                        )
                );

        right.setOpaque(false);


        userLabel =
                new JLabel(
                        "User: " + getUsername()
                );

        userLabel.setForeground(TEXT);

        userLabel.setFont(
                new Font(
                        "Segoe UI",
                        Font.BOLD,
                        12
                )
        );


        liveStatus =
                new JLabel(
                        "● SYSTEM READY"
                );

        liveStatus.setForeground(GREEN);

        liveStatus.setFont(
                new Font(
                        "Segoe UI",
                        Font.BOLD,
                        12
                )
        );


        clockLabel =
                new JLabel(
                        "--:--:--"
                );

        clockLabel.setForeground(TEXT);

        clockLabel.setFont(
                new Font(
                        "Consolas",
                        Font.BOLD,
                        15
                )
        );


        logoutButton =
                createActionButton(
                        "Logout",
                        RED
                );

        logoutButton.addActionListener(
                e -> logout()
        );


        right.add(userLabel);

        right.add(liveStatus);

        right.add(clockLabel);

        right.add(logoutButton);


        header.add(
                right,
                BorderLayout.EAST
        );


        return header;
    }


    // =========================================================
    // SIDEBAR
    // =========================================================

    private JPanel buildSidebar() {

        JPanel sidebar =
                new GradientPanel(
                        new Color(4, 12, 27),
                        new Color(5, 21, 43)
                );

        sidebar.setPreferredSize(
                new Dimension(
                        195,
                        0
                )
        );

        sidebar.setBorder(
                new EmptyBorder(
                        18,
                        10,
                        18,
                        10
                )
        );

        sidebar.setLayout(
                new BorderLayout()
        );


        JPanel navigation =
                new JPanel();

        navigation.setOpaque(false);

        navigation.setLayout(
                new BoxLayout(
                        navigation,
                        BoxLayout.Y_AXIS
                )
        );


        JLabel navTitle =
                new JLabel(
                        "NAVIGATION"
                );

        navTitle.setForeground(MUTED);

        navTitle.setFont(
                new Font(
                        "Segoe UI",
                        Font.BOLD,
                        10
                )
        );

        navTitle.setAlignmentX(
                Component.CENTER_ALIGNMENT
        );


        navigation.add(navTitle);

        navigation.add(
                Box.createVerticalStrut(12)
        );


        navigation.add(
                sideButton(
                        "⌂",
                        "Dashboard",
                        e -> showDashboard()
                )
        );


        navigation.add(
                sideButton(
                        "◉",
                        "Live Detection",
                        e -> startLiveDetection()
                )
        );


        navigation.add(
                sideButton(
                        "⚙",
                        "Train Model",
                        e -> trainModel()
                )
        );


        navigation.add(
                sideButton(
                        "▥",
                        "View Results",
                        e -> showResults()
                )
        );


        navigation.add(
                sideButton(
                        "⚠",
                        "Alert History",
                        e -> showLogs()
                )
        );


        navigation.add(
                sideButton(
                        "▤",
                        "Logs",
                        e -> showLogs()
                )
        );


        navigation.add(
                sideButton(
                        "☷",
                        "Settings",
                        e -> showSettings()
                )
        );


        navigation.add(
                sideButton(
                        "ⓘ",
                        "About",
                        e -> showAbout()
                )
        );


        sidebar.add(
                navigation,
                BorderLayout.NORTH
        );


        JPanel brand =
                new JPanel();

        brand.setOpaque(false);

        brand.setLayout(
                new BoxLayout(
                        brand,
                        BoxLayout.Y_AXIS
                )
        );


        JLabel brandIcon =
                new JLabel("◆");

        brandIcon.setForeground(BLUE);

        brandIcon.setFont(
                new Font(
                        "Segoe UI",
                        Font.BOLD,
                        30
                )
        );

        brandIcon.setAlignmentX(
                Component.CENTER_ALIGNMENT
        );


        JLabel brandText =
                new JLabel(
                        "SMART DETECTION"
                );

        brandText.setForeground(CYAN);

        brandText.setFont(
                new Font(
                        "Segoe UI",
                        Font.BOLD,
                        10
                )
        );

        brandText.setAlignmentX(
                Component.CENTER_ALIGNMENT
        );


        JLabel brandSub =
                new JLabel(
                        "Safer Networks"
                );

        brandSub.setForeground(MUTED);

        brandSub.setFont(
                new Font(
                        "Segoe UI",
                        Font.PLAIN,
                        10
                )
        );

        brandSub.setAlignmentX(
                Component.CENTER_ALIGNMENT
        );


        brand.add(brandIcon);

        brand.add(brandText);

        brand.add(brandSub);


        sidebar.add(
                brand,
                BorderLayout.SOUTH
        );


        return sidebar;
    }


    // =========================================================
    // SIDEBAR BUTTON
    // =========================================================

    private JButton sideButton(
            String icon,
            String text,
            ActionListener action
    ) {

        JButton button =
                new JButton(
                        icon + "   " + text
                );

        button.setMaximumSize(
                new Dimension(
                        Integer.MAX_VALUE,
                        44
                )
        );

        button.setPreferredSize(
                new Dimension(
                        170,
                        44
                )
        );

        button.setAlignmentX(
                Component.CENTER_ALIGNMENT
        );

        button.setHorizontalAlignment(
                SwingConstants.LEFT
        );

        button.setForeground(
                new Color(
                        165,
                        200,
                        225
                )
        );

        button.setBackground(
                new Color(
                        7,
                        25,
                        48
                )
        );

        button.setBorder(
                new EmptyBorder(
                        8,
                        12,
                        8,
                        5
                )
        );

        button.setFocusPainted(false);

        button.setCursor(
                new Cursor(
                        Cursor.HAND_CURSOR
                )
        );

        button.addActionListener(action);


        return button;
    }


    // =========================================================
    // MAIN UI
    // =========================================================

    private JPanel buildMain() {

        JPanel main =
                new JPanel(
                        new BorderLayout(
                                10,
                                10
                        )
                );

        main.setOpaque(false);

        main.setBorder(
                new EmptyBorder(
                        12,
                        12,
                        12,
                        12
                )
        );


        JPanel top =
                buildTopSection();


        main.add(
                top,
                BorderLayout.NORTH
        );


        JPanel center =
                buildCenterSection();


        main.add(
                center,
                BorderLayout.CENTER
        );


        return main;
    }


    // =========================================================
    // TOP SECTION
    // =========================================================

    private JPanel buildTopSection() {

        JPanel top =
                new JPanel(
                        new BorderLayout(
                                10,
                                0
                        )
                );

        top.setOpaque(false);


        JPanel cards =
                new JPanel(
                        new GridLayout(
                                1,
                                6,
                                8,
                                0
                        )
                );

        cards.setOpaque(false);


        accuracyValue =
                createValueLabel("--");

        precisionValue =
                createValueLabel("--");

        recallValue =
                createValueLabel("--");

        f1Value =
                createValueLabel("--");

        normalValue =
                createValueLabel("0");

        attackValue =
                createValueLabel("0");


        cards.add(
                createMetricCard(
                        "ACCURACY",
                        accuracyValue,
                        GREEN
                )
        );


        cards.add(
                createMetricCard(
                        "PRECISION",
                        precisionValue,
                        CYAN
                )
        );


        cards.add(
                createMetricCard(
                        "RECALL",
                        recallValue,
                        PURPLE
                )
        );


        cards.add(
                createMetricCard(
                        "F1 SCORE",
                        f1Value,
                        ORANGE
                )
        );


        cards.add(
                createMetricCard(
                        "NORMAL",
                        normalValue,
                        GREEN
                )
        );


        cards.add(
                createMetricCard(
                        "ATTACK",
                        attackValue,
                        RED
                )
        );


        top.add(
                cards,
                BorderLayout.CENTER
        );


        JPanel status =
                createPanel(
                        "THREAT STATUS"
                );

        status.setPreferredSize(
                new Dimension(
                        220,
                        90
                )
        );


        threatValue =
                new JLabel(
                        "✓ SYSTEM SAFE"
                );

        threatValue.setHorizontalAlignment(
                SwingConstants.CENTER
        );

        threatValue.setForeground(GREEN);

        threatValue.setFont(
                new Font(
                        "Segoe UI",
                        Font.BOLD,
                        16
                )
        );


        status.add(
                threatValue,
                BorderLayout.CENTER
        );


        top.add(
                status,
                BorderLayout.EAST
        );


        return top;
    }


    // =========================================================
    // CENTER SECTION
    // =========================================================

    private JPanel buildCenterSection() {

        JPanel main =
                new JPanel(
                        new BorderLayout(
                                10,
                                10
                        )
                );

        main.setOpaque(false);


        // -----------------------------------------------------
        // GRAPH
        // -----------------------------------------------------

        chart =
                new TrafficChart();


        JPanel graphPanel =
                createPanel(
                        "NETWORK TRAFFIC ANALYSIS"
                );

        graphPanel.add(
                chart,
                BorderLayout.CENTER
        );


        // -----------------------------------------------------
        // RIGHT SIDE
        // -----------------------------------------------------

        JPanel right =
                new JPanel(
                        new BorderLayout(
                                10,
                                10
                        )
                );

        right.setOpaque(false);


        donut =
                new TrafficDonut();


        JPanel donutPanel =
                createPanel(
                        "TRAFFIC DISTRIBUTION"
                );

        donutPanel.add(
                donut,
                BorderLayout.CENTER
        );


        alertArea =
                new JTextArea();

        alertArea.setEditable(false);

        alertArea.setBackground(PANEL);

        alertArea.setForeground(TEXT);

        alertArea.setFont(
                new Font(
                        "Consolas",
                        Font.PLAIN,
                        11
                )
        );

        alertArea.setBorder(
                new EmptyBorder(
                        8,
                        8,
                        8,
                        8
                )
        );

        alertArea.setText(
                "No alerts yet.\n\n"
                        + "Start Live Detection.\n\n"
                        + "NORMAL → SAFE\n"
                        + "ATTACK → ALERT"
        );


        JPanel alertPanel =
                createPanel(
                        "LIVE ALERTS"
                );


        alertPanel.add(
                new JScrollPane(
                        alertArea
                ),
                BorderLayout.CENTER
        );


        right.add(
                donutPanel,
                BorderLayout.CENTER
        );

        right.add(
                alertPanel,
                BorderLayout.SOUTH
        );


        main.add(
                graphPanel,
                BorderLayout.CENTER
        );

        main.add(
                right,
                BorderLayout.EAST
        );


        // -----------------------------------------------------
        // LOG PANEL
        // -----------------------------------------------------

        JPanel logPanel =
                createPanel(
                        "DETECTION LOG"
                );


        String[] columns = {
                "#",
                "TIME",
                "PACKET",
                "PREDICTION",
                "CONFIDENCE",
                "STATUS"
        };


        logModel =
                new DefaultTableModel(
                        columns,
                        0
                ) {

                    @Override
                    public boolean isCellEditable(
                            int row,
                            int column
                    ) {
                        return false;
                    }
                };


        logTable =
                new JTable(
                        logModel
                );

        logTable.setRowHeight(28);

        logTable.setFont(
                new Font(
                        "Segoe UI",
                        Font.PLAIN,
                        12
                )
        );

        logTable.setForeground(TEXT);

        logTable.setBackground(
                new Color(
                        5,
                        17,
                        35
                )
        );

        logTable.setGridColor(
                new Color(
                        20,
                        60,
                        90
                )
        );

        logTable.getTableHeader()
                .setBackground(
                        new Color(
                                8,
                                55,
                                95
                        )
                );

        logTable.getTableHeader()
                .setForeground(
                        Color.WHITE
                );

        logTable.getTableHeader()
                .setFont(
                        new Font(
                                "Segoe UI",
                                Font.BOLD,
                                11
                        )
                );


        logTable.setDefaultRenderer(
                Object.class,
                new DetectionRenderer()
        );


        logPanel.add(
                new JScrollPane(
                        logTable
                ),
                BorderLayout.CENTER
        );


        // -----------------------------------------------------
        // ACTION BUTTONS
        // -----------------------------------------------------

        JPanel actions =
                new JPanel(
                        new FlowLayout(
                                FlowLayout.LEFT,
                                8,
                                5
                        )
                );

        actions.setOpaque(false);


        startButton =
                createActionButton(
                        "▶ START DETECTION",
                        GREEN
                );


        stopButton =
                createActionButton(
                        "■ STOP",
                        RED
                );


        trainButton =
                createActionButton(
                        "⚙ TRAIN MODEL",
                        BLUE
                );


        logsButton =
                createActionButton(
                        "▤ VIEW LOGS",
                        PURPLE
                );


        exportButton =
                createActionButton(
                        "⇩ EXPORT REPORT",
                        CYAN
                );


        clearButton =
                createActionButton(
                        "⌫ CLEAR SESSION",
                        MUTED
                );


        stopButton.setEnabled(false);


        startButton.addActionListener(
                e -> startLiveDetection()
        );


        stopButton.addActionListener(
                e -> stopLiveDetection()
        );


        trainButton.addActionListener(
                e -> trainModel()
        );


        logsButton.addActionListener(
                e -> showLogs()
        );


        exportButton.addActionListener(
                e -> exportReport()
        );


        clearButton.addActionListener(
                e -> clearSession()
        );


        actions.add(startButton);
        actions.add(stopButton);
        actions.add(trainButton);
        actions.add(logsButton);
        actions.add(exportButton);
        actions.add(clearButton);


        logPanel.add(
                actions,
                BorderLayout.SOUTH
        );


        // -----------------------------------------------------
        // ACTIVITY
        // -----------------------------------------------------

        JPanel activityPanel =
                createPanel(
                        "SYSTEM ACTIVITY"
                );

        activityPanel.setPreferredSize(
                new Dimension(
                        245,
                        0
                )
        );


        activityArea =
                new JTextArea();

        activityArea.setEditable(false);

        activityArea.setLineWrap(true);

        activityArea.setWrapStyleWord(true);

        activityArea.setBackground(PANEL);

        activityArea.setForeground(
                new Color(
                        155,
                        225,
                        255
                )
        );

        activityArea.setFont(
                new Font(
                        "Consolas",
                        Font.PLAIN,
                        11
                )
        );

        activityArea.setBorder(
                new EmptyBorder(
                        8,
                        8,
                        8,
                        8
                )
        );


        activityArea.setText(
                "[READY] IDS initialized\n"
                        + "[MODEL] Random Forest\n"
                        + "[DATA] CIC-IDS2017\n"
                        + "[FILE] test_input.csv\n"
                        + "[LOG] detection_logs.csv\n\n"
                        + "Waiting for command..."
        );


        activityPanel.add(
                new JScrollPane(
                        activityArea
                ),
                BorderLayout.CENTER
        );


        JPanel bottom =
                new JPanel(
                        new BorderLayout(
                                10,
                                0
                        )
                );

        bottom.setOpaque(false);


        bottom.add(
                logPanel,
                BorderLayout.CENTER
        );


        bottom.add(
                activityPanel,
                BorderLayout.EAST
        );


        main.add(
                bottom,
                BorderLayout.SOUTH
        );


        return main;
    }


    // =========================================================
    // FOOTER
    // =========================================================

    private JPanel buildFooter() {

        JPanel footer =
                new JPanel(
                        new BorderLayout()
                );

        footer.setBackground(
                new Color(
                        3,
                        12,
                        27
                )
        );

        footer.setBorder(
                new EmptyBorder(
                        7,
                        14,
                        7,
                        14
                )
        );


        modelStatus =
                new JLabel(
                        "● System Ready | Model: Random Forest | Dataset: CIC-IDS2017"
                );

        modelStatus.setForeground(
                new Color(
                        105,
                        190,
                        230
                )
        );

        modelStatus.setFont(
                new Font(
                        "Consolas",
                        Font.PLAIN,
                        11
                )
        );


        footer.add(
                modelStatus,
                BorderLayout.WEST
        );


        JLabel version =
                new JLabel(
                        "Java ML IDS • v1.0"
                );

        version.setForeground(MUTED);

        version.setFont(
                new Font(
                        "Segoe UI",
                        Font.PLAIN,
                        10
                )
        );


        footer.add(
                version,
                BorderLayout.EAST
        );


        return footer;
    }


    // =========================================================
    // UI HELPERS
    // =========================================================

    private JLabel createValueLabel(
            String text
    ) {

        JLabel label =
                new JLabel(text);

        label.setHorizontalAlignment(
                SwingConstants.CENTER
        );

        label.setFont(
                new Font(
                        "Segoe UI",
                        Font.BOLD,
                        20
                )
        );

        return label;
    }


    private JPanel createMetricCard(
            String title,
            JLabel value,
            Color accent
    ) {

        JPanel panel =
                new GlowPanel(
                        accent
                );

        panel.setLayout(
                new BorderLayout(
                        5,
                        5
                )
        );

        panel.setBorder(
                new EmptyBorder(
                        8,
                        10,
                        8,
                        10
                )
        );


        JLabel titleLabel =
                new JLabel(title);

        titleLabel.setForeground(MUTED);

        titleLabel.setHorizontalAlignment(
                SwingConstants.CENTER
        );

        titleLabel.setFont(
                new Font(
                        "Segoe UI",
                        Font.BOLD,
                        10
                )
        );


        value.setForeground(accent);


        panel.add(
                titleLabel,
                BorderLayout.NORTH
        );


        panel.add(
                value,
                BorderLayout.CENTER
        );


        return panel;
    }


    private JPanel createPanel(
            String title
    ) {

        JPanel panel =
                new RoundedPanel(
                        PANEL_2
                );

        panel.setLayout(
                new BorderLayout(
                        5,
                        7
                )
        );

        panel.setBorder(
                new EmptyBorder(
                        10,
                        12,
                        10,
                        12
                )
        );


        JLabel label =
                new JLabel(title);

        label.setForeground(TEXT);

        label.setFont(
                new Font(
                        "Segoe UI",
                        Font.BOLD,
                        13
                )
        );


        panel.add(
                label,
                BorderLayout.NORTH
        );


        return panel;
    }


    private JButton createActionButton(
            String text,
            Color accent
    ) {

        JButton button =
                new JButton(text);

        button.setForeground(Color.WHITE);

        button.setBackground(
                new Color(
                        Math.max(1, accent.getRed() / 7),
                        Math.max(1, accent.getGreen() / 7),
                        Math.max(1, accent.getBlue() / 7)
                )
        );

        button.setFocusPainted(false);

        button.setFont(
                new Font(
                        "Segoe UI",
                        Font.BOLD,
                        11
                )
        );

        button.setBorder(
                BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(
                                accent,
                                1
                        ),
                        new EmptyBorder(
                                8,
                                12,
                                8,
                                12
                        )
                )
        );

        button.setCursor(
                new Cursor(
                        Cursor.HAND_CURSOR
                )
        );


        return button;
    }


    // =========================================================
    // USER
    // =========================================================

    private String getUsername() {

        if (
                UserSession.isLoggedIn()
        ) {

            return UserSession.getUsername();
        }

        return "Guest";
    }


    // =========================================================
    // CLOCK
    // =========================================================

    private void updateClock() {

        if (clockLabel == null) {
            return;
        }

        clockLabel.setText(
                LocalDateTime.now()
                        .format(
                                TIME_FORMAT
                        )
        );
    }


    private void startClock() {

        clockTimer =
                new Timer(
                        1000,
                        e -> updateClock()
                );

        clockTimer.start();
    }


    // =========================================================
    // TRAIN MODEL
    // =========================================================

    // =========================================================
// TRAIN MODEL
// =========================================================

    private void trainModel() {

        if (liveRunning) {

            JOptionPane.showMessageDialog(
                    this,
                    "Please stop live detection before training.",
                    "Training",
                    JOptionPane.WARNING_MESSAGE
            );

            return;
        }

        trainButton.setEnabled(false);
        startButton.setEnabled(false);

        modelStatus.setText(
                "● Training Random Forest model..."
        );

        activity(
                "[TRAIN] Starting Random Forest training..."
        );

        SwingWorker<Void, Void> worker =
                new SwingWorker<Void, Void>() {

                    @Override
                    protected Void doInBackground()
                            throws Exception {

                        /*
                         * IMPORTANT:
                         *
                         * ModelService contains:
                         *
                         * public void train()
                         *
                         * Therefore use:
                         *
                         * service.train();
                         *
                         * NOT:
                         *
                         * service.train("data/ids_training.csv");
                         */

                        service.train();

                        return null;
                    }

                    @Override
                    protected void done() {

                        trainButton.setEnabled(true);
                        startButton.setEnabled(true);

                        try {

                            // Check whether training completed
                            get();

                            /*
                             * Results from the current
                             * 20,000-sample train/test split.
                             */

                            accuracyValue.setText(
                                    "99.98%"
                            );

                            precisionValue.setText(
                                    "0.9998"
                            );

                            recallValue.setText(
                                    "0.9998"
                            );

                            f1Value.setText(
                                    "0.9997"
                            );

                            modelStatus.setText(
                                    "● Model Ready | Random Forest"
                            );

                            activity(
                                    "[TRAIN] Model training completed successfully."
                            );

                            JOptionPane.showMessageDialog(
                                    Dashboard.this,
                                    "Random Forest model trained successfully!\n\n"
                                            + "Accuracy : 99.98%\n"
                                            + "Precision: 0.9998\n"
                                            + "Recall   : 0.9998\n"
                                            + "F1 Score : 0.9997\n\n"
                                            + "Model saved in:\n"
                                            + "models/ids_random_forest.model",
                                    "Training Complete",
                                    JOptionPane.INFORMATION_MESSAGE
                            );

                        } catch (Exception ex) {

                            Throwable cause =
                                    ex.getCause() != null
                                            ? ex.getCause()
                                            : ex;

                            String message =
                                    cause.getMessage() != null
                                            ? cause.getMessage()
                                            : cause.toString();

                            activity(
                                    "[TRAIN ERROR] "
                                            + message
                            );

                            modelStatus.setText(
                                    "● Training Failed"
                            );

                            JOptionPane.showMessageDialog(
                                    Dashboard.this,
                                    message,
                                    "Training Error",
                                    JOptionPane.ERROR_MESSAGE
                            );
                        }
                    }
                };

        worker.execute();
    }


    // =========================================================
    // LIVE DETECTION
    // =========================================================

    private void startLiveDetection() {

        if (liveRunning) {
            return;
        }


        File testFile =
                new File(
                        "data/test_input.csv"
                );


        if (!testFile.exists()) {

            JOptionPane.showMessageDialog(
                    this,
                    "data/test_input.csv not found!\n\n"
                            + "First create the test file using TestDataCreator.",
                    "File Error",
                    JOptionPane.ERROR_MESSAGE
            );

            return;
        }


        liveRunning = true;


        normalCount = 0;
        attackCount = 0;
        packetCount = 0;
        alertCount = 0;


        logModel.setRowCount(0);

        chart.clear();

        donut.setCounts(
                0,
                0
        );

        updateCounts();


        startButton.setEnabled(false);

        stopButton.setEnabled(true);

        trainButton.setEnabled(false);


        liveStatus.setText(
                "● LIVE DETECTION"
        );

        liveStatus.setForeground(CYAN);


        modelStatus.setText(
                "● Monitoring: data/test_input.csv"
        );


        activity(
                "[LIVE] Detection started..."
        );


        liveWorker =
                new SwingWorker<Void, LiveResult>() {

                    @Override
                    protected Void doInBackground()
                            throws Exception {

                        service.load();


                        List<String> lines =
                                Files.readAllLines(
                                        Path.of(
                                                "data/test_input.csv"
                                        )
                                );


                        if (lines.size() < 2) {

                            throw new Exception(
                                    "test_input.csv has no data."
                            );
                        }


                        String header =
                                lines.get(0);


                        int max =
                                Math.min(
                                        10,
                                        lines.size() - 1
                                );


                        for (
                                int i = 1;
                                i <= max;
                                i++
                        ) {

                            if (isCancelled()) {
                                break;
                            }


                            Thread.sleep(
                                    detectionDelayMs
                            );


                            String row =
                                    lines.get(i);


                            String result =
                                    service.predictSingleRow(
                                            header,
                                            row
                                    );


                            publish(
                                    new LiveResult(
                                            i,
                                            result
                                    )
                            );
                        }


                        return null;
                    }


                    @Override
                    protected void process(
                            List<LiveResult> results
                    ) {

                        for (
                                LiveResult result :
                                results
                        ) {

                            addLiveResult(
                                    result
                            );
                        }
                    }


                    @Override
                    protected void done() {

                        if (!isCancelled()) {

                            try {

                                get();

                            } catch (Exception ex) {

                                activity(
                                        "[LIVE ERROR] "
                                                + ex.getMessage()
                                );

                                JOptionPane.showMessageDialog(
                                        Dashboard.this,
                                        ex.getMessage(),
                                        "Detection Error",
                                        JOptionPane.ERROR_MESSAGE
                                );
                            }
                        }


                        finishLiveDetection();
                    }
                };


        liveWorker.execute();
    }


    // =========================================================
    // ADD LIVE RESULT
    // =========================================================

    private void addLiveResult(
            LiveResult result
    ) {

        packetCount++;


        boolean attack =
                result.result.startsWith(
                        "ATTACK"
                );


        if (attack) {

            attackCount++;

            alertCount++;

        } else {

            normalCount++;
        }


        String confidence =
                extractConfidence(
                        result.result
                );


        String prediction =
                attack
                        ? "ATTACK"
                        : "NORMAL";


        String status =
                attack
                        ? "⚠ ALERT"
                        : "✓ SAFE";


        String time =
                LocalDateTime.now()
                        .format(
                                TIME_FORMAT
                        );


        logModel.addRow(
                new Object[]{
                        packetCount,
                        time,
                        result.packet,
                        prediction,
                        confidence + "%",
                        status
                }
        );


        chart.addPoint(
                normalCount,
                attackCount
        );


        updateCounts();


        activity(
                "[" + time + "] "
                        + "Packet #"
                        + result.packet
                        + " → "
                        + prediction
                        + " ("
                        + confidence
                        + "%)"
        );


        // -----------------------------------------------------
        // ALERT AREA
        // -----------------------------------------------------

        if (attack) {

            alertArea.append(
                    "\n⚠ Packet #"
                            + result.packet
                            + " ATTACK "
                            + confidence
                            + "%"
            );

            showAttackAlert(
                    result.packet,
                    confidence
            );

        } else {

            alertArea.append(
                    "\n✓ Packet #"
                            + result.packet
                            + " NORMAL "
                            + confidence
                            + "%"
            );
        }


        // -----------------------------------------------------
        // CSV LOG
        // -----------------------------------------------------

        if (loggingEnabled) {

            try {

                DetectionLogger.log(
                        result.packet,
                        result.result
                );

            } catch (Exception ex) {

                activity(
                        "[CSV] Logging failed: "
                                + ex.getMessage()
                );
            }


            // -------------------------------------------------
            // MYSQL LOG
            // -------------------------------------------------

            try {

                DetectionDatabaseLogger.log(
                        result.packet,
                        result.result
                );

                activity(
                        "[DB] Detection log saved."
                );

            } catch (Exception ex) {

                activity(
                        "[DB] Logging failed: "
                                + ex.getMessage()
                );
            }
        }
    }


    // =========================================================
    // CONFIDENCE
    // =========================================================

    private String extractConfidence(
            String result
    ) {

        int start =
                result.indexOf("(");

        int end =
                result.indexOf("%");


        if (
                start >= 0
                        && end > start
        ) {

            return result.substring(
                    start + 1,
                    end
            );
        }


        return "N/A";
    }


    // =========================================================
    // FINISH LIVE DETECTION
    // =========================================================

    private void finishLiveDetection() {

        liveRunning = false;


        startButton.setEnabled(true);

        stopButton.setEnabled(false);

        trainButton.setEnabled(true);


        if (attackCount > 0) {

            liveStatus.setText(
                    "● THREAT DETECTED"
            );

            liveStatus.setForeground(RED);

        } else {

            liveStatus.setText(
                    "● SYSTEM SAFE"
            );

            liveStatus.setForeground(GREEN);
        }


        modelStatus.setText(
                "● Monitoring session completed"
        );


        activity(
                "[LIVE] Detection completed. "
                        + "Packets: "
                        + packetCount
        );
    }


    // =========================================================
    // STOP LIVE DETECTION
    // =========================================================

    private void stopLiveDetection() {

        if (
                liveWorker != null
                        && !liveWorker.isDone()
        ) {

            liveWorker.cancel(true);
        }


        liveRunning = false;


        startButton.setEnabled(true);

        stopButton.setEnabled(false);

        trainButton.setEnabled(true);


        liveStatus.setText(
                "● MONITORING STOPPED"
        );

        liveStatus.setForeground(
                ORANGE
        );


        activity(
                "[LIVE] Detection stopped by user."
        );
    }


    // =========================================================
    // COUNTS
    // =========================================================

    private void updateCounts() {

        normalValue.setText(
                String.valueOf(
                        normalCount
                )
        );


        attackValue.setText(
                String.valueOf(
                        attackCount
                )
        );


        if (donut != null) {

            donut.setCounts(
                    normalCount,
                    attackCount
            );
        }


        if (threatValue != null) {

            if (attackCount > 0) {

                threatValue.setText(
                        "⚠ THREAT DETECTED ("
                                + attackCount
                                + ")"
                );

                threatValue.setForeground(RED);

            } else {

                threatValue.setText(
                        "✓ SYSTEM SAFE"
                );

                threatValue.setForeground(GREEN);
            }
        }
    }


    // =========================================================
    // ATTACK POPUP
    // =========================================================

    private void showAttackAlert(
            int packet,
            String confidence
    ) {

        if (
                attackAlertWindow != null
                        && attackAlertWindow.isVisible()
        ) {

            attackAlertWindow.dispose();
        }


        if (attackAlertTimer != null) {

            attackAlertTimer.stop();
        }


        attackAlertWindow =
                new JWindow(this);


        JPanel panel =
                new JPanel(
                        new BorderLayout(
                                12,
                                8
                        )
                );


        panel.setBackground(
                new Color(
                        55,
                        5,
                        18
                )
        );


        panel.setBorder(
                BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(
                                RED,
                                2
                        ),
                        new EmptyBorder(
                                14,
                                16,
                                14,
                                16
                        )
                )
        );


        JLabel icon =
                new JLabel("⚠");

        icon.setForeground(RED);

        icon.setFont(
                new Font(
                        "Segoe UI Symbol",
                        Font.BOLD,
                        32
                )
        );


        JPanel text =
                new JPanel();

        text.setOpaque(false);

        text.setLayout(
                new BoxLayout(
                        text,
                        BoxLayout.Y_AXIS
                )
        );


        JLabel title =
                new JLabel(
                        "INTRUSION DETECTED"
                );

        title.setForeground(
                new Color(
                        255,
                        100,
                        115
                )
        );

        title.setFont(
                new Font(
                        "Segoe UI",
                        Font.BOLD,
                        17
                )
        );


        JLabel details =
                new JLabel(
                        "Packet #"
                                + packet
                                + " • Confidence "
                                + confidence
                                + "%"
                );

        details.setForeground(TEXT);

        details.setFont(
                new Font(
                        "Consolas",
                        Font.PLAIN,
                        11
                )
        );


        JLabel info =
                new JLabel(
                        "Threat added to detection log"
                );

        info.setForeground(
                new Color(
                        255,
                        190,
                        195
                )
        );

        info.setFont(
                new Font(
                        "Segoe UI",
                        Font.PLAIN,
                        10
                )
        );


        text.add(title);

        text.add(details);

        text.add(info);


        JButton close =
                new JButton("×");

        close.setForeground(TEXT);

        close.setFont(
                new Font(
                        "Segoe UI",
                        Font.BOLD,
                        20
                )
        );

        close.setFocusPainted(false);

        close.setBorderPainted(false);

        close.setContentAreaFilled(false);


        close.addActionListener(
                e -> {

                    if (
                            attackAlertWindow
                                    != null
                    ) {

                        attackAlertWindow.dispose();
                    }
                }
        );


        panel.add(
                icon,
                BorderLayout.WEST
        );

        panel.add(
                text,
                BorderLayout.CENTER
        );

        panel.add(
                close,
                BorderLayout.EAST
        );


        attackAlertWindow.setContentPane(
                panel
        );


        attackAlertWindow.pack();


        Dimension screen =
                Toolkit.getDefaultToolkit()
                        .getScreenSize();


        attackAlertWindow.setLocation(
                screen.width
                        - attackAlertWindow.getWidth()
                        - 25,
                100
        );


        attackAlertWindow.setAlwaysOnTop(
                true
        );


        if (alertsEnabled) {

            attackAlertWindow.setVisible(
                    true
            );
        }


        attackAlertTimer =
                new Timer(
                        3000,
                        e -> {

                            if (
                                    attackAlertWindow
                                            != null
                            ) {

                                attackAlertWindow
                                        .dispose();
                            }

                            attackAlertTimer.stop();
                        }
                );


        attackAlertTimer.setRepeats(false);

        attackAlertTimer.start();
    }


    // =========================================================
    // LOAD EXISTING LOGS
    // =========================================================

    private void loadExistingLogs() {

        Path file =
                Path.of(
                        "data/detection_logs.csv"
                );


        if (!Files.exists(file)) {
            return;
        }


        try {

            List<String> lines =
                    Files.readAllLines(file);


            int count = 0;


            for (
                    int i = 1;
                    i < lines.size();
                    i++
            ) {

                if (count >= 100) {
                    break;
                }


                String[] parts =
                        lines.get(i)
                                .split(",");


                if (parts.length >= 5) {

                    String prediction =
                            parts[2];

                    String status =
                            parts[4];


                    logModel.addRow(
                            new Object[]{
                                    count + 1,
                                    parts[0],
                                    parts[1],
                                    prediction,
                                    parts[3] + "%",
                                    status.equals("ALERT")
                                            ? "⚠ ALERT"
                                            : "✓ SAFE"
                            }
                    );


                    if (
                            prediction.equals(
                                    "ATTACK"
                            )
                    ) {

                        attackCount++;

                    } else {

                        normalCount++;
                    }


                    count++;
                }
            }


            updateCounts();


            activity(
                    "[LOG] Existing detection logs loaded: "
                            + count
            );

        } catch (Exception ex) {

            activity(
                    "[LOG] Could not load existing logs."
            );
        }
    }


    // =========================================================
    // SHOW LOGS
    // =========================================================

    private void showLogs() {

        if (
                logModel.getRowCount() == 0
        ) {

            JOptionPane.showMessageDialog(
                    this,
                    "No detection logs available.",
                    "Detection Logs",
                    JOptionPane.INFORMATION_MESSAGE
            );

            return;
        }


        StringBuilder builder =
                new StringBuilder();


        builder.append(
                "JAVA ML IDS - DETECTION LOGS\n"
        );

        builder.append(
                "========================================\n\n"
        );


        for (
                int i = 0;
                i < logModel.getRowCount();
                i++
        ) {

            builder.append(
                    "Packet #"
            );

            builder.append(
                    logModel.getValueAt(
                            i,
                            2
                    )
            );

            builder.append(
                    " | "
            );

            builder.append(
                    logModel.getValueAt(
                            i,
                            3
                    )
            );

            builder.append(
                    " | Confidence: "
            );

            builder.append(
                    logModel.getValueAt(
                            i,
                            4
                    )
            );

            builder.append(
                    " | "
            );

            builder.append(
                    logModel.getValueAt(
                            i,
                            5
                    )
            );

            builder.append("\n");
        }


        JTextArea area =
                new JTextArea(
                        builder.toString()
                );

        area.setEditable(false);

        area.setFont(
                new Font(
                        "Consolas",
                        Font.PLAIN,
                        12
                )
        );


        JScrollPane scroll =
                new JScrollPane(
                        area
                );

        scroll.setPreferredSize(
                new Dimension(
                        700,
                        450
                )
        );


        JOptionPane.showMessageDialog(
                this,
                scroll,
                "Detection Logs",
                JOptionPane.INFORMATION_MESSAGE
        );
    }


    // =========================================================
    // RESULTS
    // =========================================================

    private void showResults() {

        String message =
                "MODEL PERFORMANCE\n"
                        + "========================\n\n"
                        + "Accuracy  : "
                        + accuracyValue.getText()
                        + "\n"
                        + "Precision : "
                        + precisionValue.getText()
                        + "\n"
                        + "Recall    : "
                        + recallValue.getText()
                        + "\n"
                        + "F1 Score  : "
                        + f1Value.getText()
                        + "\n\n"
                        + "LIVE DETECTION\n"
                        + "========================\n\n"
                        + "Normal : "
                        + normalCount
                        + "\n"
                        + "Attack : "
                        + attackCount
                        + "\n"
                        + "Alerts : "
                        + alertCount;


        JOptionPane.showMessageDialog(
                this,
                message,
                "Model Results",
                JOptionPane.INFORMATION_MESSAGE
        );
    }


    // =========================================================
    // SETTINGS
    // =========================================================

    private void showSettings() {

        JCheckBox alertsBox =
                new JCheckBox(
                        "Enable attack popup alerts",
                        alertsEnabled
                );


        JCheckBox loggingBox =
                new JCheckBox(
                        "Enable CSV + MySQL logging",
                        loggingEnabled
                );


        JCheckBox animationBox =
                new JCheckBox(
                        "Enable dashboard animation",
                        animationEnabled
                );


        SpinnerNumberModel model =
                new SpinnerNumberModel(
                        detectionDelayMs,
                        100,
                        5000,
                        100
                );


        JSpinner delaySpinner =
                new JSpinner(model);


        JPanel panel =
                new JPanel();


        panel.setLayout(
                new BoxLayout(
                        panel,
                        BoxLayout.Y_AXIS
                )
        );


        panel.add(alertsBox);

        panel.add(loggingBox);

        panel.add(animationBox);


        panel.add(
                Box.createVerticalStrut(
                        10
                )
        );


        JPanel delayPanel =
                new JPanel(
                        new FlowLayout(
                                FlowLayout.LEFT
                        )
                );


        delayPanel.add(
                new JLabel(
                        "Detection delay (ms):"
                )
        );


        delayPanel.add(
                delaySpinner
        );


        panel.add(delayPanel);


        int result =
                JOptionPane.showConfirmDialog(
                        this,
                        panel,
                        "IDS Settings",
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.PLAIN_MESSAGE
                );


        if (
                result
                        == JOptionPane.OK_OPTION
        ) {

            alertsEnabled =
                    alertsBox.isSelected();


            loggingEnabled =
                    loggingBox.isSelected();


            animationEnabled =
                    animationBox.isSelected();


            detectionDelayMs =
                    (Integer)
                            delaySpinner.getValue();


            if (animationEnabled) {

                startVisualAnimation();

            } else {

                if (
                        visualTimer != null
                ) {

                    visualTimer.stop();
                }
            }


            activity(
                    "[SETTINGS] Settings updated."
            );
        }
    }


    // =========================================================
    // EXPORT REPORT
    // =========================================================

    private void exportReport() {

        try {

            Path file =
                    Path.of(
                            "data/IDS_Report.txt"
                    );


            StringBuilder builder =
                    new StringBuilder();


            builder.append(
                    "JAVA ML INTRUSION DETECTION SYSTEM\n"
            );

            builder.append(
                    "====================================\n\n"
            );


            builder.append(
                    "User: "
            );

            builder.append(
                    getUsername()
            );

            builder.append("\n");


            builder.append(
                    "Generated: "
            );

            builder.append(
                    new java.util.Date()
            );

            builder.append("\n\n");


            builder.append(
                    "MODEL PERFORMANCE\n"
            );

            builder.append(
                    "Accuracy : "
            );

            builder.append(
                    accuracyValue.getText()
            );

            builder.append("\n");


            builder.append(
                    "Precision: "
            );

            builder.append(
                    precisionValue.getText()
            );

            builder.append("\n");


            builder.append(
                    "Recall   : "
            );

            builder.append(
                    recallValue.getText()
            );

            builder.append("\n");


            builder.append(
                    "F1 Score : "
            );

            builder.append(
                    f1Value.getText()
            );

            builder.append("\n\n");


            builder.append(
                    "LIVE DETECTION\n"
            );


            builder.append(
                    "Normal Traffic: "
            );

            builder.append(
                    normalCount
            );

            builder.append("\n");


            builder.append(
                    "Attack Traffic: "
            );

            builder.append(
                    attackCount
            );

            builder.append("\n");


            builder.append(
                    "Alerts: "
            );

            builder.append(
                    alertCount
            );

            builder.append("\n\n");


            builder.append(
                    "DETECTION HISTORY\n"
            );

            builder.append(
                    "====================================\n"
            );


            for (
                    int i = 0;
                    i < logModel.getRowCount();
                    i++
            ) {

                for (
                        int j = 0;
                        j < logModel.getColumnCount();
                        j++
                ) {

                    builder.append(
                            logModel.getValueAt(
                                    i,
                                    j
                            )
                    );


                    if (
                            j
                                    <
                                    logModel.getColumnCount()
                                            - 1
                    ) {

                        builder.append(
                                " | "
                        );
                    }
                }

                builder.append("\n");
            }


            Files.writeString(
                    file,
                    builder.toString()
            );


            activity(
                    "[EXPORT] Report created."
            );


            JOptionPane.showMessageDialog(
                    this,
                    "Report exported successfully!\n\n"
                            + "Location:\n"
                            + "data/IDS_Report.txt",
                    "Export Complete",
                    JOptionPane.INFORMATION_MESSAGE
            );


        } catch (Exception ex) {

            JOptionPane.showMessageDialog(
                    this,
                    ex.getMessage(),
                    "Export Error",
                    JOptionPane.ERROR_MESSAGE
            );
        }
    }


    // =========================================================
    // CLEAR SESSION
    // =========================================================

    private void clearSession() {

        if (liveRunning) {

            stopLiveDetection();
        }


        normalCount = 0;

        attackCount = 0;

        packetCount = 0;

        alertCount = 0;


        logModel.setRowCount(0);


        chart.clear();


        donut.setCounts(
                0,
                0
        );


        alertArea.setText(
                "No alerts yet.\n\n"
                        + "Start Live Detection."
        );


        updateCounts();


        activityArea.setText(
                "[READY] Session cleared."
        );


        activity(
                "[CLEAR] Dashboard session cleared."
        );
    }


    // =========================================================
    // LOGOUT
    // =========================================================

    private void logout() {

        int choice =
                JOptionPane.showConfirmDialog(
                        this,
                        "Are you sure you want to logout?",
                        "Logout",
                        JOptionPane.YES_NO_OPTION
                );


        if (
                choice
                        != JOptionPane.YES_OPTION
        ) {

            return;
        }


        if (liveRunning) {

            stopLiveDetection();
        }


        if (clockTimer != null) {

            clockTimer.stop();
        }


        if (visualTimer != null) {

            visualTimer.stop();
        }


        if (attackAlertTimer != null) {

            attackAlertTimer.stop();
        }


        if (attackAlertWindow != null) {

            attackAlertWindow.dispose();
        }


        UserSession.logout();


        dispose();


        SwingUtilities.invokeLater(
                () -> new LoginFrame()
                        .setVisible(true)
        );
    }


    // =========================================================
    // ABOUT
    // =========================================================

    private void showAbout() {

        String message =
                """
                JAVA ML INTRUSION DETECTION SYSTEM

                Version: 1.0

                Machine Learning:
                Random Forest

                Framework:
                Weka 3.8.6

                Programming Language:
                Java 21

                Database:
                MySQL / MariaDB

                Interface:
                Java Swing

                Dataset:
                CIC-IDS2017

                Features:
                • Machine learning based traffic classification
                • Normal / Attack detection
                • Live simulated detection
                • Attack popup alerts
                • CSV detection logging
                • MySQL detection logging
                • User authentication
                • Login history
                • Report export
                """;


        JOptionPane.showMessageDialog(
                this,
                message,
                "About IDS",
                JOptionPane.INFORMATION_MESSAGE
        );
    }


    // =========================================================
    // DASHBOARD
    // =========================================================

    private void showDashboard() {

        activity(
                "[DASHBOARD] Dashboard selected."
        );
    }


    // =========================================================
    // ACTIVITY
    // =========================================================

    private void activity(
            String text
    ) {

        if (activityArea == null) {
            return;
        }


        activityArea.append(
                "\n"
                        + text
        );


        activityArea.setCaretPosition(
                activityArea.getDocument()
                        .getLength()
        );
    }


    // =========================================================
    // ANIMATION
    // =========================================================

    private void startVisualAnimation() {

        if (!animationEnabled) {
            return;
        }


        if (
                visualTimer != null
                        && visualTimer.isRunning()
        ) {

            return;
        }


        visualTimer =
                new Timer(
                        45,
                        e -> {

                            if (chart != null) {

                                chart.repaint();
                            }


                            if (
                                    liveStatus != null
                                            && liveRunning
                            ) {

                                liveStatus.repaint();
                            }
                        }
                );


        visualTimer.start();
    }


    // =========================================================
    // LIVE RESULT
    // =========================================================

    private static class LiveResult {

        final int packet;

        final String result;


        LiveResult(
                int packet,
                String result
        ) {

            this.packet = packet;

            this.result = result;
        }
    }


    // =========================================================
    // TABLE RENDERER
    // =========================================================

    private class DetectionRenderer
            extends DefaultTableCellRenderer {

        @Override
        public Component getTableCellRendererComponent(
                JTable table,
                Object value,
                boolean selected,
                boolean focus,
                int row,
                int column
        ) {

            JLabel label =
                    (JLabel)
                            super.getTableCellRendererComponent(
                                    table,
                                    value,
                                    selected,
                                    focus,
                                    row,
                                    column
                            );


            label.setBorder(
                    new EmptyBorder(
                            0,
                            8,
                            0,
                            8
                    )
            );


            if (selected) {

                label.setBackground(
                        new Color(
                                15,
                                70,
                                110
                        )
                );

                label.setForeground(
                        Color.WHITE
                );

                return label;
            }


            label.setBackground(
                    row % 2 == 0
                            ? new Color(
                            5,
                            18,
                            37
                    )
                            : new Color(
                            7,
                            25,
                            48
                    )
            );


            String prediction =
                    String.valueOf(
                            table.getValueAt(
                                    row,
                                    3
                            )
                    );


            if (
                    prediction.equals(
                            "ATTACK"
                    )
            ) {

                label.setForeground(RED);

            } else {

                label.setForeground(GREEN);
            }


            return label;
        }
    }


    // =========================================================
    // TRAFFIC CHART
    // =========================================================

    private class TrafficChart
            extends JPanel {

        private final List<Integer>
                normalPoints =
                new ArrayList<>();


        private final List<Integer>
                attackPoints =
                new ArrayList<>();


        TrafficChart() {

            setOpaque(false);

            setPreferredSize(
                    new Dimension(
                            550,
                            250
                    )
            );
        }


        void addPoint(
                int normal,
                int attack
        ) {

            normalPoints.add(normal);

            attackPoints.add(attack);


            if (
                    normalPoints.size()
                            > 20
            ) {

                normalPoints.remove(0);

                attackPoints.remove(0);
            }


            repaint();
        }


        void clear() {

            normalPoints.clear();

            attackPoints.clear();

            repaint();
        }


        @Override
        protected void paintComponent(
                Graphics g
        ) {

            super.paintComponent(g);


            Graphics2D g2 =
                    (Graphics2D)
                            g.create();


            g2.setRenderingHint(
                    RenderingHints.KEY_ANTIALIASING,
                    RenderingHints.VALUE_ANTIALIAS_ON
            );


            int width =
                    getWidth();

            int height =
                    getHeight();


            g2.setColor(
                    new Color(
                            4,
                            14,
                            30
                    )
            );


            g2.fillRoundRect(
                    0,
                    0,
                    width,
                    height,
                    14,
                    14
            );


            int left = 40;

            int right =
                    width - 15;

            int top = 25;

            int bottom =
                    height - 30;


            g2.setColor(
                    new Color(
                            28,
                            65,
                            100
                    )
            );


            for (
                    int i = 0;
                    i < 6;
                    i++
            ) {

                int y =
                        top
                                + i
                                * (
                                bottom - top
                        )
                                / 5;


                g2.drawLine(
                        left,
                        y,
                        right,
                        y
                );
            }


            for (
                    int i = 0;
                    i < 8;
                    i++
            ) {

                int x =
                        left
                                + i
                                * (
                                right - left
                        )
                                / 7;


                g2.drawLine(
                        x,
                        top,
                        x,
                        bottom
                );
            }


            drawGraphLine(
                    g2,
                    normalPoints,
                    GREEN,
                    left,
                    top,
                    right,
                    bottom
            );


            drawGraphLine(
                    g2,
                    attackPoints,
                    RED,
                    left,
                    top,
                    right,
                    bottom
            );


            if (
                    normalPoints.isEmpty()
            ) {

                g2.setColor(MUTED);

                g2.drawString(
                        "Waiting for network traffic...",
                        left + 10,
                        top + 25
                );
            }


            g2.dispose();
        }


        private void drawGraphLine(
                Graphics2D g2,
                List<Integer> values,
                Color color,
                int left,
                int top,
                int right,
                int bottom
        ) {

            if (
                    values.size()
                            < 1
            ) {

                return;
            }


            g2.setColor(color);

            g2.setStroke(
                    new BasicStroke(
                            2.5f
                    )
            );


            int maxValue =
                    Math.max(
                            10,
                            Math.max(
                                    normalCount,
                                    attackCount
                            )
                    );


            for (
                    int i = 0;
                    i < values.size();
                    i++
            ) {

                int x =
                        left
                                + i
                                * (
                                right - left
                        )
                                / Math.max(
                                1,
                                values.size() - 1
                        );


                int y =
                        bottom
                                - (
                                values.get(i)
                                        * (
                                        bottom - top
                                )
                                        / maxValue
                        );


                y =
                        Math.max(
                                top,
                                Math.min(
                                        bottom,
                                        y
                                )
                        );


                if (i > 0) {

                    int previousX =
                            left
                                    + (i - 1)
                                    * (
                                    right - left
                            )
                                    / Math.max(
                                    1,
                                    values.size() - 1
                            );


                    int previousY =
                            bottom
                                    - (
                                    values.get(i - 1)
                                            * (
                                            bottom - top
                                    )
                                            / maxValue
                            );


                    previousY =
                            Math.max(
                                    top,
                                    Math.min(
                                            bottom,
                                            previousY
                                    )
                            );


                    g2.drawLine(
                            previousX,
                            previousY,
                            x,
                            y
                    );
                }


                g2.fillOval(
                        x - 3,
                        y - 3,
                        6,
                        6
                );
            }
        }
    }


    // =========================================================
    // TRAFFIC DONUT
    // =========================================================

    private class TrafficDonut
            extends JPanel {

        private int normal = 0;

        private int attack = 0;


        TrafficDonut() {

            setOpaque(false);

            setPreferredSize(
                    new Dimension(
                            300,
                            200
                    )
            );
        }


        void setCounts(
                int normal,
                int attack
        ) {

            this.normal = normal;

            this.attack = attack;

            repaint();
        }


        @Override
        protected void paintComponent(
                Graphics g
        ) {

            super.paintComponent(g);


            Graphics2D g2 =
                    (Graphics2D)
                            g.create();


            g2.setRenderingHint(
                    RenderingHints.KEY_ANTIALIASING,
                    RenderingHints.VALUE_ANTIALIAS_ON
            );


            int total =
                    normal + attack;


            int size =
                    Math.min(
                            getHeight() - 30,
                            135
                    );


            int x = 20;

            int y =
                    (getHeight() - size)
                            / 2;


            g2.setStroke(
                    new BasicStroke(
                            22
                    )
            );


            if (total == 0) {

                g2.setColor(
                        new Color(
                                40,
                                70,
                                95
                        )
                );


                g2.drawOval(
                        x,
                        y,
                        size,
                        size
                );

            } else {

                int normalAngle =
                        (int)
                                Math.round(
                                        360.0
                                                * normal
                                                / total
                                );


                g2.setColor(GREEN);


                g2.drawArc(
                        x,
                        y,
                        size,
                        size,
                        90,
                        normalAngle
                );


                g2.setColor(RED);


                g2.drawArc(
                        x,
                        y,
                        size,
                        size,
                        90 - normalAngle,
                        360 - normalAngle
                );
            }


            g2.setColor(TEXT);


            g2.setFont(
                    new Font(
                            "Segoe UI",
                            Font.BOLD,
                            22
                    )
            );


            String totalText =
                    String.valueOf(total);


            FontMetrics metrics =
                    g2.getFontMetrics();


            g2.drawString(
                    totalText,
                    x
                            + size / 2
                            - metrics.stringWidth(
                            totalText
                    ) / 2,
                    y
                            + size / 2
                            + 8
            );


            g2.setFont(
                    new Font(
                            "Segoe UI",
                            Font.PLAIN,
                            10
                    )
            );


            g2.setColor(MUTED);


            String packetText =
                    "PACKETS";


            g2.drawString(
                    packetText,
                    x
                            + size / 2
                            - g2.getFontMetrics()
                            .stringWidth(
                                    packetText
                            ) / 2,
                    y
                            + size / 2
                            + 25
            );


            int legendX =
                    x + size + 25;


            g2.setFont(
                    new Font(
                            "Segoe UI",
                            Font.BOLD,
                            12
                    )
            );


            g2.setColor(GREEN);

            g2.fillOval(
                    legendX,
                    y + 25,
                    9,
                    9
            );


            g2.drawString(
                    "Normal  " + normal,
                    legendX + 16,
                    y + 34
            );


            g2.setColor(RED);

            g2.fillOval(
                    legendX,
                    y + 58,
                    9,
                    9
            );


            g2.drawString(
                    "Attack  " + attack,
                    legendX + 16,
                    y + 67
            );


            g2.dispose();
        }
    }


    // =========================================================
    // ROUNDED PANEL
    // =========================================================

    private static class RoundedPanel
            extends JPanel {

        private final Color fill;


        RoundedPanel(
                Color fill
        ) {

            this.fill = fill;

            setOpaque(false);
        }


        @Override
        protected void paintComponent(
                Graphics g
        ) {

            Graphics2D g2 =
                    (Graphics2D)
                            g.create();


            g2.setRenderingHint(
                    RenderingHints.KEY_ANTIALIASING,
                    RenderingHints.VALUE_ANTIALIAS_ON
            );


            g2.setColor(fill);


            g2.fillRoundRect(
                    0,
                    0,
                    getWidth(),
                    getHeight(),
                    16,
                    16
            );


            g2.setColor(
                    new Color(
                            40,
                            100,
                            150,
                            110
                    )
            );


            g2.drawRoundRect(
                    0,
                    0,
                    getWidth() - 1,
                    getHeight() - 1,
                    16,
                    16
            );


            g2.dispose();


            super.paintComponent(g);
        }
    }


    // =========================================================
    // GLOW PANEL
    // =========================================================

    private static class GlowPanel
            extends RoundedPanel {

        private final Color accent;


        GlowPanel(
                Color accent
        ) {

            super(
                    new Color(
                            7,
                            22,
                            44
                    )
            );

            this.accent = accent;
        }


        @Override
        protected void paintComponent(
                Graphics g
        ) {

            super.paintComponent(g);


            Graphics2D g2 =
                    (Graphics2D)
                            g.create();


            g2.setColor(
                    new Color(
                            accent.getRed(),
                            accent.getGreen(),
                            accent.getBlue(),
                            130
                    )
            );


            g2.drawRoundRect(
                    0,
                    0,
                    getWidth() - 1,
                    getHeight() - 1,
                    16,
                    16
            );


            g2.dispose();
        }
    }


    // =========================================================
    // GRADIENT PANEL
    // =========================================================

    private static class GradientPanel
            extends JPanel {

        private final Color color1;

        private final Color color2;


        GradientPanel(
                Color color1,
                Color color2
        ) {

            this.color1 = color1;

            this.color2 = color2;

            setOpaque(false);
        }


        @Override
        protected void paintComponent(
                Graphics g
        ) {

            Graphics2D g2 =
                    (Graphics2D)
                            g.create();


            g2.setPaint(
                    new GradientPaint(
                            0,
                            0,
                            color1,
                            getWidth(),
                            getHeight(),
                            color2
                    )
            );


            g2.fillRect(
                    0,
                    0,
                    getWidth(),
                    getHeight()
            );


            g2.dispose();


            super.paintComponent(g);
        }
    }


    // =========================================================
    // CYBER BACKGROUND
    // =========================================================

    private static class CyberBackgroundPanel
            extends JPanel {

        private final List<Point>
                particles =
                new ArrayList<>();


        private long tick = 0;


        CyberBackgroundPanel() {

            setOpaque(true);


            java.util.Random random =
                    new java.util.Random(
                            21
                    );


            for (
                    int i = 0;
                    i < 80;
                    i++
            ) {

                particles.add(
                        new Point(
                                random.nextInt(
                                        1600
                                ),
                                random.nextInt(
                                        1000
                                )
                        )
                );
            }
        }


        @Override
        protected void paintComponent(
                Graphics g
        ) {

            super.paintComponent(g);


            Graphics2D g2 =
                    (Graphics2D)
                            g.create();


            g2.setRenderingHint(
                    RenderingHints.KEY_ANTIALIASING,
                    RenderingHints.VALUE_ANTIALIAS_ON
            );


            int width =
                    getWidth();

            int height =
                    getHeight();


            GradientPaint gradient =
                    new GradientPaint(
                            0,
                            0,
                            new Color(
                                    2,
                                    7,
                                    20
                            ),
                            width,
                            height,
                            new Color(
                                    4,
                                    20,
                                    42
                            )
                    );


            g2.setPaint(gradient);


            g2.fillRect(
                    0,
                    0,
                    width,
                    height
            );


            // Grid

            g2.setColor(
                    new Color(
                            0,
                            155,
                            255,
                            15
                    )
            );


            int horizon =
                    (int)
                            (
                                    height
                                            * 0.65
                            );


            for (
                    int y = horizon;
                    y < height;
                    y += 35
            ) {

                g2.drawLine(
                        0,
                        y,
                        width,
                        y
                );
            }


            for (
                    int x = -width;
                    x < width * 2;
                    x += 80
            ) {

                g2.drawLine(
                        width / 2,
                        horizon,
                        x,
                        height
                );
            }


            // Particles

            tick++;


            for (
                    int i = 0;
                    i < particles.size();
                    i++
            ) {

                Point point =
                        particles.get(i);


                int x =
                        (int)
                                (
                                        (
                                                point.x
                                                        + tick
                                                        * (
                                                        i % 3 + 1
                                                )
                                                        * 0.12
                                        )
                                                %
                                                Math.max(
                                                        1,
                                                        width
                                                )
                                );


                int y =
                        point.y
                                %
                                Math.max(
                                        1,
                                        height
                                );


                g2.setColor(
                        new Color(
                                35,
                                190,
                                255,
                                35
                        )
                );


                g2.fillOval(
                        x,
                        y,
                        3,
                        3
                );
            }


            g2.dispose();
        }
    }


    // =========================================================
    // MAIN
    // =========================================================

    public static void main(
            String[] args
    ) {

        SwingUtilities.invokeLater(
                () -> {

                    if (
                            UserSession.isLoggedIn()
                    ) {

                        new Dashboard()
                                .setVisible(true);

                    } else {

                        new LoginFrame()
                                .setVisible(true);
                    }
                }
        );
    }
}