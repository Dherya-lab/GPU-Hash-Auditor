import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.MessageDigest;

public class Dashboard {
    public static void main(String[] args) {
        JFrame frame = new JFrame("GPU Hash Auditor Control Panel");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(750, 450);
        frame.setLayout(new BorderLayout(10, 10));

        JPanel topPanel = new JPanel();
        
        // NEW: Dropdown for Algorithm Selection
        JComboBox<String> algoBox = new JComboBox<>(new String[]{"MD5", "SHA-256"});
        JLabel label = new JLabel("Target:");
        JTextField inputField = new JTextField(20);
        JCheckBox plainTextCheck = new JCheckBox("Input is Plain Text");
        JButton startButton = new JButton("Start Audit");
        
        topPanel.add(algoBox);
        topPanel.add(label);
        topPanel.add(inputField);
        topPanel.add(plainTextCheck);
        topPanel.add(startButton);

        JTextArea consoleLog = new JTextArea();
        consoleLog.setEditable(false);
        consoleLog.setBackground(Color.BLACK);
        consoleLog.setForeground(Color.GREEN);
        consoleLog.setFont(new Font("Monospaced", Font.PLAIN, 14));
        JScrollPane scrollPane = new JScrollPane(consoleLog);

        JProgressBar progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setPreferredSize(new Dimension(700, 30));
        progressBar.setForeground(new Color(0, 150, 255));

        frame.add(topPanel, BorderLayout.NORTH);
        frame.add(scrollPane, BorderLayout.CENTER);
        frame.add(progressBar, BorderLayout.SOUTH);

        startButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String target = inputField.getText().trim();
                String selectedAlgo = algoBox.getSelectedItem().toString();
                
                if (target.isEmpty()) {
                    consoleLog.append(">> ERROR: Please enter a target.\n");
                    return;
                }

                if (plainTextCheck.isSelected()) {
                    try {
                        // Dynamically hash based on the dropdown selection
                        MessageDigest md = MessageDigest.getInstance(selectedAlgo);
                        byte[] hashBytes = md.digest(target.getBytes());
                        StringBuilder sb = new StringBuilder();
                        for (byte b : hashBytes) {
                            sb.append(String.format("%02x", b));
                        }
                        target = sb.toString();
                        consoleLog.append(">> UI AUTO-CONVERT: Translated plain text to " + selectedAlgo + " -> " + target + "\n");
                    } catch (Exception ex) {
                        consoleLog.append(">> ERROR: Could not generate hash.\n");
                        return;
                    }
                }

                startButton.setEnabled(false); 
                progressBar.setValue(0);
                consoleLog.append(">> Connecting to Python Orchestrator...\n");
                
                // Pack the algorithm and the hash together (e.g., "SHA-256:9f86d081884c7d65...")
                final String finalPayload = selectedAlgo + ":" + target; 

                new Thread(() -> {
                    try (Socket socket = new Socket("127.0.0.1", 5000);
                         PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                         BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
                         
                        out.println(finalPayload); 
                        
                        String line;
                        while ((line = in.readLine()) != null) {
                            if (line.startsWith("PROG:")) {
                                int percent = Integer.parseInt(line.substring(5).trim());
                                SwingUtilities.invokeLater(() -> progressBar.setValue(percent));
                            } else if (line.startsWith("DONE:")) {
                                String doneMsg = line.substring(5); 
                                SwingUtilities.invokeLater(() -> {
                                    consoleLog.append(">> " + doneMsg + "\n\n");
                                    progressBar.setValue(100);
                                    startButton.setEnabled(true);
                                });
                                break;
                            } else {
                                String msg = line;
                                SwingUtilities.invokeLater(() -> consoleLog.append(">> " + msg + "\n"));
                            }
                        }
                    } catch (Exception ex) {
                        SwingUtilities.invokeLater(() -> {
                            consoleLog.append(">> ERROR: Connection failed. Is server.py running?\n\n");
                            startButton.setEnabled(true);
                        });
                    }
                }).start();
            }
        });

        frame.setLocationRelativeTo(null); 
        frame.setVisible(true);
    }
}