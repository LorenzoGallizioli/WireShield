package com.wireshield.ui;
import com.wireshield.av.FileManager;
import com.wireshield.av.ScanReport;
import com.wireshield.enums.connectionStates;
import com.wireshield.enums.runningStates;
import com.wireshield.enums.vpnOperations;
import com.wireshield.localfileutils.SystemOrchestrator;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;

import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;
import javafx.scene.layout.AnchorPane;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.control.ListView;

public class UserInterface extends Application {

    private static SystemOrchestrator so;

    /**
     * JavaFX Buttons.
     */
    @FXML
    private Button vpnButton, uploadPeerButton;

    /**
     * JavaFX AnchorPanes.
     */
    @FXML
    private AnchorPane homePane, logsPane, avPane, settingsPane;

    /**
     * JavaFX TextAreas.
     */
    @FXML
    private TextArea logsArea, avStatusArea, avFilesArea;

    /**
     * JavaFX ListViews.
     */
    @FXML
    private ListView<String> peerListView;
    private ObservableList<String> peerList = FXCollections.observableArrayList();
    @FXML
    private ListView<String> avFilesListView;
    private ObservableList<String> avFilesList = FXCollections.observableArrayList();

    /**
     * Start the application.
     */
    @Override
    public void start(Stage primaryStage) {
        try {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("MainView.fxml"));
            Parent root = loader.load();
            Scene scene = new Scene(root);
            scene.getStylesheets().add(getClass().getResource("styles.css").toExternalForm());
            primaryStage.setTitle("Wireshield");
            primaryStage.setScene(scene);
            primaryStage.show();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Initialize the user interface.
     */
    @FXML
    public void initialize() {
        viewHome();
        if (peerListView != null) {
            peerListView.setItems(peerList);
        }
        if (avFilesListView != null) {
            avFilesListView.setItems(avFilesList);
        }
    }

    /**
     * Main method to launch the WireShield application.
     * 
     * @param args Command line arguments.
     */
    public static void main(String[] args) {
        so = SystemOrchestrator.getInstance();
        so.manageVPN(vpnOperations.STOP);
        launch(args);
    }

    /**
     * Changes the state of the VPN.
     */
    @FXML
    public void changeVPNState() { 
        if (so.getConnectionStatus() == connectionStates.CONNECTED) {
            so.manageDownload(runningStates.DOWN);
            so.manageAV(runningStates.DOWN);
            so.manageVPN(vpnOperations.STOP);
            vpnButton.setText("Start VPN");
            uploadPeerButton.setDisable(false);
        } else {
            so.manageVPN(vpnOperations.START);
            so.manageAV(runningStates.UP);
            so.manageDownload(runningStates.UP);
            vpnButton.setText("Stop VPN");
            uploadPeerButton.setDisable(true);
        }
    }

    @FXML
    public void viewHome() {
        homePane.toFront();
        if (!checkFilesInDirectory()) {
            vpnButton.setDisable(true);
        } else {
            vpnButton.setDisable(false);
        }
    }

    @FXML
    public void viewLogs() {
        logsPane.toFront();
        if (so.getConnectionStatus() == connectionStates.DISCONNECTED) {
            logsArea.setText("No connection.\n");
            return;
        }
        String logs = so.getWireguardManager().getConnectionLogs();
        logsArea.setText(logs + "\n");
    }

    /**
     * Displays the antivirus page.
     */
    @FXML
    public void viewAv() {
        runningStates avStatus = so.getAVStatus();
        avStatusArea.setText(avStatus + "\n");
        if (avStatus == runningStates.UP) {
            avFilesList.clear();
            List<ScanReport> reports = so.getAntivirusManager().getFinalReports();
            for (ScanReport report : reports) {
                String fileName = report.getFile().getName();
                String warningClass = report.getWarningClass().toString();
                avFilesList.add(fileName + " - " + warningClass);
            }
        }
        avPane.toFront();
    }

    /**
     * Displays the settings page.
     */
    @FXML
    public void viewSettings() {
        settingsPane.toFront();
        updatePeerList();
    }

    private boolean checkFilesInDirectory() {
        String folderPath = FileManager.getProjectFolder() + FileManager.getConfigValue("PEER_STD_PATH");
        File directory = new File(folderPath);

        if (directory.exists() && directory.isDirectory()) {
            File[] files = directory.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isFile() && file.length() > 0) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Handles the file selection event and copies the selected file to the peer directory.
     * 
     * @param event 
     *   The action event triggered when a file is selected.
     */
    @FXML
    public void handleFileSelection(ActionEvent event) {
        String defaultPeerPath = FileManager.getProjectFolder() + FileManager.getConfigValue("PEER_STD_PATH");
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Select a File");
        fileChooser.getExtensionFilters().add(
            new FileChooser.ExtensionFilter("WireGuard Config Files (*.conf)", "*.conf")
        );

        Stage stage = new Stage();
        File selectedFile = fileChooser.showOpenDialog(stage);

        if (selectedFile != null) {
            try {
                Path targetPath = Path.of(defaultPeerPath, selectedFile.getName());
                Files.createDirectories(targetPath.getParent());
                Files.copy(selectedFile.toPath(), targetPath, StandardCopyOption.REPLACE_EXISTING);
                System.out.println("File copied to: " + targetPath.toAbsolutePath());
                updatePeerList();
            } catch (IOException e) {
                e.printStackTrace();
                System.out.println("Failed to copy the file.");
            }
        } else {
            System.out.println("No file selected.");
        }
    }

    /**
     * Updates the peer list based on the files in the peer directory.
     */
    private void updatePeerList() {
        String folderPath = FileManager.getProjectFolder() + FileManager.getConfigValue("PEER_STD_PATH");
        File directory = new File(folderPath);

        if (directory.exists() && directory.isDirectory()) {
            File[] files = directory.listFiles();
            if (files != null) {
                peerList.clear(); // Svuota la lista attuale
                for (File file : files) {
                    if (file.isFile() && file.length() > 0) {
                        peerList.add(file.getName()); // Aggiungi il nome del file alla lista
                    }
                }
            }
        }
    }
}
