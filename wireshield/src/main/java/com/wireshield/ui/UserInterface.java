package com.wireshield.ui;
import com.wireshield.av.FileManager;
import com.wireshield.av.ScanReport;
import com.wireshield.enums.connectionStates;
import com.wireshield.enums.runningStates;
import com.wireshield.enums.vpnOperations;
import com.wireshield.localfileutils.SystemOrchestrator;
import com.wireshield.wireguard.WireguardManager;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.VBox;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.scene.control.ListView;

public class UserInterface extends Application {

    private static final Logger logger = LogManager.getLogger(UserInterface.class);
    protected static SystemOrchestrator so;
    protected static WireguardManager wg;
    protected String selectedPeerFile;
    private static double xOffset = 0;
    private static double yOffset = 0;

    // FXML Controls
    @FXML
    protected Button vpnButton;
    @FXML
    protected Label avStatusLabel;
    @FXML
    protected Label connLabel;
    @FXML
    protected AnchorPane homePane;
    @FXML
    protected AnchorPane logsPane;
    @FXML
    protected AnchorPane avPane;
    @FXML
    protected TextArea logsArea;
    @FXML
    protected Button minimizeButton;
    @FXML
    protected Button closeButton;
    @FXML
    protected ListView<String> avFilesListView;
    @FXML
    protected VBox peerCardsContainer;

    @Override
    public void start(Stage primaryStage) {
        try {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("MainView.fxml"));
            Parent root = loader.load();
            Scene scene = new Scene(root);
            scene.getStylesheets().add(getClass().getResource("styles.css").toExternalForm());

            primaryStage.initStyle(StageStyle.UNDECORATED);
            primaryStage.setTitle("Wireshield");
            primaryStage.setScene(scene);
            primaryStage.show();

            root.setOnMousePressed(event -> {
                xOffset = event.getSceneX();
                yOffset = event.getSceneY();
            });
            root.setOnMouseDragged(event -> {
                primaryStage.setX(event.getScreenX() - xOffset);
                primaryStage.setY(event.getScreenY() - yOffset);
            });
            logger.info("Main view loaded successfully.");
        } catch (IOException e) {
            e.printStackTrace();
            logger.error("Failed to load the main view.");
        }
    }

    @FXML
    public void initialize() {
        viewHome();
        updatePeerList();
        startDynamicConnectionLogsUpdate();
        startDynamicLogUpdate();

        if (vpnButton.getText().equals("Start VPN")) {
            vpnButton.setDisable(true);
        }

        logger.info("UI initialized successfully");
    }

    public static void main(String[] args) {
        so = SystemOrchestrator.getInstance();
        so.manageVPN(vpnOperations.STOP, null);
        wg = so.getWireguardManager();
        launch(args);
    }

    @FXML
    public void minimizeWindow() {
        Stage stage = (Stage) minimizeButton.getScene().getWindow();
        stage.setIconified(true);
        logger.info("Window minimized.");
    }

    @FXML
    public void closeWindow() {
        Stage stage = (Stage) closeButton.getScene().getWindow();
        stage.close();

        so.manageDownload(runningStates.DOWN);
        so.manageAV(runningStates.DOWN);
        so.manageVPN(vpnOperations.STOP, null);
        System.exit(0);
    }

    @FXML
    public void changeVPNState() {
        if (so.getConnectionStatus() == connectionStates.CONNECTED) {
            so.setGuardianState(runningStates.DOWN);
            so.manageDownload(runningStates.DOWN);
            so.manageAV(runningStates.DOWN);
            so.manageVPN(vpnOperations.STOP, null);
            vpnButton.setText("Start VPN");
            logger.info("All services are stopped.");
        } else {
            so.manageVPN(vpnOperations.START, selectedPeerFile);
            so.manageAV(runningStates.UP);
            so.manageDownload(runningStates.UP);
            so.statesGuardian();
            vpnButton.setText("Stop VPN");
            logger.info("All services started successfully.");
        }
    }

    @FXML
    public void viewHome() {
        homePane.toFront();
        updatePeerList();
    }

    @FXML
    public void viewLogs() {
        logsPane.toFront();
        logger.info("Viewing logs...");
    }

    @FXML
    public void viewAv() {
        runningStates avStatus = so.getAVStatus();
        avStatusLabel.setText(avStatus.toString());
        if (avStatus == runningStates.UP) {
            List<ScanReport> reports = so.getAntivirusManager().getFinalReports();
            avFilesListView.getItems().clear();
            for (ScanReport report : reports) {
                String fileName = report.getFile().getName();
                String warningClass = report.getWarningClass().toString();
                avFilesListView.getItems().add(fileName + " - " + warningClass);
            }
        }
        avPane.toFront();
    }

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
                logger.debug("File copied to: {}", targetPath.toAbsolutePath());
                updatePeerList();
                logger.info("File copied successfully.");
            } catch (IOException e) {
                e.printStackTrace();
                logger.error("Failed to copy the file.");
            }
        } else {
            logger.info("No file selected.");
        }
    }

    protected void updatePeerList() {
        if (peerCardsContainer == null) {
            logger.error("peerCardsContainer is null");
            return;
        }
        
        peerCardsContainer.getChildren().clear();
        String folderPath = FileManager.getProjectFolder() + FileManager.getConfigValue("PEER_STD_PATH");
        File directory = new File(folderPath);

        if (directory.exists() && directory.isDirectory()) {
            File[] files = directory.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isFile() && file.length() > 0) {
                        VBox peerCard = new VBox();
                        peerCard.getStyleClass().add("peer-card");
                        
                        Label peerName = new Label(file.getName());
                        peerName.getStyleClass().add("peer-name");
                        peerCard.getChildren().add(peerName);
                        
                        peerCard.setOnMouseClicked(event -> {
                            selectedPeerFile = file.getName();
                            peerCardsContainer.getChildren().forEach(node -> 
                                node.getStyleClass().remove("selected"));
                            peerCard.getStyleClass().add("selected");
                            if (vpnButton.getText().equals("Start VPN")) {
                                vpnButton.setDisable(false);
                            }
                            logger.info("Selected peer file: {}", selectedPeerFile);
                        });
                        
                        peerCardsContainer.getChildren().add(peerCard);
                        logger.debug("Added peer card for file: {}", file.getName());
                    }
                }
                logger.info("Peer cards updated successfully");
            }
        } else {
            logger.warn("Peer directory does not exist or is not a directory: {}", folderPath);
        }
    }

    protected void startDynamicLogUpdate() {
        Runnable task = () -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    String logs = wg.getLog();
                    Platform.runLater(() -> {
                        double scrollPosition = logsArea.getScrollTop();
                        logsArea.clear();
                        logsArea.setText(logs);
                        logsArea.setScrollTop(scrollPosition);
                    });
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    logger.error("Dynamic log update thread interrupted.");
                } catch (Exception e) {
                    Thread.currentThread().interrupt();
                    logger.error("Error updating logs dynamically: ", e);
                }
            }
        };

        Thread logUpdateThread = new Thread(task);
        logUpdateThread.setDaemon(true);
        logUpdateThread.start();
    }

    protected void startDynamicConnectionLogsUpdate() {
        Runnable task = () -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    String logs = wg.getConnectionLogs();
                    Platform.runLater(() -> {
                        connLabel.setText("");
                        connLabel.setText(logs);
                    });
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    logger.error("Dynamic connection logs update thread interrupted.");
                } catch (Exception e) {
                    Thread.currentThread().interrupt();
                    logger.error("Error updating connection logs: ", e);
                }
            }
        };

        Thread connectionLogThread = new Thread(task);
        connectionLogThread.setDaemon(true);
        connectionLogThread.start();
    }
}