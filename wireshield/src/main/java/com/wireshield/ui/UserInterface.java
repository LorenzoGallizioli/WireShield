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
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.control.ListView;

public class UserInterface extends Application {

    private static final Logger logger = LogManager.getLogger(SystemOrchestrator.class);
    protected static SystemOrchestrator so;
    
    // Control variable for componentStatesGuardian thread --> runningStates.UP let the thread to continue running, runningStates.DOWN stops the thread execution
    private runningStates componentStatesGuardianState = runningStates.DOWN; 

    /**
     * JavaFX Buttons.
     */
    @FXML
    protected Button vpnButton;

    /**
     * JavaFX Labels.
     */
    @FXML
    protected Label avStatusLabel;
    
    /**
     * JavaFX AnchorPanes.
     */
    @FXML
    protected AnchorPane homePane, logsPane, avPane, settingsPane;

    /**
     * JavaFX TextAreas.
     */
    @FXML
    protected TextArea logsArea, avFilesArea;

    /**
     * JavaFX HBox Buttons.
     */
    @FXML
    protected Button minimizeButton, closeButton;

    /**
     * JavaFX ListViews.
     */
    @FXML
    protected ListView<String> peerListView;
    protected ObservableList<String> peerList = FXCollections.observableArrayList();
    @FXML
    protected ListView<String> avFilesListView;
    protected ObservableList<String> avFilesList = FXCollections.observableArrayList();
    private String selectedPeerFile; // Variabile per memorizzare il file selezionato.
    

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
            primaryStage.initStyle(StageStyle.UNDECORATED);
            primaryStage.setTitle("Wireshield");
            primaryStage.setScene(scene);
            primaryStage.show();
            logger.info("Main view loaded successfully.");
        } catch (IOException e) {
            e.printStackTrace();
            logger.error("Failed to load the main view.");
        }
    }

    /**
     * Initialize the user interface.
     */
    @FXML
    public void initialize() {
        viewHome();
        updatePeerList();
        startDynamicLogUpdate();
        // Imposta lo stato iniziale della ListView in base allo stato della VPN
        peerListView.setDisable(so.getConnectionStatus() == connectionStates.CONNECTED);

        // Disabilita il pulsante solo se il testo è "Start VPN" e non è selezionato alcun file
        if (vpnButton.getText().equals("Start VPN")) {
            vpnButton.setDisable(true);
        }
    
        if (peerListView != null) {
            peerListView.setItems(peerList);
            peerListView.getSelectionModel().selectedItemProperty().addListener((observable, oldValue, newValue) -> {
                if (newValue != null) {
                    selectedPeerFile = newValue; // Memorizza il file selezionato
                    if (vpnButton.getText().equals("Start VPN")) {
                        vpnButton.setDisable(false); // Abilita il pulsante solo se il testo è "Start VPN"
                    }
                    logger.info("File selezionato nella peer list: " + selectedPeerFile);
                } else {
                    if (vpnButton.getText().equals("Start VPN")) {
                        vpnButton.setDisable(true); // Disabilita il pulsante solo se non c'è selezione e il testo è "Start VPN"
                    }
                    logger.info("Nessun file selezionato.");
                }
            });
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
        so.manageVPN(vpnOperations.STOP,null);
        launch(args);
    }

    /**
     * Minimizes the application window.
     */
    @FXML
    public void minimizeWindow() {
        Stage stage = (Stage) minimizeButton.getScene().getWindow();
        stage.setIconified(true);
        logger.info("Window minimized.");
    }

    /**
     * Closes the application window.
     */
    @FXML
    public void closeWindow() {
        Stage stage = (Stage) closeButton.getScene().getWindow();
        stage.close();
        so.manageDownload(runningStates.DOWN);
        so.manageAV(runningStates.DOWN);
        so.manageVPN(vpnOperations.STOP, null);
        System.exit(0);
    }

    /**
     * Changes the state of the VPN.
     */
    @FXML
    public void changeVPNState() { 

        if (so.getConnectionStatus() == connectionStates.CONNECTED) {
        	
        	// Stop execution componentStatesGuardian thread
        	componentStatesGuardianState = runningStates.DOWN;
        	
            so.manageDownload(runningStates.DOWN);
            so.manageAV(runningStates.DOWN);
            so.manageVPN(vpnOperations.STOP, null);
            vpnButton.setText("Start VPN");
            peerListView.setDisable(false); // Rendi i peer selezionabili.
            logger.info("All services are stopped.");
        } else {
            so.manageVPN(vpnOperations.START, selectedPeerFile);
            so.manageAV(runningStates.UP);
            so.manageDownload(runningStates.UP);
            
            // Start execution componentStatesGuardian thread
            componentStatesGuardian();
            
            vpnButton.setText("Stop VPN");
            peerListView.setDisable(true); // Disabilita la selezione dei peer.
            logger.info("All services started successfully.");
        }
    }
   
    /**
     * Displays the home page.
     */
    @FXML
    public void viewHome() {
        homePane.toFront();
        updatePeerList();
    }

    /**
     * Displays the logs page.
     */
    @FXML
    public void viewLogs() {
        logsPane.toFront();
    }

    /**
     * Displays the antivirus page.
     */
    @FXML
    public void viewAv() {
        runningStates avStatus = so.getAVStatus();
        avStatusLabel.setText(avStatus.toString());
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
                logger.debug("File copied to: " + targetPath.toAbsolutePath());
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

    /**
     * Updates the peer list based on the files in the peer directory.
     */
    protected void updatePeerList() {
        String folderPath = FileManager.getProjectFolder() + FileManager.getConfigValue("PEER_STD_PATH");
        File directory = new File(folderPath);

        if (directory.exists() && directory.isDirectory()) {
            File[] files = directory.listFiles();
            if (files != null) {
                peerList.clear(); // Svuota la lista attuale
                for (File file : files) {
                    if (file.isFile() && file.length() > 0) {
                        peerList.add(file.getName()); // Aggiungi il nome del file alla lista
                        logger.debug("File added to peer list: " + file.getName());
                        logger.info("Peer list updated.");
                    }
                }
            }
        }
    }

    /**
     * Starts a thread that dynamically updates the logs area.
     */
    protected void startDynamicLogUpdate() {
        Runnable task = () -> {
            while (true) {
                try {
                    // Recupera i log aggiornati
                    String logs = so.getWireguardManager().getLog();
                    // Aggiorna logsArea sul thread JavaFX
                    Platform.runLater(() -> {
                        logsArea.clear();
                        logsArea.setText(logs);
                    });
                    Thread.sleep(1000); // Attendi un secondo prima di aggiornare di nuovo
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    logger.error("Dynamic log update thread interrupted.");
                    break;
                } catch (Exception e) {
                    logger.error("Error updating logs dynamically: ", e);
                }
            }
        };

        Thread logUpdateThread = new Thread(task);
        logUpdateThread.setDaemon(true); // Assicura che il thread si fermi con l'applicazione
        logUpdateThread.start();
    }
    
    /**
     * Monitors the states of essential system components and handles failures.
     * <p>
     * This method starts a thread to periodically check the operational states of components. 
     * If a critical component fails, the system logs the error, stops related services, 
     * and shuts down the VPN for the selected peer.
     * </p>
     *
     * <h2>Functionality:</h2>
     * <ul>
     *   <li>Checks if the interface is up and the connection is active.</li>
     *   <li>Handles failures by stopping downloads, AV services, or the VPN as needed.</li>
     *   <li>Runs every 200ms until the guardian state changes from {@code runningStates.UP}.</li>
     * </ul>
     *
     * <h2>Thread Management:</h2>
     * The thread terminates gracefully when interrupted or when the guardian state changes.
     */
    private void componentStatesGuardian() {
    	Runnable task = () -> {
            while (componentStatesGuardianState == runningStates.UP) { // Check interface is up
            	if(so.getConnectionStatus() == connectionStates.CONNECTED) {
            		if(so.getAVStatus() == runningStates.DOWN || so.getMonitorStatus() == runningStates.DOWN) {
            			
            			logger.error("An essential component has encountered an error - Shutting down services...");
            			
            			if(so.getAVStatus() == runningStates.DOWN) {
            				so.manageDownload(runningStates.DOWN);
            			} else if(so.getMonitorStatus() == runningStates.DOWN) {
            				so.manageAV(runningStates.DOWN);
            			}
            			
            			so.manageVPN(vpnOperations.STOP,null);
            		}
            	}
                try {
                    Thread.sleep(200); // wait
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    logger.error("startComponentStatesGuardian() thread unexpecly interrupted");
                    break;
                }
            }
            logger.info("startComponentStatesGuardian() thread stopped");
        };
        
        Thread thread = new Thread(task);
        componentStatesGuardianState = runningStates.UP;
        thread.start();
    }

}
