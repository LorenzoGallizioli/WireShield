package com.wireshield.ui;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.kordamp.ikonli.javafx.FontIcon;

import com.wireshield.av.FileManager;
import com.wireshield.av.ScanReport;
import com.wireshield.enums.connectionStates;
import com.wireshield.enums.runningStates;
import com.wireshield.enums.vpnOperations;
import com.wireshield.enums.warningClass;
import com.wireshield.localfileutils.SystemOrchestrator;
import com.wireshield.windows.WFPManager;
import com.wireshield.wireguard.Connection;
import com.wireshield.wireguard.Peer;
import com.wireshield.wireguard.PeerManager;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.scene.shape.Circle;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.stage.WindowEvent;

public class UserInterface extends Application implements PeerOperationListener {

    private static final Logger logger = LogManager.getLogger(UserInterface.class);

    protected static SystemOrchestrator so;

    protected String selectedPeer;
    private Thread logUpdateThread;
    private Thread connectionInfoUpdateThread;
    private Process notepadProcess;

    private static double xOffset = 0;
    private static double yOffset = 0;

    double peerInfo_xOffset = 740.0;
    double peerInfo_yOffset = 470.0;
    double peerInfo_leftAnchor = 320.0;
    double peerInfo_topAnchor = 145.0;

    static String defaultPeerPath = FileManager.getProjectFolder() + FileManager.getConfigValue("PEER_STD_PATH");

    // FXML Controls
    @FXML
    protected Button vpnButton;
    @FXML
    protected Label avStatusLabel;
    @FXML
    protected Label connStatusLabel;
    @FXML
    protected Label lastHandshakeTimeLabel;
    @FXML
    protected Label sentTrafficLable;
    @FXML
    protected Label receivedTrafficLabel;
    @FXML
    protected Label connInterfaceLabel;
    @FXML
    protected AnchorPane homePane;
    @FXML
    protected AnchorPane logsPane;
    @FXML
    protected AnchorPane avPane;
    @FXML
    protected TextArea logsArea;
    @FXML
    protected Button closeButton;
    @FXML
    protected ListView<String> avFilesListView;
    @FXML
    protected VBox peerCardsContainer;
    @FXML
    protected AnchorPane CIDRPane;

    @Override
    public void start(Stage primaryStage) {
        try {

            FXMLLoader loader = new FXMLLoader(getClass().getResource("MainView.fxml"));
            Parent root = loader.load();

            Scene scene = new Scene(root);
            scene.getStylesheets().add(getClass().getResource("styles.css").toExternalForm());

            primaryStage.initStyle(StageStyle.DECORATED);
            primaryStage.setTitle("WireShield - ALPHA");

            primaryStage.setScene(scene);
            primaryStage.setResizable(false);
            primaryStage.setOnCloseRequest(this::closeWindow);
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

        this.loadPeersFromPath();
        this.viewHome();
        this.setDynamicLogUpdate();

        this.startDynamicConnectionInfoUpdate();
        if(FileManager.getConfigValue("CLAMD_SERVICE_AUTOMATIC_STARTUP").equals("true")){
            this.so.manageClamdService(runningStates.UP);
        }

        if (this.vpnButton.getText().equals("Start VPN")) {
            this.vpnButton.setDisable(true);
        }

        logger.info("UI initialized successfully");
    }

    public static void main(String[] args) {
        
        so = SystemOrchestrator.getInstance();

        so.manageVPN(vpnOperations.STOP, null);

        launch(args);
    }

    @FXML
    public void closeWindow(WindowEvent windowevent) {
        this.so.manageDownload(runningStates.DOWN);

        this.so.manageClamdService(runningStates.DOWN);
        this.so.manageAV(runningStates.DOWN);
        this.so.manageVPN(vpnOperations.STOP, null);

        while(this.so.getConnectionStatus() == connectionStates.CONNECTED || this.so.getAntivirusManager().getClamdStatus() == runningStates.UP) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {}
        }

        // manca da aggiungere il print con logger di chiusra su tutti i thread (in modo da eseguire il debug e verifica)
        // verficare che i thread siano stati chiusi correttamente e che non ne restanino di attivi
        this.stopAllThreads();

        System.exit(0);
    }

    @FXML
    public void viewHome() {
        this.stopDynamicLogUpdate();
        this.stopAVInfoUpdate();

        this.updatePeerList();
        this.startDynamicConnectionInfoUpdate();

        this.homePane.toFront();
    }

    @FXML
    public void viewLogs() {
        this.stopAVInfoUpdate();
        this.stopDynamicConnectionLogsUpdate();

        this.startDynamicLogUpdate();

        this.logsPane.toFront();
    }

    @FXML
    public void viewAv() {
        this.stopDynamicLogUpdate();
        this.stopDynamicConnectionLogsUpdate();

        this.startUpdateAVInfo();

        this.avPane.toFront();
    }

    /*@FXML
    public void viewAv() {
        this.stopDynamicLogUpdate();

        runningStates scannerStatus = so.getScannerStatus();
        avStatusLabel.setText(scannerStatus.toString());

        if (scannerStatus == runningStates.UP) {
            List<ScanReport> reports = so.getAntivirusManager().getFinalReports();
            avFilesListView.getItems().clear();
            for (ScanReport report : reports) {
                String fileName = report.getFile().getName();
                String warningClass = report.getWarningClass().toString();
                avFilesListView.getItems().add(fileName + " - " + warningClass);
            }
        }
        avPane.toFront();
    }*/


    /**
     * Toggles the VPN connection state. If the VPN is currently connected,
     * stops all services (VPN, antivirus, and download manager). If
     * disconnected, starts all services using the selected peer configuration.
     * Updates the UI to reflect the current state.
     */
    @FXML
    public void changeVPNState() {
        if (this.so.getConnectionStatus() == connectionStates.CONNECTED) 
        {
            this.so.setGuardianState(runningStates.DOWN);
            this.so.manageDownload(runningStates.DOWN);
            this.so.manageAV(runningStates.DOWN);

            this.so.manageVPN(vpnOperations.STOP, null);
            while (this.so.getConnectionStatus() == connectionStates.CONNECTED) {
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {}
            }

            this.vpnButton.setText("Start VPN");
            logger.info("All services are stopped.");

            Peer[] peers = so.getWireguardManager().getPeerManager().getPeers();
            Peer p = so.getWireguardManager().getPeerManager().getPeerByName(this.selectedPeer);
            if (!Arrays.asList(peers).contains(p)) {
                vpnButton.setDisable(true);
            }

        } else {
            this.vpnButton.setDisable(true);

            this.so.manageVPN(vpnOperations.START, this.selectedPeer);
            while (this.so.getConnectionStatus() == connectionStates.DISCONNECTED) {
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {}
            }
            this.so.getWireguardManager().startUpdateConnectionStats();


            this.so.manageAV(runningStates.UP);
            this.so.manageDownload(runningStates.UP);
            this.so.statesGuardian();

            this.vpnButton.setDisable(false);
            this.vpnButton.setText("Stop VPN");
            logger.info("All services started successfully.");
        }
    }

    /**
     * Handles the selection and import of WireGuard configuration files. Opens
     * a file chooser dialog for the user to select a .conf file, copies it to
     * the peer directory, and updates the peer list in the UI.
     *
     * @param event The action event that triggered this method
     */
    @FXML
    public void handleFileSelection(ActionEvent event) {

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

                String peerNameWithoutExtension = selectedFile.getName().contains(".") ? selectedFile.getName().substring(0, selectedFile.getName().lastIndexOf(".")) : selectedFile.getName();
                WFPManager.createCIDRFile(this.defaultPeerPath, peerNameWithoutExtension);

                // Update list and peerContainer
                loadPeersFromPath();
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
     * Loads peer configurations from the specified folder path. Resets the
     * current peer list and rebuilds it by parsing each configuration file.
     * Peer objects are created based on the parsed configuration data.
     */
    private void loadPeersFromPath() {
        File directory = new File(defaultPeerPath);

        System.out.println("Loading peers from path: " + defaultPeerPath);

        this.so.getWireguardManager().getPeerManager().resetPeerList();

        if (directory.exists() && directory.isDirectory()) {
            File[] files = directory.listFiles();

            if (files != null) {
                for (File file : files) {
                    if (file.isFile() && file.length() > 0 && file.getName().toLowerCase().endsWith(".conf")) {

                        Scanner scanner = null;
                        String data = "";
                        try {
                            scanner = new Scanner(file);
                        } catch (FileNotFoundException e) {
                            e.printStackTrace();
                        }

                        while (scanner.hasNextLine()) {
                            data = data + scanner.nextLine() + "\n";
                        }

                        Map<String, Map<String, String>> dataMap = PeerManager.parsePeerConfig(data);
                        this.so.getWireguardManager().getPeerManager().createPeer(dataMap, file.getName());
                    }
                }
                logger.info("Peer cards updated successfully");
            }
        } else {
            logger.warn("Peer directory does not exist or is not a directory: {}", defaultPeerPath);
        }

    }

    /**
     * Handles the deletion of a peer from the system. Removes the peer from the
     * peer manager and deletes its configuration file from the filesystem.
     * Updates the UI accordingly to reflect the deletion.
     *
     * @param peer The peer object that needs to be deleted
     */
    public void onPeerDeleted(Peer peer) {
        this.so.getWireguardManager().getPeerManager().removePeer(peer.getId());

        String peerName = peer.getName();

        File file = new File(this.defaultPeerPath + "/" + peerName);
        if (file.isFile()) {
            file.delete();
        }

        System.out.println("Peer deleted: " + peerName);
        String peerNameWithoutExtension = peerName.contains(".") ? peerName.substring(0, peerName.lastIndexOf(".")) : peerName;
        WFPManager.deleteCIDRFile(this.defaultPeerPath, peerNameWithoutExtension);

        Platform.runLater(() -> {

            this.updatePeerList();

            if (this.so.getConnectionStatus() == connectionStates.DISCONNECTED) {
                this.vpnButton.setDisable(true);
            }
        });
    }

    /**
     * Handles the peer modification process by opening the peer configuration
     * file in an external editor. After the editor is closed, it refreshes the
     * peer list and updates the peer information displayed in the UI.
     *
     * @param peer The peer object that needs to be modified
     */
    public void onPeerModified(Peer peer) {
        File configFile = new File(this.defaultPeerPath + "/" + peer.getName());

        Thread editorThread = new Thread(() -> {

            ProcessBuilder processBuilder = new ProcessBuilder("notepad.exe", configFile.getAbsolutePath());

            try {

                this.notepadProcess = processBuilder.start();

                // Create a shutdown hook
                /*Thread hookThread = new Thread(() -> {
                    if (process.isAlive()) {
                        process.destroy();
                    }
                });*/

                // Add a shutdown hook to ensure the process is terminated when the application exits.
                // When process terminate, the ShutdownHook is removed (no more needed).
                //Runtime.getRuntime().addShutdownHook(hookThread);

                this.notepadProcess.waitFor();

            }catch (InterruptedException e) {
                if (this.notepadProcess.isAlive()) {
                    this.notepadProcess.destroy();
                }
            } catch (IOException e) {}


                //Runtime.getRuntime().removeShutdownHook(hookThread);
                
                Platform.runLater(() -> {
                    this.loadPeersFromPath();
                    this.updatePeerList();

                    this.selectedPeer = peer.getName();

                    Peer updatedPeer = this.so.getWireguardManager().getPeerManager().getPeerByName(peer.getName());
                    if (updatedPeer != null) {

                        VBox existingContainer = null;
                        for (javafx.scene.Node node : this.homePane.getChildren()) {
                            if (node instanceof VBox && node.getStyleClass().contains("peerInfo-container")) {
                                existingContainer = (VBox) node;
                                break;
                            }
                        }

                        if (existingContainer != null) {
                            this.fillPeerInfoContainer(updatedPeer, existingContainer);
                        }
                    }

                    for (javafx.scene.Node node : this.peerCardsContainer.getChildren()) {
                        if (node instanceof VBox peerCard) {
                            for (javafx.scene.Node cardChild : peerCard.getChildren()) {
                                if (cardChild instanceof Label cardLabel
                                        && cardLabel.getStyleClass().contains("peer-card-text-name")
                                        && cardLabel.getText().equals(this.selectedPeer)) {
                                    peerCard.getStyleClass().add("selected");
                                    break;
                                }
                            }
                        }
                    }
                });

                logger.info("Thread stopped - [onPeerModified()] peer modify thread terminated.");
        });

        editorThread.setDaemon(true);
        editorThread.start();
    }

    /**
     * Populates the specified container with detailed information about the
     * peer. Loads the peerInfo.fxml template and configures its controller with
     * the provided peer data.
     *
     * @param peer The peer object containing the data to display
     * @param peerInfoContainer The VBox container where peer information will
     * be shown
     */
    private void fillPeerInfoContainer(Peer peer, VBox peerInfoContainer) {
        try {

            peerInfoContainer.getChildren().clear();

            FXMLLoader loader = new FXMLLoader(getClass().getResource("peerInfo.fxml"));
            javafx.scene.Node newContent = loader.load();

            PeerInfoController controller = loader.getController();
            controller.setPeer(peer);
            controller.setOperationListener(this);
            controller.loadCIDRs();

            peerInfoContainer.getChildren().add(newContent);

            if (!this.homePane.getChildren().contains(peerInfoContainer)) {
                this.homePane.getChildren().add(peerInfoContainer);
            }

        } catch (Exception e) {
            logger.error("Error during peerInfo pannel initialization: " + e.getMessage(), e);
        }
    }

    /**
     * Creates a new VBox container for displaying peer information. Sets its
     * style class and preferred dimensions. Anchors it to the specified
     * position within the home pane.
     *
     * @return VBox The newly created VBox container for peer information
     */
    private VBox createPeerInfoContainer() {

        VBox peerInfo = new VBox();

        peerInfo.getStyleClass().add("peerInfo-container");
        peerInfo.setPrefWidth(peerInfo_xOffset);
        peerInfo.setPrefHeight(peerInfo_yOffset);
        AnchorPane.setLeftAnchor(peerInfo, peerInfo_leftAnchor);
        AnchorPane.setTopAnchor(peerInfo, peerInfo_topAnchor);

        return peerInfo;
    }

    /**
     * Handles peer selection events when a peer card is clicked. Updates the UI
     * to reflect the selected peer, enables the VPN button if appropriate, and
     * displays detailed information about the selected peer.
     *
     * @param peer The peer that was selected
     * @param peerCard The VBox representing the peer card in the UI that was
     * clicked
     */
    private void onClickOperation(Peer peer, VBox peerCard) {

        this.peerCardsContainer.getChildren().forEach(node -> node.getStyleClass().remove("selected"));
        peerCard.getStyleClass().add("selected");

        // Connection Container Logic
        this.selectedPeer = peer.getName();

        if (this.vpnButton.getText().equals("Start VPN")) {
            this.vpnButton.setDisable(false);
        }

        // PeerInfo Container Logic
        VBox existingContainer = null;
        for (javafx.scene.Node node : homePane.getChildren()) {
            if (node instanceof VBox && node.getStyleClass().contains("peerInfo-container")) {
                existingContainer = (VBox) node;
                break;
            }
        }

        VBox peerInfoContainer = existingContainer != null ? existingContainer : createPeerInfoContainer();

        this.fillPeerInfoContainer(peer, peerInfoContainer);

        logger.info("Selected peer file: {}", this.selectedPeer);
    }

    /**
     * Updates the list of peers displayed in the UI. Clears and repopulates the
     * peer cards container with current peer data. Each card displays the peer
     * name and endpoint address, and is clickable to select that peer. This
     * method is called after any changes to the peer configurations.
     */
    protected void updatePeerList() {

        if (this.peerCardsContainer == null) {
            logger.error("peerCardsContainer is null");
            return;
        }

        this.peerCardsContainer.getChildren().clear();

        for (Peer peer : this.so.getWireguardManager().getPeerManager().getPeers()) {
            VBox peerCard = new VBox();
            peerCard.getStyleClass().add("peer-card");

            Label peerName = new Label(peer.getName());
            Label peerAddr = new Label(peer.getEndPoint());

            peerName.getStyleClass().add("peer-card-text-name");
            peerAddr.getStyleClass().add("peer-card-text-address");

            peerCard.getChildren().add(peerName);
            peerCard.getChildren().add(peerAddr);

            peerCard.setOnMouseClicked(event -> onClickOperation(peer, peerCard));

            this.peerCardsContainer.getChildren().add(peerCard);

            logger.debug("Added peer card for file: {}", peer.getName());
        }
    }

    /**
     * Starts a background thread that periodically updates the log display
     * area. Retrieves the latest logs from the WireGuard manager and updates
     * the UI while preserving the current scroll position. This thread runs as
     * a daemon to ensure it's terminated when the application closes.
     */
    protected void setDynamicLogUpdate() {

        this.logUpdateThread = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    String logs = this.so.getWireguardManager().getLog();

                    Platform.runLater(() -> {
                        double scrollPosition = this.logsArea.getScrollTop();
                        this.logsArea.clear();
                        this.logsArea.setText(logs);
                        this.logsArea.setScrollTop(scrollPosition);
                    });

                    Thread.sleep(1000);

                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            logger.info("Thread stopped - [setDynamicLogUpdate()] logUpdateThread thread terminated.");
        });

        this.logUpdateThread.setDaemon(true);
    }

    protected void startDynamicLogUpdate() {
        
        if (this.logUpdateThread != null && this.logUpdateThread.isAlive()) {
            return;
        }

        if (this.logUpdateThread.isInterrupted()) {
            setDynamicLogUpdate();
        }
        this.logUpdateThread.start();
    }

    protected void stopDynamicLogUpdate() {

        if (this.logUpdateThread != null && this.logUpdateThread.isAlive()) {
            this.logUpdateThread.interrupt();
            try{
                this.logUpdateThread.join();
            }catch (InterruptedException e) {}
        }
    }

    /**
     * Starts a background thread that periodically updates the connection
     * information displayed in the UI. Updates various UI elements with
     * real-time connection data such as: - Active interface name - Connection
     * status with appropriate color indication - Sent and received traffic data
     * with appropriate formatting - Time since the last handshake occurred
     *
     * This thread runs as a daemon to ensure it's terminated when the
     * application closes. Updates occur at 1-second intervals to provide near
     * real-time feedback.
     */
    protected void startDynamicConnectionInfoUpdate() {

        if (this.connectionInfoUpdateThread != null && this.connectionInfoUpdateThread.isAlive()) {
            return;
        }

        this.connectionInfoUpdateThread = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Platform.runLater(() -> {

                        this.connStatusLabel.setText("");
                        if (so.getConnectionStatus() == connectionStates.CONNECTED) {

                            this.connStatusLabel.setText("● Connected");
                            this.connStatusLabel.setStyle("-fx-text-fill: #DAF7A6");

                            String interf = so.getWireguardManager().getConnection().getActiveInterface();
                            if (interf == null) {
                                this.connInterfaceLabel.setText("interface: --");
                            } else {
                                this.connInterfaceLabel.setText("interface: " + interf);
                            }

                            // Transmission                    	
                            this.sentTrafficLable.setText(Connection.formatBytes(so.getWireguardManager().getConnection().getSentTraffic()));
                            this.receivedTrafficLabel.setText(Connection.formatBytes(so.getWireguardManager().getConnection().getReceivedTraffic()));

                            // HandShake
                            this.lastHandshakeTimeLabel.setText(TimeUtil.getTimeSinceHandshake(so.getWireguardManager().getConnection().getLastHandshakeTime()));

                        } else {
                            this.connStatusLabel.setText("● Disconnected");
                            this.connStatusLabel.setStyle("-fx-text-fill: #FF5733");

                            this.connInterfaceLabel.setText("interface: --");

                            if (!this.sentTrafficLable.getText().equals("0 B")) {
                                this.sentTrafficLable.setText("0 B");
                            }
                            if (!this.receivedTrafficLabel.getText().equals("0 B")) {
                                this.receivedTrafficLabel.setText("0 B");
                            }
                            if (!this.lastHandshakeTimeLabel.getText().equals("--")) {
                                this.lastHandshakeTimeLabel.setText("--");
                            }
                        }

                    });

                    Thread.sleep(500);

                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    logger.error("Dynamic connection logs update thread interrupted.");

                } catch (Exception e) {
                    Thread.currentThread().interrupt();
                    logger.error("Error updating connection logs: ", e);

                }
            }

            logger.info("Thread stopped - [startDynamicConnectionLogsUpdate()] UI update connection info thread terminated.");
        });

        this.connectionInfoUpdateThread.setDaemon(true);
        this.connectionInfoUpdateThread.start();
    }

    private void stopDynamicConnectionLogsUpdate() {
        if (this.connectionInfoUpdateThread != null && this.connectionInfoUpdateThread.isAlive()) {
            this.connectionInfoUpdateThread.interrupt();
            try {
                this.connectionInfoUpdateThread.join();
            } catch (InterruptedException e) {}
        }
    }



    /* AntiVirus */
    @FXML
    private Circle statusIndicator;
    @FXML
    private Button startScanButton;
    @FXML
    private Label totalScannedLabel;
    @FXML
    private Label threatsDetectedLabel;
    @FXML
    private Label currentStatusLabel;
    @FXML
    private TextField searchField;
    @FXML
    private VBox fileCardsContainer;

    Thread updateAVInfoThread;

    private List<FileCardComponent> fileCards = new ArrayList<>();

    /**
     * Avvia il thread che aggiorna le informazioni sull'antivirus e sullo stato del servizio ogni secondo.
     * Il thread viene eseguito in background e continua a eseguire l'aggiornamento fino a quando non viene interrotto.
     */
    private void startUpdateAVInfo(){

        if (this.updateAVInfoThread != null && this.updateAVInfoThread.isAlive()) {
            return;
        }
        
        Runnable task = () -> {
            while (!Thread.currentThread().isInterrupted()) {

                runningStates scannerStatus = this.so.getScannerStatus();

                this.clamdAtStartupSelector();

                Platform.runLater(() -> {
                    this.updateAVInfo(scannerStatus);
                    this.updateServiceStatus(scannerStatus, this.so.getAntivirusManager().getClamdStatus());
                });

                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            logger.info("Thread interrupted - [startUpdateAVInfo()] AV info update thread interrupted.");    
        };

        this.updateAVInfoThread = new Thread(task);
        this.updateAVInfoThread.setDaemon(true);
        this.updateAVInfoThread.start();
    }

    /**
     * Ferma l'aggiornamento delle informazioni sull'antivirus interrompendo il thread associato e aspettando il suo completamento.
     */
    private void stopAVInfoUpdate() {
        if (this.updateAVInfoThread != null && this.updateAVInfoThread.isAlive()) {
            this.updateAVInfoThread.interrupt();
            try {
                this.updateAVInfoThread.join();
            } catch (InterruptedException e) {}
        }
    }

    /**
     * Aggiorna le informazioni sull'antivirus in base allo stato dello scanner.
     * Se lo scanner è attivo, mostra i report finali, il numero di minacce rilevate e le informazioni sui file scansionati.
     * Se lo scanner non è attivo, resetta le etichette e le card.
     *
     * @param scannerStatus Lo stato attuale dello scanner antivirus.
     */
    private void updateAVInfo(runningStates scannerStatus){

        if (scannerStatus == runningStates.UP) {

            List<ScanReport> reports = so.getAntivirusManager().getFinalReports();
            this.totalScannedLabel.setText(String.valueOf(reports.size()));

            long threatCount = reports.stream().filter(report -> !report.getWarningClass().equals(com.wireshield.enums.warningClass.CLEAR)).count();
            this.threatsDetectedLabel.setText(String.valueOf(threatCount));

            this.fileCardsContainer.getChildren().clear();
            this.fileCards.clear();

            for (ScanReport report : reports) {
                String fileName = report.getFile().getName();
                String filePath = report.getFile().getAbsolutePath();
                warningClass warningClass = report.getWarningClass();

                String status = convertWarningClassToStatus(warningClass);

                LocalDateTime scanTime = LocalDateTime.now();

                addScannedFile(fileName, filePath, status, scanTime, warningClass);
            }

        } else {
            this.totalScannedLabel.setText("0");
            this.threatsDetectedLabel.setText("0");
            this.fileCardsContainer.getChildren().clear();
            this.fileCards.clear();
        }
    }

    /**
     * Aggiorna lo stato visivo del servizio nell'interfaccia utente.
     * Modifica il colore dell'indicatore di stato e il testo dei label in base allo stato dello scanner e del servizio antivirus.
     *
     * @param scannerStatus Lo stato attuale dello scanner antivirus.
     * @param avStatus Lo stato del servizio antivirus.
     */
    private void updateServiceStatus(runningStates scannerStatus, runningStates clamdStatus) {

        statusIndicator.getStyleClass().removeAll("inactive", "active");

        switch (clamdStatus) {
            case UP:
                this.statusIndicator.getStyleClass().add("active");
                this.avStatusLabel.setText("Servizio antivirus attivo");

                if (scannerStatus == runningStates.UP) {
                    this.currentStatusLabel.setText("In esecuzione");
                } else {
                    this.currentStatusLabel.setText("In attesa");
                }
                break;

            case DOWN:
                this.statusIndicator.getStyleClass().add("inactive");
                this.avStatusLabel.setText("Servizio antivirus non attivo");
                this.currentStatusLabel.setText("Non disponibile");
                break;

            // Aggiungi altri stati se necessario
            default:
                break;
        }
    }

    /**
     * Converte una classe di avviso di un report in uno stato stringa da visualizzare.
     * Gli stati possibili sono "Clean", "Warning" e "Threat".
     *
     * @param warningClass La classe di avviso del report da convertire.
     * @return Lo stato corrispondente alla classe di avviso.
     */
    private String convertWarningClassToStatus(warningClass warningClass) {
        if (warningClass.equals(warningClass.CLEAR)) {
            return "Clean";
        } else if (warningClass.equals(warningClass.SUSPICIOUS)) {
            return "Warning";
        } else {
            return "Threat";
        }
    }

    /**
     * Aggiunge una card alla lista dei file scansionati nell'interfaccia utente.
     *
     * @param fileName Il nome del file scansionato.
     * @param filePath Il percorso del file scansionato.
     * @param status Lo stato del file scansionato ("Clean", "Warning", "Threat").
     * @param scanTime Il tempo in cui è stata eseguita la scansione.
     * @param detectedThreats La minaccia rilevata durante la scansione del file.
     */
    private void addScannedFile(String fileName, String filePath, String status, LocalDateTime scanTime, warningClass detectedThreats) {
        FileCardComponent card = new FileCardComponent(fileName, filePath, status, scanTime, this.convertWarningClassToStatus(detectedThreats).toUpperCase());
        this.fileCards.add(card);
        this.fileCardsContainer.getChildren().add(card);
    }

    /**
     * Filtra le card dei file scansionati in base al testo di ricerca.
     * Mostra solo le card che contengono il testo di ricerca nel nome del file.
     *
     * @param searchText Il testo da cercare nel nome dei file scansionati.
     */
    private void filterFileCards(String searchText) {
        if (searchText == null || searchText.isEmpty()) {
            this.fileCardsContainer.getChildren().clear();
            this.fileCardsContainer.getChildren().addAll(this.fileCards);
        } else {
            this.fileCardsContainer.getChildren().clear();
            searchText = searchText.toLowerCase();

            for (FileCardComponent card : this.fileCards) {
                // Nota: questo è un po' hacky, dovresti migliorare la classe FileCardComponent
                // aggiungendo un metodo per ottenere il nome del file
                String fileName = extractFileNameFromCard(card);

                if (fileName.toLowerCase().contains(searchText)) {
                    this.fileCardsContainer.getChildren().add(card);
                }
            }
        }
    }

    /**
     * Estrae il nome del file da una card di file.
     * Questo è un metodo temporaneo che dovrebbe essere migliorato nella classe `FileCardComponent`.
     *
     * @param card La card di file da cui estrarre il nome del file.
     * @return Il nome del file estratto dalla card.
     */
    private String extractFileNameFromCard(FileCardComponent card) {
        try {
            HBox mainRow = (HBox) card.getChildren().get(0);
            VBox fileInfo = (VBox) mainRow.getChildren().get(1);
            Label fileNameLabel = (Label) fileInfo.getChildren().get(0);
            return fileNameLabel.getText();
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Gestisce l'avvio automatico del servizio antivirus al momento dell'avvio del programma.
     * Imposta il testo e l'icona del pulsante in base al valore della configurazione "CLAMD_SERVICE_AUTOMATIC_STARTUP".
     * Inoltre, definisce il comportamento del pulsante per abilitare o disabilitare l'avvio automatico del servizio.
     */
    private void clamdAtStartupSelector(){

        Platform.runLater(() -> {
            if (FileManager.getConfigValue("CLAMD_SERVICE_AUTOMATIC_STARTUP").equals("true")) {
                this.startScanButton.setText("Service enabled");
                ((FontIcon)this.startScanButton.getGraphic()).setIconLiteral("fas-pause");
            } else {
                this.startScanButton.setText("Service disabled");
                ((FontIcon)this.startScanButton.getGraphic()).setIconLiteral("fas-play");
            }
        });

        this.startScanButton.setOnAction(event -> {
            if (FileManager.getConfigValue("CLAMD_SERVICE_AUTOMATIC_STARTUP").equals("true")) {
                FileManager.setConfigValue("CLAMD_SERVICE_AUTOMATIC_STARTUP", "false");
                clamdAtStartupSelector();
            } else {
                FileManager.setConfigValue("CLAMD_SERVICE_AUTOMATIC_STARTUP", "true");
                clamdAtStartupSelector();
            }
        });
    }




    /* GENERAL PURPOSE METHODS */

    private void stopAllThreads(){

        try{
            // SystemOrchestrator
            this.so.interruptAllThreads();

            // WireguardManager
            this.so.getWireguardManager().interruptAllThreads();

            // Connection
            this.so.getWireguardManager().getConnection().interruptAllThreads();

            // AntivirusManager
            this.so.getAntivirusManager().interruptAllThreads();

            // ClamAV
            this.so.getAntivirusManager().getClamAV().interruptAllThreads();

            // DownloadManager
            this.so.getDownloadManager().interruptAllThreads();

        }catch (InterruptedException e) {
            logger.error("Error stopping all threads: ", e);
        }
    } 
}
