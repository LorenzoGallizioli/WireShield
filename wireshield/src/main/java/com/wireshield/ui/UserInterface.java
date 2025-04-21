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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

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
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Pane;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
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
        if (FileManager.getConfigValue("CLAMD_SERVICE_AUTOMATIC_STARTUP").equals("true")) {
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

        while (this.so.getConnectionStatus() == connectionStates.CONNECTED || this.so.getAntivirusManager().getClamdStatus() == runningStates.UP) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
            }
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
        if (this.so.getConnectionStatus() == connectionStates.CONNECTED) {
            this.so.setGuardianState(runningStates.DOWN);
            this.so.manageDownload(runningStates.DOWN);
            this.so.manageAV(runningStates.DOWN);

            this.so.manageVPN(vpnOperations.STOP, null);
            while (this.so.getConnectionStatus() == connectionStates.CONNECTED) {
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                }
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
                } catch (InterruptedException e) {
                }
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

            } catch (InterruptedException e) {
                if (this.notepadProcess.isAlive()) {
                    this.notepadProcess.destroy();
                }
            } catch (IOException e) {
            }

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
            try {
                this.logUpdateThread.join();
            } catch (InterruptedException e) {
            }
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
            } catch (InterruptedException e) {
            }
        }
    }

    /* AntiVirus UI Elements */
    @FXML
    private Circle statusIndicator;
    @FXML
    private Button startScanButton; // Rinominato per chiarezza rispetto all'azione
    @FXML
    private Label totalScannedLabel;
    @FXML
    private Label threatsDetectedLabel;
    @FXML
    protected Label avStatusLabel;
    @FXML
    private Label currentStatusLabel;
    @FXML
    private TextField searchField;
    @FXML
    private VBox fileCardsContainer;

    private Thread updateAVInfoThread;
    private final List<FileCardComponent> fileCards = new ArrayList<>(); // Mantiene l'ordine visivo
    private final Set<UUID> displayedReportIds = new HashSet<>(); // Traccia gli UUID dei report mostrati
    private final Map<UUID, FileCardComponent> reportIdToCardMap = new HashMap<>(); // Mappa UUID a Card per rimozione efficiente

    /**
     * Avvia il thread di aggiornamento.
     */
    private void startUpdateAVInfo() {
        if (this.updateAVInfoThread != null && this.updateAVInfoThread.isAlive()) {
            return; // Già in esecuzione
        }

        Runnable task = () -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    // Recupera gli stati PRIMA di accedere alla UI thread
                    runningStates scannerStatus = this.so.getScannerStatus();
                    runningStates clamdStatus = this.so.getAntivirusManager().getClamdStatus();
                    List<ScanReport> finalReports = null;

                    if (scannerStatus == runningStates.UP) {
                        // Recupera i report solo se lo scanner è attivo
                        // Clona la lista per evitare ConcurrentModificationException se viene modificata altrove
                        finalReports = new ArrayList<>(so.getAntivirusManager().getFinalReports());
                    }

                    // Aggiorna la UI sulla JavaFX Application Thread
                    final List<ScanReport> reportsToProcess = finalReports; // Final per lambda
                    Platform.runLater(() -> {
                        updateServiceStatus(scannerStatus, clamdStatus);
                        updateAVInfo(scannerStatus, reportsToProcess); // Passa i report recuperati
                        setupClamdStartupButtonAction(); // Aggiorna stato pulsante avvio auto
                    });

                    Thread.sleep(1000); // Intervallo di aggiornamento

                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    logger.info("Thread stopped - [startUpdateAVInfo()] AV info update thread interrupted.");
                    break; // Esci dal ciclo se interrotto
                } catch (Exception e) {
                    logger.error("Error during AV info update loop", e);
                    // Attendi un po' di più in caso di errore per evitare log flooding
                    try {
                        Thread.sleep(5000);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break; // Esci se interrotto durante l'attesa
                    }
                }
            }
            logger.info("AV info update thread finished.");
        };

        this.updateAVInfoThread = new Thread(task);
        this.updateAVInfoThread.setDaemon(true); // Permette all'applicazione di chiudersi anche se il thread è attivo
        this.updateAVInfoThread.setName("AV-Info-Updater");
        this.updateAVInfoThread.start();
    }

    /**
     * Ferma il thread di aggiornamento.
     */
    public void stopAVInfoUpdate() {
        if (this.updateAVInfoThread != null && this.updateAVInfoThread.isAlive()) {
            this.updateAVInfoThread.interrupt();
            try {
                // Attendi un breve periodo per permettere al thread di terminare
                this.updateAVInfoThread.join(1500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.warn("Interrupted while waiting for AV info update thread to stop.");
            }
            logger.info("AV info update thread stop requested.");
        }
    }

    /**
     * Aggiorna le informazioni AV, creando card con pulsanti basate sugli UUID.
     *
     * @param scannerStatus Lo stato corrente dello scanner.
     * @param reports La lista di report da processare (può essere null se
     * scannerStatus != UP).
     */
    private void updateAVInfo(runningStates scannerStatus, List<ScanReport> reports) {

        if (scannerStatus == runningStates.UP && reports != null) {

            long totalFiles = reports.size();
            long threatCount = reports.stream()
                    .filter(report -> report.getWarningClass() != null && !warningClass.CLEAR.equals(report.getWarningClass()))
                    .count();
            this.totalScannedLabel.setText(String.valueOf(totalFiles));
            this.threatsDetectedLabel.setText(String.valueOf(threatCount));

            List<FileCardComponent> cardsToAdd = new ArrayList<>();
            List<UUID> currentReportIds = reports.stream().map(ScanReport::getId).collect(Collectors.toList());

            Set<UUID> idsToRemove = new HashSet<>(displayedReportIds);
            idsToRemove.removeAll(currentReportIds);
            if (!idsToRemove.isEmpty()) {
                logger.debug("Removing {} outdated cards.", idsToRemove.size());
                idsToRemove.forEach(this::removeCardByReportIdInternal);
            }

            for (ScanReport report : reports) {
                UUID reportId = report.getId();

                if (!displayedReportIds.contains(reportId)) {
                    String fileName = report.getFile().getName();
                    String filePath = FileManager.getConfigValue("FOLDER_TO_SCAN_PATH") + File.separator + fileName;
                    warningClass wc = report.getWarningClass();
                    String status = wc.toString().toLowerCase();
                    //String hash = FileManager.calculateFileHash(report.getFile().getHash()); // Assicurati che il metodo getHash() restituisca un valore significativo
                    LocalDateTime scanTime = LocalDateTime.now();//DA MODIFICARE: //report.getScanTime(); // Usa il tempo dal report se disponibile, altrimenti usa LocalDateTime.now() come fallback

                    Button restoreButton = new Button("Restore");
                    Button deleteButton = new Button("Delete");
                    restoreButton.getStyleClass().add("action-button-restore");
                    deleteButton.getStyleClass().add("action-button-delete");

                    if (report.getWarningClass() != warningClass.CLEAR) {
                        boolean isInQuarantine = so.getAntivirusManager().isFileInQuarantine(report.getFile());
                        restoreButton.setDisable(!isInQuarantine);
                        deleteButton.setDisable(!isInQuarantine);

                        restoreButton.setOnAction(e -> operationOnFile("restore", report));
                        deleteButton.setOnAction(e -> operationOnFile("delete", report));
                    } else {
                        // if the file is CLEAR, disable the buttons and hide them
                        restoreButton.setVisible(false);
                        restoreButton.setManaged(false);
                        deleteButton.setVisible(false);
                        deleteButton.setManaged(false);
                    }

                    FileCardComponent card = new FileCardComponent(fileName, filePath, status, scanTime, wc);

                    try {
                        HBox actionBox = new HBox(10, restoreButton, deleteButton);
                        actionBox.setAlignment(Pos.CENTER_LEFT);
                        Pane spacer = new Pane();
                        HBox.setHgrow(spacer, Priority.ALWAYS);

                        if (!card.getChildren().isEmpty() && card.getChildren().get(0) instanceof HBox) {
                            HBox mainLayout = (HBox) card.getChildren().get(0);
                            if (restoreButton.isManaged() || deleteButton.isManaged()) {
                                mainLayout.getChildren().addAll(spacer, actionBox);
                            }
                        } else {
                            if (restoreButton.isManaged() || deleteButton.isManaged()) {
                                card.getChildren().add(actionBox);
                                logger.warn("Added action buttons directly to card root for {}, layout might be suboptimal.", fileName);
                            }
                        }

                    } catch (Exception ex) {
                        logger.error("Failed to add action buttons to card for {}. FileCardComponent structure might be incompatible.", fileName, ex);
                    }

                    cardsToAdd.add(card);
                    displayedReportIds.add(reportId);
                    reportIdToCardMap.put(reportId, card);
                }
            }

            if (!cardsToAdd.isEmpty()) {
                for (FileCardComponent card : cardsToAdd) {
                    if (!this.fileCardsContainer.getChildren().contains(card)) {
                        this.fileCardsContainer.getChildren().add(card);
                    }
                }
                //this.fileCardsContainer.getChildren().addAll(0, cardsToAdd);
                //this.fileCards.addAll(0, cardsToAdd);
                logger.debug("Added {} new file cards.", cardsToAdd.size());
            }

            // IMPLEMENTARE AGGIUNTA O RIMOZIONE CARD IN REALTIME BASATA SUL TESTO DI RICERCA
            /*
            String lowerCaseSearchText = (searchField.getText() == null) ? "" : searchField.getText().toLowerCase().trim();
            System.out.println("Lower case search text: " + lowerCaseSearchText);
            if (!lowerCaseSearchText.isEmpty()) {
                // Se la ricerca è vuota, mostra tutte le card presenti nella lista interna 'fileCards'
                for (FileCardComponent card : this.fileCards) {
                    String fileName = card.get; // Usa l'helper per estrarre il nome
                    // Aggiungi la card solo se il nome file non è nullo e contiene il testo di ricerca
                    if (!fileName.toLowerCase().contains(lowerCaseSearchText)) {
                        this.fileCardsContainer.getChildren().remove(card);
                    }
                }
            }
            */

        } else {
            if (!this.fileCardsContainer.getChildren().isEmpty()) {
                logger.info("Scanner is not UP or reports unavailable. Clearing file cards display.");
                this.fileCardsContainer.getChildren().clear();
                this.fileCards.clear();
                this.displayedReportIds.clear();
                this.reportIdToCardMap.clear();
                this.totalScannedLabel.setText("0");
                this.threatsDetectedLabel.setText("0");
            }
            // Potresti voler impostare uno stato specifico se reports è null ma lo scanner è UP
            if (scannerStatus == runningStates.UP && reports == null) {
                this.currentStatusLabel.setText("In attesa di report...");
            }
        }
    }

    /**
     * Esegue un'operazione (ripristino o eliminazione) su un file associato a
     * un report. Usa l'UUID del report per identificare la card da rimuovere in
     * caso di successo.
     *
     * @param actionType Tipo di azione ("restore" o "delete").
     * @param report Il report di scansione relativo al file.
     */
    private void operationOnFile(String actionType, ScanReport report) {
        UUID reportId = report.getId();
        String filePath = report.getFile().getAbsolutePath(); // Il path è ancora utile per l'azione effettiva
        logger.info("Action requested: {} on file: {} (Report ID: {})", actionType, filePath, reportId);

        boolean success = false;
        if ("restore".equals(actionType)) {
            success = so.getAntivirusManager().restoreFileFromQuarantine(report); // Passa il File object
            if (success) {
                logger.info("File restored successfully: {}", filePath); 
            }else {
                logger.error("Failed to restore file: {}", filePath);
            }
        } else if ("delete".equals(actionType)) {
            success = so.getAntivirusManager().deleteFileFromQuarantine(report); // Passa il File object
            if (success) {
                logger.info("File deleted successfully: {}", filePath); 
            }else {
                logger.error("Failed to delete file: {}", filePath);
            }
        }

        if (success) {
            // Rimuovi la card associata a questo report usando l'UUID
            removeCardByReportId(reportId);
            // Aggiorna i conteggi dopo la rimozione (opzionale, dipende se vuoi che i conteggi riflettano solo i file VISUALIZZATI)
            // updateThreatCountAfterAction();
        } else {
            // Mostra un messaggio di errore all'utente (es. usando un Alert)
            showOperationErrorAlert(actionType, filePath);
        }
    }

    /**
     * Rimuove una card dall'UI e dalle strutture dati interne usando l'UUID del
     * report. Questo metodo esegue l'operazione sulla UI thread.
     *
     * @param reportId L'UUID del report la cui card deve essere rimossa.
     */
    private void removeCardByReportId(UUID reportId) {
        Platform.runLater(() -> removeCardByReportIdInternal(reportId));
    }

    /**
     * Logica interna per rimuovere la card. Deve essere chiamata dalla UI
     * thread.
     *
     * @param reportId L'UUID del report la cui card deve essere rimossa.
     */
    private void removeCardByReportIdInternal(UUID reportId) {
        FileCardComponent cardToRemove = reportIdToCardMap.get(reportId);

        if (cardToRemove != null) {
            boolean removedFromUI = fileCardsContainer.getChildren().remove(cardToRemove);
            boolean removedFromList = fileCards.remove(cardToRemove);
            reportIdToCardMap.remove(reportId); // Rimuovi dalla mappa
            displayedReportIds.remove(reportId); // Rimuovi dal set di tracciamento

            if (removedFromUI && removedFromList) {
                logger.info("Removed card for report ID: {}", reportId);
            } else {
                logger.warn("Card for report ID {} removed from map/set, but removal from UI ({}) or internal list ({}) failed.",
                        reportId, removedFromUI, removedFromList);
            }
            // Potresti voler aggiornare i conteggi qui se necessario
            // updateThreatCountAfterAction();

        } else {
            logger.warn("Attempted to remove card for report ID {}, but it was not found in the map.", reportId);
            // Potrebbe essere già stata rimossa, o mai aggiunta correttamente.
            // Rimuovi comunque l'ID dal set per sicurezza, se presente.
            displayedReportIds.remove(reportId);
        }
    }

    /**
     * Mostra un popup di errore all'utente.
     *
     * @param actionType L'azione fallita ("restore" o "delete").
     * @param filePath Il percorso del file coinvolto.
     */
    private void showOperationErrorAlert(String actionType, String filePath) {
        Platform.runLater(() -> {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Errore Operazione");
            alert.setHeaderText("Impossibile completare l'azione: " + actionType);
            alert.setContentText("Si è verificato un errore durante il tentativo di "
                    + (actionType.equals("restore") ? "ripristinare" : "eliminare")
                    + " il file:\n" + filePath
                    + "\n\nControlla i log per maggiori dettagli.");
            alert.showAndWait();
        });
    }

    /**
     * Aggiorna lo stato del servizio antivirus e dello scanner. Cambia il
     * colore dell'indicatore di stato e aggiorna le etichette in base allo
     * stato corrente dei servizi.
     *
     * @param scannerStatus Lo stato corrente dello scanner.
     * @param clamdStatus Lo stato corrente del servizio Clamd.
     */
    private void updateServiceStatus(runningStates scannerStatus, runningStates clamdStatus) {
        statusIndicator.getStyleClass().removeAll("active", "inactive");
        currentStatusLabel.getStyleClass().add("status-indicator");

        switch (clamdStatus) {
            case UP:
                this.statusIndicator.getStyleClass().add("active");
                this.avStatusLabel.setText("Clamd service is running");

                if (scannerStatus == runningStates.UP) {
                    this.currentStatusLabel.setText("Active");
                } else {
                    this.currentStatusLabel.setText("Waiting VPN");
                }
                break;

            case DOWN:
                this.statusIndicator.getStyleClass().add("inactive");
                this.avStatusLabel.setText("Clamd service is not running");
                this.currentStatusLabel.setText("Inactive");
                break;

            default: // UNKNOWN o altri stati
                this.statusIndicator.getStyleClass().add("inactive");
                this.avStatusLabel.setText("Service status unknown");
                this.currentStatusLabel.setText("Indeterminated");
                break;
        }
    }

    /**
     * Configura l'azione del pulsante per abilitare/disabilitare l'avvio
     * automatico di Clamd. (Invariato)
     */
    private void setupClamdStartupButtonAction() {
        this.startScanButton.setOnAction(event -> {
            try {
                boolean currentSetting = Boolean.parseBoolean(FileManager.getConfigValue("CLAMD_SERVICE_AUTOMATIC_STARTUP")); // Default a false
                boolean newSetting = !currentSetting;
                FileManager.setConfigValue("CLAMD_SERVICE_AUTOMATIC_STARTUP", String.valueOf(newSetting));
                logger.info("Clamd automatic startup set to: {}", newSetting);
                updateClamdStartupButtonState(); // Aggiorna immediatamente lo stato del pulsante
            } catch (Exception e) {
                logger.error("Failed to toggle Clamd automatic startup setting", e);
                // Mostra errore all'utente?
                showOperationErrorAlert("configurazione avvio automatico", "impostazioni Clamd");
            }
        });
        // Aggiorna lo stato iniziale del pulsante
        updateClamdStartupButtonState();
    }

    /**
     * Aggiorna testo, icona e stile del pulsante di avvio automatico Clamd.
     * (Invariato)
     */
    private void updateClamdStartupButtonState() {
        try {
            // Leggi l'impostazione corrente, fornendo un default "false" se non trovata o errata
            boolean isEnabled = Boolean.parseBoolean(FileManager.getConfigValue("CLAMD_SERVICE_AUTOMATIC_STARTUP"));
            FontIcon icon = null;
            // Cerca l'icona solo se il pulsante ha un graphic e se è un FontIcon
            if (this.startScanButton.getGraphic() instanceof FontIcon) {
                icon = (FontIcon) this.startScanButton.getGraphic();
            } else {
                // Se non c'è icona o non è del tipo giusto, potresti crearne una nuova
                // icon = new FontIcon();
                // this.startScanButton.setGraphic(icon);
                // logger.warn("Start scan button graphic is not a FontIcon or is null. Attempting to fix.");
                // Per ora, logghiamo solo se non è un FontIcon
                if (this.startScanButton.getGraphic() != null) {
                    logger.warn("Start scan button graphic is not a FontIcon: {}", this.startScanButton.getGraphic().getClass().getName());
                }
            }

            if (isEnabled) {
                this.startScanButton.setText("On Startup: ON");
                if (icon != null) {
                    icon.setIconLiteral("fas-toggle-on"); // Usa FontAwesome sintassi
                    icon.setIconColor(Color.GREEN); // Esempio colore
                }
                // Rimuovi la classe 'disabled' e aggiungi 'enabled' per lo stile CSS
                this.startScanButton.getStyleClass().remove("button-disabled");
                this.startScanButton.getStyleClass().add("button-enabled");
            } else {
                this.startScanButton.setText("On Startup: OFF");
                if (icon != null) {
                    icon.setIconLiteral("fas-toggle-off");
                    icon.setIconColor(Color.RED); // Esempio colore
                }
                // Rimuovi la classe 'enabled' e aggiungi 'disabled'
                this.startScanButton.getStyleClass().remove("button-enabled");
                this.startScanButton.getStyleClass().add("button-disabled");
            }
            // Assicurati che il pulsante sia abilitato per permettere il click
            this.startScanButton.setDisable(false);

        } catch (Exception e) {
            logger.error("Failed to update Clamd startup button state from config", e);
            this.startScanButton.setText("Errore Config");
            this.startScanButton.setDisable(true); // Disabilita se c'è errore nel leggere/scrivere config
            if (this.startScanButton.getGraphic() instanceof FontIcon) {
                ((FontIcon) this.startScanButton.getGraphic()).setIconLiteral("fas-exclamation-triangle");
                ((FontIcon) this.startScanButton.getGraphic()).setIconColor(Color.ORANGERED);
            }
            this.startScanButton.setTooltip(new Tooltip("Impossibile leggere/scrivere la configurazione per l'avvio automatico."));
        }
    }

    /* GENERAL PURPOSE METHODS */
    private void stopAllThreads() {

        try {
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

        } catch (InterruptedException e) {
            logger.error("Error stopping all threads: ", e);
        }
    }
}
