package com.wireshield.ui;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.wireshield.av.FileManager;
import com.wireshield.av.ScanReport;
import com.wireshield.enums.connectionStates;
import com.wireshield.enums.runningStates;
import com.wireshield.enums.vpnOperations;
import com.wireshield.localfileutils.SystemOrchestrator;
import com.wireshield.windows.WFPManager;
import com.wireshield.wireguard.Connection;
import com.wireshield.wireguard.Peer;
import com.wireshield.wireguard.PeerManager;
import com.wireshield.wireguard.WireguardManager;

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
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.stage.WindowEvent;

public class UserInterface extends Application implements PeerOperationListener{

    private static final Logger logger = LogManager.getLogger(UserInterface.class);
    
    protected static SystemOrchestrator so;
    protected static WireguardManager wg;

    protected String selectedPeer;
    private Thread logUpdateThread;

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
    	
        viewHome();
        loadPeersFromPath();
        updatePeerList();
        
        // to be updated
        setDynamicLogUpdate();
        startDynamicConnectionLogsUpdate();

        if (vpnButton.getText().equals("Start VPN")) {
            vpnButton.setDisable(true);
        }

        logger.info("UI initialized successfully");
    }

    public static void main(String[] args) {
    	
    	//System.setProperty("prism.lcdtext", "true");
    	//System.setProperty("prism.text", "gray");
    	
        so = SystemOrchestrator.getInstance();
        wg = so.getWireguardManager();
        
        so.manageVPN(vpnOperations.STOP, null);
        
        launch(args);
    }

    @FXML
    public void closeWindow(WindowEvent windowevent) {
    	so.manageDownload(runningStates.DOWN);
        so.manageAV(runningStates.DOWN);
        so.manageVPN(vpnOperations.STOP, null);
        
        // add function to wait all threads stops
        
        System.exit(0);
    }
    
    /**
     * Toggles the VPN connection state. If the VPN is currently connected, stops all services
     * (VPN, antivirus, and download manager). If disconnected, starts all services using the
     * selected peer configuration.
     * Updates the UI to reflect the current state.
     */
    @FXML
    public void changeVPNState() {
        if (so.getConnectionStatus() == connectionStates.CONNECTED) {
            
            so.setGuardianState(runningStates.DOWN);
            so.manageDownload(runningStates.DOWN);
            so.manageAV(runningStates.DOWN);

            so.manageVPN(vpnOperations.STOP, null);
            while (so.getConnectionStatus() == connectionStates.CONNECTED) {
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    logger.error("Thread interrupted while waiting for VPN disconnection.");
                }
            }

            vpnButton.setText("Start VPN");
            logger.info("All services are stopped.");
            
            // Disable vpnButton if selected peer is been deleted
            Peer[] peers = wg.getPeerManager().getPeers();
            Peer p = wg.getPeerManager().getPeerByName(this.selectedPeer);
            if(!Arrays.asList(peers).contains(p)) {
            	vpnButton.setDisable(true);
            }
            
        } else {
            vpnButton.setDisable(true);

            so.manageVPN(vpnOperations.START, this.selectedPeer);
            while (so.getConnectionStatus() == connectionStates.DISCONNECTED) {
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    logger.error("Thread interrupted while waiting for VPN connection.");
                }
            }
            so.getWireguardManager().startUpdateConnectionStats();

            so.manageAV(runningStates.UP);
            so.manageDownload(runningStates.UP);
            so.statesGuardian();

            vpnButton.setDisable(false);
            vpnButton.setText("Stop VPN");
            logger.info("All services started successfully.");
        }
    }

    @FXML
    public void viewHome() {
        this.stopDynamicLogUpdate();
        homePane.toFront();
    }

    @FXML
    public void viewLogs() {
        if(logUpdateThread != null && !logUpdateThread.isAlive()){
            this.startDynamicLogUpdate();
        }
        logsPane.toFront();
    }

    @FXML
    public void viewAv() {
        this.stopDynamicLogUpdate();

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

    /**
     * Handles the selection and import of WireGuard configuration files.
     * Opens a file chooser dialog for the user to select a .conf file, copies it to the
     * peer directory, and updates the peer list in the UI.
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
                WFPManager.createCIDRFile(defaultPeerPath, peerNameWithoutExtension);
                
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
     * Loads peer configurations from the specified folder path.
     * Resets the current peer list and rebuilds it by parsing each configuration file.
     * Peer objects are created based on the parsed configuration data.
     */
    private void loadPeersFromPath() {
        File directory = new File(defaultPeerPath);
        
        System.out.println("Loading peers from path: " + defaultPeerPath);

        wg.getPeerManager().resetPeerList();
        
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
                    	wg.getPeerManager().createPeer(dataMap, file.getName());
                    }
                }
                logger.info("Peer cards updated successfully");
            }
        }
        else
        {
        	logger.warn("Peer directory does not exist or is not a directory: {}", defaultPeerPath);
        }
    	
    }
    
    /**
     * Handles the deletion of a peer from the system. Removes the peer from the peer manager
     * and deletes its configuration file from the filesystem. Updates the UI accordingly
     * to reflect the deletion.
     *
     * @param peer The peer object that needs to be deleted
     */
	public void onPeerDeleted(Peer peer) {
		wg.getPeerManager().removePeer(peer.getId());

        String peerName = peer.getName();
		
		File file = new File(defaultPeerPath + "/" + peerName);		
		if (file.isFile()) {
			file.delete();
		}


        System.out.println("Peer deleted: " + peerName);
        String peerNameWithoutExtension = peerName.contains(".") ? peerName.substring(0, peerName.lastIndexOf(".")) : peerName;
        WFPManager.deleteCIDRFile(defaultPeerPath, peerNameWithoutExtension);

        Platform.runLater(() -> {
            
        	updatePeerList();
            
        	if(so.getConnectionStatus() == connectionStates.DISCONNECTED) {
        		vpnButton.setDisable(true);
        	}
        });
	}
    
    /**
     * Handles the peer modification process by opening the peer configuration file
     * in an external editor. After the editor is closed, it refreshes the peer list
     * and updates the peer information displayed in the UI.
     *
     * @param peer The peer object that needs to be modified
     */
    public void onPeerModified(Peer peer) {
	    File configFile = new File(defaultPeerPath + "/" + peer.getName());

        Thread editorThread = new Thread(() -> {
	        try {
	            ProcessBuilder processBuilder = new ProcessBuilder("notepad.exe", configFile.getAbsolutePath());	            
	            Process process = processBuilder.start();

                // Create a shutdown hook
                Thread hookThread = new Thread(() -> {
                    if (process.isAlive()) {
                        process.destroy();
                    }
                });

                // Add a shutdown hook to ensure the process is terminated when the application exits.
                // When process terminate, the ShutdownHook is removed (no more needed).
                Runtime.getRuntime().addShutdownHook(hookThread);
	            
	            process.waitFor();

                Runtime.getRuntime().removeShutdownHook(hookThread);
	            
	            Platform.runLater(() -> {
	            	loadPeersFromPath();
	            	updatePeerList();
	            	
	            	selectedPeer = peer.getName();
	    	            	
	                Peer updatedPeer = wg.getPeerManager().getPeerByName(peer.getName());
	                if (updatedPeer != null) {

	                	VBox existingContainer = null;
	                    for (javafx.scene.Node node : homePane.getChildren()) {
	                        if (node instanceof VBox && node.getStyleClass().contains("peerInfo-container")) {
	                            existingContainer = (VBox) node;
	                            break;
	                        }
	                    }
	                    
	                    if (existingContainer != null) {
	                        fillPeerInfoContainer(updatedPeer, existingContainer);
	                    }
	                }
	                
                    for (javafx.scene.Node node : peerCardsContainer.getChildren()) {
                        if (node instanceof VBox peerCard) {
                            for (javafx.scene.Node cardChild : peerCard.getChildren()) {
                                if (cardChild instanceof Label cardLabel && 
                                    cardLabel.getStyleClass().contains("peer-card-text-name") && 
                                    cardLabel.getText().equals(selectedPeer)) {
                                    peerCard.getStyleClass().add("selected");
                                    break;
                                }
                            }
                        }
                    }
	            });
	            
	        } catch (IOException | InterruptedException e) {
	            e.printStackTrace();
	        }
	    });

        editorThread.setDaemon(true);
        editorThread.start();
	}
    
    /**
     * Populates the specified container with detailed information about the peer.
     * Loads the peerInfo.fxml template and configures its controller with the
     * provided peer data.
     *
     * @param peer The peer object containing the data to display
     * @param peerInfoContainer The VBox container where peer information will be shown
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

            if (!homePane.getChildren().contains(peerInfoContainer)) {
            	homePane.getChildren().add(peerInfoContainer);
            }
            
        } catch (Exception e) {
            logger.error("Error during peerInfo pannel initialization: " + e.getMessage(), e);
        }
    }
    
    /**
     * Creates a new VBox container for displaying peer information.
     * Sets its style class and preferred dimensions.
     * Anchors it to the specified position within the home pane.
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
     * Handles peer selection events when a peer card is clicked.
     * Updates the UI to reflect the selected peer, enables the VPN button if appropriate,
     * and displays detailed information about the selected peer.
     *
     * @param peer The peer that was selected
     * @param peerCard The VBox representing the peer card in the UI that was clicked
     */
    private void onClickOperation(Peer peer, VBox peerCard) {
    	
    	peerCardsContainer.getChildren().forEach(node -> node.getStyleClass().remove("selected"));
        peerCard.getStyleClass().add("selected");
    	
    	// Connection Container Logic
        selectedPeer = peer.getName();
        
        if (vpnButton.getText().equals("Start VPN")) {
        	vpnButton.setDisable(false);
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
        
        fillPeerInfoContainer(peer, peerInfoContainer);
        
        logger.info("Selected peer file: {}", selectedPeer);
    }

    /**
     * Updates the list of peers displayed in the UI.
     * Clears and repopulates the peer cards container with current peer data.
     * Each card displays the peer name and endpoint address, and is clickable to select that peer.
     * This method is called after any changes to the peer configurations.
     */
    protected void updatePeerList() {
    	
        if (peerCardsContainer == null) {
            logger.error("peerCardsContainer is null");
            return;
        }
        
        peerCardsContainer.getChildren().clear();
        
        for (Peer peer : wg.getPeerManager().getPeers()) {
        	VBox peerCard = new VBox();
            peerCard.getStyleClass().add("peer-card");
            
            Label peerName = new Label(peer.getName());
            Label peerAddr = new Label(peer.getEndPoint());
            
            peerName.getStyleClass().add("peer-card-text-name");
            peerAddr.getStyleClass().add("peer-card-text-address");   
            
            peerCard.getChildren().add(peerName);
            peerCard.getChildren().add(peerAddr);
            
            peerCard.setOnMouseClicked(event -> onClickOperation(peer, peerCard));
            
            peerCardsContainer.getChildren().add(peerCard);
            
            logger.debug("Added peer card for file: {}", peer.getName());
        }
    }
    
    /**
     * Starts a background thread that periodically updates the log display area.
     * Retrieves the latest logs from the WireGuard manager and updates the UI
     * while preserving the current scroll position.
     * This thread runs as a daemon to ensure it's terminated when the application closes.
     */
    protected void setDynamicLogUpdate() {

        logUpdateThread = new Thread(() -> {
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
        });

        logUpdateThread.setDaemon(true);
    }

    protected void startDynamicLogUpdate() {
        if (logUpdateThread.isInterrupted()) {
            setDynamicLogUpdate();
        }
        logUpdateThread.start();
    }

    protected void stopDynamicLogUpdate() {

        if (logUpdateThread != null && logUpdateThread.isAlive()) {
            logUpdateThread.interrupt();
        }
    }


    /**
     * Starts a background thread that periodically updates the connection information displayed in the UI.
     * Updates various UI elements with real-time connection data such as:
     * - Active interface name
     * - Connection status with appropriate color indication
     * - Sent and received traffic data with appropriate formatting
     * - Time since the last handshake occurred
     * 
     * This thread runs as a daemon to ensure it's terminated when the application closes.
     * Updates occur at 1-second intervals to provide near real-time feedback.
     */
    protected void startDynamicConnectionLogsUpdate() {

        Thread connectionLogThread = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Platform.runLater(() -> {
                    	                    	
                    	connStatusLabel.setText("");
                    	if(so.getConnectionStatus() == connectionStates.CONNECTED) {

                    		connStatusLabel.setText("● Connected");
                    		connStatusLabel.setStyle("-fx-text-fill: #DAF7A6");

                            String interf = so.getWireguardManager().getConnection().getActiveInterface();
                            if(interf == null) {
                            	connInterfaceLabel.setText("interface: --");
                            } else {
                            	connInterfaceLabel.setText("interface: " + interf);
                            }
                            
                            // Transmission                    	
                    	    sentTrafficLable.setText(Connection.formatBytes(so.getWireguardManager().getConnection().getSentTraffic()));
                    	    receivedTrafficLabel.setText(Connection.formatBytes(so.getWireguardManager().getConnection().getReceivedTraffic()));
                    	
                    	    // HandShake
                    	    lastHandshakeTimeLabel.setText(TimeUtil.getTimeSinceHandshake(so.getWireguardManager().getConnection().getLastHandshakeTime()));

                    	} else {
                    		connStatusLabel.setText("● Disconnected");
                    		connStatusLabel.setStyle("-fx-text-fill: #FF5733");

                            connInterfaceLabel.setText("interface: --");

                            if (!sentTrafficLable.getText().equals("0")){
                                sentTrafficLable.setText("0");
                            }
                            if (!receivedTrafficLabel.getText().equals("0")){
                                receivedTrafficLabel.setText("0");
                            }
                            if (!lastHandshakeTimeLabel.getText().equals("--")){
                                lastHandshakeTimeLabel.setText("--");
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
        });

        connectionLogThread.setDaemon(true);
        connectionLogThread.start();
    }

}