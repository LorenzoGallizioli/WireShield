package com.wireshield.ui;
import com.wireshield.av.FileManager;
import com.wireshield.av.ScanReport;
import com.wireshield.enums.connectionStates;
import com.wireshield.enums.runningStates;
import com.wireshield.enums.vpnOperations;
import com.wireshield.localfileutils.SystemOrchestrator;
import com.wireshield.wireguard.Connection;
import com.wireshield.wireguard.Peer;
import com.wireshield.wireguard.PeerManager;
import com.wireshield.wireguard.WireguardManager;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

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
import javafx.stage.WindowEvent;
import javafx.scene.control.ListView;

public class UserInterface extends Application implements PeerDeletionListener{

    private static final Logger logger = LogManager.getLogger(UserInterface.class);
    protected static SystemOrchestrator so;
    protected static WireguardManager wg;
    protected String selectedPeer;
    private static double xOffset = 0;
    private static double yOffset = 0;
    
    String folderPath = FileManager.getProjectFolder() + FileManager.getConfigValue("PEER_STD_PATH");

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
        startDynamicConnectionLogsUpdate();
        startDynamicLogUpdate();

        if (vpnButton.getText().equals("Start VPN")) {
            vpnButton.setDisable(true);
        }

        logger.info("UI initialized successfully");
    }

    public static void main(String[] args) {
    	
    	System.setProperty("prism.lcdtext", "true");
    	System.setProperty("prism.text", "gray");
    	
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
    public void closeWindow(WindowEvent windowevent) {
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
            so.manageVPN(vpnOperations.START, selectedPeer);
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
    
    private void loadPeersFromPath() {
        File directory = new File(folderPath);
        
        wg.getPeerManager().resetPeerList();
        
        if (directory.exists() && directory.isDirectory()) {
            File[] files = directory.listFiles();
            
            if (files != null) {
                for (File file : files) {
                    if (file.isFile() && file.length() > 0) {
                    	
                        Scanner scanner = null;
                        String data = "";
						try {
							scanner = new Scanner(file);
						} catch (FileNotFoundException e) {
							// TODO Auto-generated catch block
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
        	logger.warn("Peer directory does not exist or is not a directory: {}", folderPath);
        }
    	
    }
    
    @Override
	public void onPeerDeleted(Peer peer) {
		// TODO Auto-generated method stub
		wg.getPeerManager().removePeer(peer.getId());
		
		File file = new File(folderPath + "/" + peer.getName());		
		if (file.isFile()) {
			file.delete();
		}

		// Aggiorna l'interfaccia
        Platform.runLater(() -> {
            
        	loadPeersFromPath();
        	updatePeerList();
            
            // Disabilita il pulsante VPN se necessario
            vpnButton.setDisable(true);
            vpnButton.setText("Start VPN");
        });
	}
    
    private void fillPeerInfoContainer(VBox container, Peer peer) {
        try {
            // Pulisci il container prima di aggiungere nuovi elementi
            container.getChildren().clear();
            
            // Carica il file FXML
            FXMLLoader loader = new FXMLLoader(getClass().getResource("peerInfo.fxml"));
            javafx.scene.Node newContent = loader.load();
            
            // Ottieni il controller e passa i dati del peer
            PeerInfoController controller = loader.getController();
            controller.setPeer(peer);
            controller.setDeletionListener(this);
            
            // Aggiungi il contenuto al container
            container.getChildren().add(newContent);

			// Aggiungi il container alla scena se non è già presente
            if (!homePane.getChildren().contains(container)) {
            	homePane.getChildren().add(container);
            }
            
        } catch (Exception e) {
            logger.error("Errore nel caricamento del pannello informazioni peer: " + e.getMessage(), e);
        }
    }
    
    private VBox createPeerInfoContainer() {
    	
    	double xOffset = 740.0;
    	double yOffset = 400.0;
    	double leftAnchor = 320.0;
    	double topAnchor = 165.0;
    	
    	VBox peerInfo = new VBox();
    	
    	peerInfo.getStyleClass().add("peerInfo-container");
    	peerInfo.setPrefWidth(xOffset);
    	peerInfo.setPrefHeight(yOffset);
    	AnchorPane.setLeftAnchor(peerInfo, leftAnchor);
        AnchorPane.setTopAnchor(peerInfo, topAnchor);
        
        return peerInfo;
    }

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
            
            peerCard.setOnMouseClicked(event -> {
            	
            	// Connection Container Logic
                selectedPeer = peer.getName();
                
                peerCardsContainer.getChildren().forEach(node -> node.getStyleClass().remove("selected"));
                peerCard.getStyleClass().add("selected");
                
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
                
                // Se non esiste, creane uno nuovo
                VBox peerInfoContainer = existingContainer != null ? existingContainer : createPeerInfoContainer();
                
                // Riempi il container con le informazioni del peer
                fillPeerInfoContainer(peerInfoContainer, peer);
                
                logger.info("Selected peer file: {}", selectedPeer);
            });
            
            peerCardsContainer.getChildren().add(peerCard);
            
            logger.debug("Added peer card for file: {}", peer.getName());
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
                    Platform.runLater(() -> {
                    	
                        // Connected Interface
                    	connInterfaceLabel.setText("interface: " + wg.getConnection().getActiveInterface());
                    	
                    	// Connection Status
                    	connStatusLabel.setText("");
                    	if(wg.getConnection().getStatus() == connectionStates.CONNECTED) {
                    		connStatusLabel.setText("● Connected");
                    		connStatusLabel.setStyle("-fx-text-fill: #DAF7A6");
                    	} else {
                    		connStatusLabel.setText("● Disconnected");
                    		connStatusLabel.setStyle("-fx-text-fill: #FF5733");
                    	}
                    	
                        // Transmission                    	
                    	sentTrafficLable.setText(Connection.formatBytes(wg.getConnection().getSentTraffic()));
                    	receivedTrafficLabel.setText(Connection.formatBytes(wg.getConnection().getReceivedTraffic()));
                    	
                    	// HandShake
                    	lastHandshakeTimeLabel.setText(TimeUtil.getTimeSinceHandshake(wg.getConnection().getLastHandshakeTime()));
                        
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