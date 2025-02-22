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
import javafx.scene.control.ComboBox;
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

/**
 * The main user interface class for the Wireshield application, implemented
 * using JavaFX. This class handles the initialization, layout, and interaction
 * of UI components such as buttons, labels, and panes. It also provides methods
 * for managing the VPN state, updating logs, and interacting with peer
 * configuration files.
 */
public class UserInterface extends Application {

	// Logger for recording application events.
	private static final Logger logger = LogManager.getLogger(UserInterface.class);

	// Singleton instances for system orchestration and WireGuard management.
	protected static SystemOrchestrator so;
	protected static WireguardManager wg;

	// JavaFX Buttons.
	@FXML
	protected Button vpnButton;

	// JavaFX Labels.
	@FXML
	protected Label avStatusLabel;
	@FXML
	protected Label connLabel;

	// JavaFX AnchorPanes.
	@FXML
	protected AnchorPane homePane;
	@FXML
	protected AnchorPane logsPane;
	@FXML
	protected AnchorPane avPane;

	// JavaFX TextAreas.
	@FXML
	protected TextArea logsArea;
	@FXML
	protected TextArea avFilesArea;

	// JavaFX HBox Buttons.
	@FXML
	protected Button minimizeButton;
	@FXML
	protected Button closeButton;

    /**
     * JavaFX ListViews.
     */
    @FXML
    protected ComboBox<String> peerComboBox;
    protected ObservableList<String> peerList = FXCollections.observableArrayList();
    @FXML
    protected ListView<String> avFilesListView;
    protected ObservableList<String> avFilesList = FXCollections.observableArrayList();
    protected String selectedPeerFile; // Memorize the selected peer file.
    private static double xOffset = 0;
    private static double yOffset = 0;

	/**
	 * Entry point for launching the JavaFX application. This method loads the main
	 * FXML layout, applies styles, and displays the primary stage.
	 *
	 * @param primaryStage the main stage for the application.
	 */
	@Override
	public void start(Stage primaryStage) {
		try {
			FXMLLoader loader = new FXMLLoader(getClass().getResource("MainView.fxml"));
			Parent root = loader.load();
			Scene scene = new Scene(root);
			scene.getStylesheets().add(getClass().getResource("styles.css").toExternalForm());

			// Configure stage appearance
			primaryStage.initStyle(StageStyle.UNDECORATED);
			primaryStage.setTitle("Wireshield");
			primaryStage.setScene(scene);
			primaryStage.show();

            // Aggiungi eventi per trascinare la finestra
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

	/**
	 * Initializes the user interface and its components. Sets up event listeners,
	 * initializes lists, and configures UI behavior based on the current state of
	 * the application.
	 */
	@FXML
	public void initialize() {
		viewHome(); // Show the home pane on startup
		updatePeerList(); // Populate the peer list from available files
		startDynamicConnectionLogsUpdate(); // Start updating the connection logs dynamically
		startDynamicLogUpdate(); // Start updating the general logs dynamically

		// Disable the peer list if the VPN is currently connected
		peerComboBox.setDisable(so.getConnectionStatus() == connectionStates.CONNECTED);

        // Disabilita il pulsante solo se il testo è "Start VPN" e non è selezionato alcun file
        if (vpnButton.getText().equals("Start VPN")) {
            vpnButton.setDisable(true);
        }

        peerComboBox.setItems(peerList);
        peerComboBox.getSelectionModel().selectedItemProperty().addListener((observable, oldValue, newValue) -> {
            if (newValue != null) {
                selectedPeerFile = newValue; // Memorizza il file selezionato
                if (vpnButton.getText().equals("Start VPN")) {
                    vpnButton.setDisable(false); // Abilita il pulsante solo se il testo è "Start VPN"
                }
                logger.info("File selezionato nella peer list: {}", selectedPeerFile);
            } else {
                if (vpnButton.getText().equals("Start VPN")) {
                    vpnButton.setDisable(true); // Disabilita il pulsante solo se non c'è selezione e il testo è "Start VPN"
                }
                logger.info("Nessun file selezionato.");
            }
        });
    
    
        if (avFilesListView != null) {
            avFilesListView.setItems(avFilesList);
        }
    }
    

	/**
	 * Launches the Wireshield application.
	 *
	 * @param args command-line arguments.
	 */
	public static void main(String[] args) {
		// Initialize the system orchestrator and stop any running VPN on startup
		so = SystemOrchestrator.getInstance();
		so.manageVPN(vpnOperations.STOP, null);
		wg = so.getWireguardManager();
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
	 * Closes the application window and stops all running services.
	 */
	@FXML
	public void closeWindow() {
		Stage stage = (Stage) closeButton.getScene().getWindow();
		stage.close();

		// Stop all background services
		so.manageDownload(runningStates.DOWN);
		so.manageAV(runningStates.DOWN);
		so.manageVPN(vpnOperations.STOP, null);
		System.exit(0);
	}

	/**
	 * Toggles the state of the VPN between connected and disconnected.
	 */
	@FXML
	public void changeVPNState() {

		if (so.getConnectionStatus() == connectionStates.CONNECTED) {
			// Stop execution componentStatesGuardian thread
        	so.setGuardianState(runningStates.DOWN);

			so.manageDownload(runningStates.DOWN);
			so.manageAV(runningStates.DOWN);
			so.manageVPN(vpnOperations.STOP, null);
			vpnButton.setText("Start VPN");
			peerComboBox.setDisable(false); // Enable the peer list when the VPN is disconnected
			logger.info("All services are stopped.");
		} else {
			so.manageVPN(vpnOperations.START, selectedPeerFile);
			so.manageAV(runningStates.UP);
			so.manageDownload(runningStates.UP);
			
			// Start execution componentStatesGuardian thread
			so.statesGuardian();

			vpnButton.setText("Stop VPN");
			peerComboBox.setDisable(true); // Disable the peer list while the VPN is connected
			logger.info("All services started successfully.");
		}
	}

	/**
	 * Displays the home pane and updates the peer list.
	 */
	@FXML
	public void viewHome() {
		homePane.toFront();
		updatePeerList();
	}

	/**
	 * Displays the logs pane.
	 */
	@FXML
	public void viewLogs() {
		logsPane.toFront();
		logger.info("Viewing logs...");
	}

	/**
	 * Displays the antivirus pane and populates the file list if antivirus is
	 * running.
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

	/**
	 * Copies the selected peer configuration file to the application's peer
	 * directory.
	 *
	 * @param selectedFile the file to be copied.
	 */
	protected void updatePeerList() {
		String folderPath = FileManager.getProjectFolder() + FileManager.getConfigValue("PEER_STD_PATH");
		File directory = new File(folderPath);

		if (directory.exists() && directory.isDirectory()) {
			File[] files = directory.listFiles();
			if (files != null) {
				peerList.clear(); // Clear the current list
				for (File file : files) {
					if (file.isFile() && file.length() > 0) {
						peerList.add(file.getName()); // Add the file name to the list
						logger.debug("File added to peer list: {}", file.getName());
						logger.info("Peer list updated.");
					}
				}
			}
		}
	}

	/**
	 * Updates the peer list by reading configuration files from the peer directory.
	 */
	protected void startDynamicLogUpdate() {
		Runnable task = () -> {
			while (!Thread.currentThread().isInterrupted()) {
				try {
					// Retrieve updated logs
					String logs = wg.getLog();
					// Update logsArea on the JavaFX thread
					Platform.runLater(() -> {
						double scrollPosition = logsArea.getScrollTop();
						logsArea.clear();
						logsArea.setText(logs);
						logsArea.setScrollTop(scrollPosition);
					});
					Thread.sleep(1000); // Wait one second before updating again
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					logger.error("Dynamic log update thread interrupted.");
				} catch (Exception e) {
					Thread.currentThread().interrupt();
					logger.error("Error updating logs dynamically: ", e);
				}
			}
		};

        Thread Thread = new Thread(task);
        Thread.start();
    }

	/**
	 * Starts a background thread to dynamically update the logs area.
	 */
	protected void startDynamicConnectionLogsUpdate() {
		Runnable task = () -> {
			while (!Thread.currentThread().isInterrupted()) {
				try {
					// Retrieve updated logs
					String logs = wg.getConnectionLogs();
					// Update logsArea on the JavaFX thread
					Platform.runLater(() -> {
						connLabel.setText("");
						connLabel.setText(logs);
					});
					Thread.sleep(1000); // Wait one second before updating again
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					logger.error("Dynamic connection logs update thread interrupted.");
				} catch (Exception e) {
					Thread.currentThread().interrupt();
					logger.error("Error updating connection logs: ", e);
				}
			}
		};

		Thread logUpdateThread = new Thread(task);
		logUpdateThread.setDaemon(true); // Ensure the thread stops with the application
		logUpdateThread.start();
	}
}
