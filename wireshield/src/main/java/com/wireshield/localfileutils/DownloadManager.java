package com.wireshield.localfileutils;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.wireshield.av.AntivirusManager;
import com.wireshield.av.FileManager;
import com.wireshield.enums.runningStates;

/**
 * The DownloadManager class is responsible for: - Monitoring a download
 * directory for new files. - Detecting and processing new downloads. - Adding
 * detected files to the antivirus scanning queue.
 *
 * This class utilizes the Singleton design pattern to ensure a single instance
 * manages the download directory monitoring process.
 */
public class DownloadManager {

    private static final Logger logger = LogManager.getLogger(DownloadManager.class);

    private static DownloadManager instance; // Singleton instance
    private String downloadPath; // Path to the monitored download directory
    private final Set<String> detectedFiles = new HashSet<>(); // Tracks already detected files
    private AntivirusManager antivirusManager; // Manages file scanning
    private runningStates monitorStatus; // Current monitoring status (UP or DOWN)
    private WatchService watchService; // Monitors file system events
    private Thread monitorThread; // Runs the monitoring process

    /**
     * Private constructor to initialize the DownloadManager instance.
     *
     * @param antivirusManager The AntivirusManager instance for file scanning.
     */
    private DownloadManager(AntivirusManager antivirusManager) {
        this.downloadPath = getDefaultDownloadPath(); // Automatically set default download path
        this.monitorStatus = runningStates.DOWN; // Initially not monitoring
        this.antivirusManager = antivirusManager;
        logger.info("DownloadManager initialized with path: {}", getDownloadPath());
    }

    /**
     * Returns the singleton instance of DownloadManager.
     *
     * @param antivirusManager The AntivirusManager instance (only required for
     * first initialization).
     * @return The single instance of DownloadManager.
     */
    public static synchronized DownloadManager getInstance(AntivirusManager antivirusManager) {
        if (instance == null) {
            instance = new DownloadManager(antivirusManager);
        }
        return instance;
    }

    /**
     * Determines the default download directory path based on the user's
     * operating system.
     *
     * @return The default download directory path as a String.
     */
    public String getDefaultDownloadPath() {
        String userHome = System.getProperty("user.home");
        String[] possibleFolders = {"Download", "Downloads", "Scaricati"};

        // Checks if at least one folder exists
        for (String folder : possibleFolders) {
            File dir = new File(userHome, folder);
            if (dir.exists() && dir.isDirectory()) {
                logger.info("Default download folder found: {}", dir.getAbsolutePath());
                return dir.getAbsolutePath();
            }
        }

        // L'inserimento di una cartella manualmente tramite console è temporanea, in quanto verrà implementata nel UI mediante una finestra
        // If no valid folder is found, ask the user to enter one
        Scanner scanner = new Scanner(System.in);
        String userPath = null;
        int maxRetries = 3; // Limit the number of attempts to 3
        int attempts = 0;

        while (attempts < maxRetries) {
            try {
                logger.warn("No default download folder found. Please enter a path:");
                userPath = scanner.nextLine();
                File userDir = new File(userPath);

                // Check if the entered path is valid
                if (userDir.exists() && userDir.isDirectory()) {
                    logger.info("User provided a valid download directory: {}", userPath);
                    return userDir.getAbsolutePath();
                }
            } catch (Exception e) {
                logger.error("Error in user input. The program cannot continue.", e);
                break; // Exits the loop or can perform other recovery actions
            }
            attempts++;
        }

        logger.error("Too many invalid attempts. Unable to proceed.");
        return null; // Return null if no valid path is found after 3 attempts
    }

    /**
     * Starts monitoring the download directory for new files. Detected files
     * will be added to the antivirus scanning queue.
     *
     * @throws IOException If an error occurs while setting up the WatchService.
     */
    public void startMonitoring() {
        if (monitorStatus == runningStates.UP) {
            logger.warn("Already monitoring the download directory.");
            return; // Already monitoring
        }

        // Verifies that the download path is valid
        String path = getDownloadPath(); // Get the path of the folder
        if (path == null) {
            logger.error("Download directory path is null. Cannot start monitoring.");
            return; // Stops monitoring if the path is not valid
        }

        // Verifies that the download path is valid
        File downloadDir = new File(getDownloadPath());
        if (!downloadDir.exists() || !downloadDir.isDirectory()) {
            logger.error("Invalid download directory: {}", getDownloadPath());
            return; // Stops monitoring if the path is not valid
        }

        monitorStatus = runningStates.UP; // Set monitoring status to active
        logger.info("Started monitoring directory: {}", getDownloadPath());
        Path watchPath = Paths.get(path);

        // Create WatchService to monitor directory
        try {
            // Register the directory for creation events
            watchService = FileSystems.getDefault().newWatchService();
            watchPath.register(watchService, StandardWatchEventKinds.ENTRY_CREATE);

        } catch (IOException e) {
            logger.error("Error initializing WatchService.", e);
            monitorStatus = runningStates.DOWN;
            return;
        }

        // Start monitoring in a new thread
        monitorThread = new Thread(() -> {
            // Loop to monitor the directory as long as the status is UP
            while (!Thread.currentThread().isInterrupted()) {

                WatchKey key;

                try {

                    key = watchService.take(); // Wait for events

                } catch (InterruptedException e) {
                    // Handle interruption gracefully, but don't stop the monitoring thread
                    Thread.currentThread().interrupt();
                    continue;
                }

                // Process events
                for (WatchEvent<?> event : key.pollEvents()) {

                    if (event.kind() == StandardWatchEventKinds.ENTRY_CREATE) {

                        Path newFilePath = watchPath.resolve((Path) event.context());
                        File newFile = newFilePath.toFile();

                        if (!FileManager.isTemporaryFile(newFile) && FileManager.isFileStable(newFile)) {
                            String fileName = newFile.getAbsolutePath();

                            if (!detectedFiles.contains(fileName)) {
                                detectedFiles.add(fileName);
                                logger.info("New file detected: {}", newFile.getName());
                                File quarantinedFile = antivirusManager.moveToQuarantine(newFile);
                                if (quarantinedFile != null) {
                                    antivirusManager.addFileToScanBuffer(quarantinedFile);  // Invii già la versione bloccata e spostata
                                } else {
                                    logger.error("Failed to quarantine the file: {}", newFile.getName());
                                }
                            }
                        }
                    }
                }

                key.reset(); // Continue watching for further events

            }

            monitorStatus = runningStates.DOWN;
        });

        monitorThread.start(); // Begin monitoring
    }

    /**
     * Stops monitoring the download directory and shuts down the monitoring
     * thread.
     */
    public void forceStopMonitoring() {
        if (monitorStatus == runningStates.DOWN) {
            logger.warn("Monitoring is already stopped.");
            return; // Already stopped

        }

        if (monitorThread != null && monitorThread.isAlive()) {

            // Set monitorThread's termination flag UP
            monitorThread.interrupt();
            try {
                // Wait for the thread to finish
                monitorThread.join();

            } catch (InterruptedException e) {
                logger.error("Thread interrupted while stopping monitoring.");
            }
        }

        if (watchService != null) {
            try {

                watchService.close(); // Close WatchService

            } catch (IOException e) {
                logger.error("Error stopping monitoring due to IO issue: {}", e.getMessage(), e);
            }
        }

        logger.info("Stopped monitoring the directory.");
    }

    /**
     * Returns the current monitoring status (UP or DOWN).
     *
     * @return The current monitoring status.
     */
    public runningStates getMonitorStatus() {
        return monitorStatus;
    }

    /**
     * Retrieves the path to the download directory being monitored.
     *
     * @return The monitored download directory path.
     */
    public String getDownloadPath() {
        return downloadPath;
    }

    public static void main(String[] args) {
        // Crea un'istanza di AntivirusManager
        AntivirusManager antivirusManager = AntivirusManager.getInstance();

        // Ottieni l'istanza di DownloadManager
        DownloadManager downloadManager = DownloadManager.getInstance(antivirusManager);

        // Forziamo il percorso di download a un percorso non valido per simulare l'errore
        // String invalidPath = "C:/CartellaNonEsistente/Downloads";
        // downloadManager.downloadPath = invalidPath;
        // Avvia il monitoraggio della cartella di download (questo farà il check della cartella)
        downloadManager.startMonitoring();
    }
}
