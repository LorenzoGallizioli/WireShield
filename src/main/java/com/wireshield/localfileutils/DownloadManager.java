package com.wireshield.localfileutils;

import com.wireshield.av.AntivirusManager;
import com.wireshield.enums.runningStates;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.util.HashSet;
import java.util.Set;

/*
 * The DownloadManager class is responsible for monitoring the download directory for new files,
 * detecting new downloads, and adding them to the antivirus scanning queue.
 */
public class DownloadManager {

    private static final Logger logger = LogManager.getLogger(DownloadManager.class);

    private String downloadPath; // Path to the monitored download directory
    private final Set<String> detectedFiles = new HashSet<>(); // Set to track already detected files
    private AntivirusManager antivirusManager; // Antivirus manager instance for scanning files
    private runningStates monitorStatus; // Current monitoring status (UP or DOWN)
    private WatchService watchService; // WatchService to monitor file system events
    private Thread monitorThread; // Thread to run the monitoring process

    /**
     * Constructs a DownloadManager instance and sets up the initial state.
     *
     * @param antivirusManager The AntivirusManager instance for file scanning.
     */
    public DownloadManager(AntivirusManager antivirusManager) {
        this.setDownloadPath(getDefaultDownloadPath()); // Set the default download path
        this.monitorStatus = runningStates.DOWN; // Initially DOWN (not monitoring)
        this.antivirusManager = antivirusManager;
        logger.info("DownloadManager initialized with path: {}", getDownloadPath());
    }

    /**
     * Determines the default download directory path based on the operating system.
     *
     * @return The default download directory path.
     */
    public String getDefaultDownloadPath() {
        String userHome = System.getProperty("user.home");
        String downloadFolder = "Downloads";

        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            return userHome + "\\" + downloadFolder; // Windows path separator
        } else {
            return userHome + "/" + downloadFolder; // UNIX-based path separator
        }
    }

    /**
     * Starts monitoring the download directory for new files. Files detected will be added to the antivirus scan queue.
     *
     * @throws IOException If an error occurs while setting up the WatchService.
     */
    public void startMonitoring() throws IOException {
        if (monitorStatus == runningStates.UP) {
            logger.warn("Already monitoring the download directory.");
            return; // Monitoring already in progress
        }

        monitorStatus = runningStates.UP; // Set monitoring status to UP (active)
        logger.info("Monitoring directory: {}", getDownloadPath());

        // Create WatchService to monitor directory
        try {
            watchService = FileSystems.getDefault().newWatchService();
            Path path = Paths.get(getDownloadPath());

            // Register the directory to listen for new file creation events
            path.register(watchService, StandardWatchEventKinds.ENTRY_CREATE);

            // Start monitoring in a new thread
            monitorThread = new Thread(() -> {
                // Loop to monitor the directory as long as the status is UP
                while (monitorStatus == runningStates.UP) {
                    try {
                        WatchKey key = watchService.take(); // Blocking call until an event is detected

                        // Process each event
                        for (WatchEvent<?> event : key.pollEvents()) {
                            if (event.kind() == StandardWatchEventKinds.ENTRY_CREATE) {
                                Path newFilePath = path.resolve((Path) event.context());
                                File newFile = newFilePath.toFile();

                                if (!FileManager.isTemporaryFile(newFile) && FileManager.isFileStable(newFile)) {
                                    String fileName = newFile.getAbsolutePath();

                                    // Check if file is already detected
                                    if (!detectedFiles.contains(fileName)) {
                                        detectedFiles.add(fileName);
                                        logger.info("New file detected: {}", newFile.getName());
                                        antivirusManager.addFileToScanBuffer(newFile); // Add to antivirus queue
                                    }
                                }
                            }
                        }

                        key.reset(); // Reset the key to continue watching for further events

                    } catch (InterruptedException e) {
                        // Handle interruption gracefully, but don't stop the monitoring thread
                        if (monitorStatus == runningStates.UP) {
                            logger.info("Monitoring interrupted, but continuing...");
                            Thread.currentThread().interrupt(); // Preserve interruption flag
                        }
                    }
                }
            });

            // Start the monitoring thread
            monitorThread.start();

        } catch (IOException e) {
            logger.error("Error creating WatchService: {}", e.getMessage(), e);
        }
    }

    /*
     * Stops monitoring the download directory and terminates the monitoring thread.
     */
    public void stopMonitoring() {
        if (monitorStatus == runningStates.DOWN) {
            logger.warn("Monitoring is already stopped.");
            return; // Monitoring already stopped
        }

        monitorStatus = runningStates.DOWN; // Set monitoring status to DOWN (inactive)
        try {
            // Stop the monitor thread and close WatchService
            if (monitorThread != null && monitorThread.isAlive()) {
                monitorThread.interrupt();
                monitorThread.join(); // Wait for the thread to finish
            }

            if (watchService != null) {
                watchService.close(); // Close the WatchService
            }

            logger.info("Stopped monitoring the directory.");

        } catch (IOException | InterruptedException e) {
            logger.error("Error stopping monitoring: {}", e.getMessage(), e);
        }
    }

    /**
     * Returns the current status of the monitor (UP or DOWN).
     *
     * @return The current monitor status.
     */
    public runningStates getMonitorStatus() {
        return monitorStatus;
    }

    /**
     * Returns the path to the download directory being monitored.
     *
     * @return The path to the monitored download directory.
     */
    public String getDownloadPath() {
        return downloadPath;
    }

    /**
     * Sets the path to the download directory to be monitored.
     *
     * @param downloadPath The path to the download directory.
     */
    public void setDownloadPath(String downloadPath) {
        this.downloadPath = downloadPath;
    }   
}
