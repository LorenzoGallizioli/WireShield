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
		this.downloadPath = null; // Automatically set default download path
		this.monitorStatus = runningStates.DOWN; // Initially not monitoring
		this.antivirusManager = antivirusManager;
		logger.info("DownloadManager initialized with path: {}", this.downloadPath);
	}

	/**
	 * Returns the singleton instance of DownloadManager.
	 *
	 * @param antivirusManager The AntivirusManager instance (only required for
	 *                         first initialization).
	 * @return The single instance of DownloadManager.
	 */
	public static synchronized DownloadManager getInstance(AntivirusManager antivirusManager) {
		if (instance == null) {
			instance = new DownloadManager(antivirusManager);
		}
		return instance;
	}

	/**
	 * Starts monitoring the download directory for new files. Detected files
	 * will be added to the antivirus scanning queue.
	 *
	 * @throws IOException If an error occurs while setting up the WatchService.
	 */
	public void startMonitoring() {
		if (this.monitorStatus == runningStates.UP) {
			logger.warn("Already monitoring the download directory.");
			return;
		}

		String path = FileManager.getConfigValue("FOLDER_TO_SCAN_PATH");
		if (path == null) {
			logger.error("Download directory path is null. Cannot start monitoring.");
			return;
		}

		File downloadDir = new File(path);
		if (!downloadDir.exists() || !downloadDir.isDirectory()) {
			logger.error("Invalid download directory: {}", path);
			return;
		}

		Path watchPath = Paths.get(path);

		try {
			this.watchService = FileSystems.getDefault().newWatchService();
			watchPath.register(this.watchService,
					StandardWatchEventKinds.ENTRY_CREATE,
					StandardWatchEventKinds.ENTRY_MODIFY);

		} catch (IOException e) {
			logger.error("Error initializing WatchService.", e);
			this.monitorStatus = runningStates.DOWN;
			return;
		}

		this.monitorThread = new Thread(() -> {

			this.monitorStatus = runningStates.UP;
			
			while (!Thread.currentThread().isInterrupted()) {

				WatchKey key;

				try {

					key = watchService.take(); // Wait for events

				} catch (InterruptedException e) {
					
					Thread.currentThread().interrupt();
					continue;
				}

				for (WatchEvent<?> event : key.pollEvents()) {

					try {
						if (event.kind() == StandardWatchEventKinds.ENTRY_CREATE ||
								event.kind() == StandardWatchEventKinds.ENTRY_MODIFY) {

							Path newFilePath = watchPath.resolve((Path) event.context());
							File newFile = newFilePath.toFile();

							if (!FileManager.isTemporaryFile(newFile) && FileManager.isFileStable(newFile)) {
								String fileName = newFile.getAbsolutePath() + "-" + newFile.lastModified();

								if (!detectedFiles.contains(fileName)) {
									detectedFiles.add(fileName);

									logger.info("New file detected: {}", newFile.getName());

									File quarantinedFile = antivirusManager.moveToQuarantine(newFile);

									if (quarantinedFile != null) {
										antivirusManager.addFileToScanBuffer(quarantinedFile);
									} else {
										logger.error("Failed to quarantine the file: {}", newFile.getName());
									}
								}
							}
						}
					} catch (Exception ex) {
						logger.error("Unexpected error during file event handling", ex);
					}
				}

				boolean valid = key.reset();
				if (!valid) {
					logger.warn("WatchKey is invalid, stopping monitoring.");
					break;
				}
			}

			this.monitorStatus = runningStates.DOWN;
		});

		monitorThread.setDaemon(true);
		monitorThread.start(); // Begin monitoring
	}


	/**
	 * Forces the monitoring service to stop immediately.
	 * If the monitoring service is already stopped, it logs a warning and exits.
	 * Otherwise, it sets the termination flag, interrupts the monitoring thread, and waits for
	 * the thread to finish. Finally, it closes the WatchService and logs a success message.
	 */
	public void forceStopMonitoring() {
		if (monitorStatus == runningStates.DOWN) {
			logger.warn("Monitoring is already stopped.");
			return; 

		}

		if (monitorThread != null && monitorThread.isAlive()) {

			monitorThread.interrupt();
			try {
				monitorThread.join();

			} catch (InterruptedException e) {
				logger.error("Thread interrupted while stopping monitoring.");
			}
		}

		if (watchService != null) {
			try {

				watchService.close();

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

	public void interruptAllThreads() throws InterruptedException {
		if(this.monitorThread != null && this.monitorThread.isAlive()){
			this.monitorThread.interrupt();
			this.monitorThread.join();
		}
	}
}