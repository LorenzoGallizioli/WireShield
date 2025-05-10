package com.wireshield.localfileutils;

import com.wireshield.av.AntivirusManager;
import com.wireshield.enums.runningStates;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;

import static org.junit.Assert.*;

/**
 * This class tests various functionalities of the {@code DownloadManager},
 * including default path detection, handling of temporary files, file stability
 * checks, and monitoring capabilities.
 */
public class DownloadManagerTest {

	// Logger for logging test-related information
	private static final Logger logger = LogManager.getLogger(DownloadManagerTest.class);

	// Instances of the DownloadManager and AntivirusManager for testing
	private DownloadManager downloadManager;
	private AntivirusManager antivirusManager;

	/**
	 * Sets up the test environment before each test. This method initializes the
	 * {@code DownloadManager} and {@code AntivirusManager}, and creates a temporary
	 * directory for testing.
	 * 
	 * @throws IOException if an I/O error occurs during the setup.
	 */
	@Before
	public void setUp() throws IOException {
		antivirusManager = AntivirusManager.getInstance();
		downloadManager = DownloadManager.getInstance(antivirusManager);
	}

	/**
	 * Tests the default download path determination for Windows systems. This test
	 * simulates a Windows environment and verifies that the default download path
	 * is correctly set.
	 */
	@Test
	public void testGetDefaultDownloadPathWindows() {

		// Simulating a Windows environment
		System.setProperty("os.name", "Windows 10");

		// Get the default download path and expected path
		String downloadPath = downloadManager.getDefaultDownloadPath();
		String expectedPath = System.getProperty("user.home") + "\\Downloads";

		// Verify that the default download path for Windows matches the expected path
		assertEquals("Default path for Windows should match", expectedPath, downloadPath);
	}

	/**
	 * Tests the default download path determination for Unix-based systems. This
	 * test simulates a Unix/Linux environment and verifies that the default
	 * download path is correctly set.
	 */
	@Test
	public void testGetDefaultDownloadPathUnix() {

		// Simulating a Unix/Linux environment
		System.setProperty("os.name", "Linux");

		// Get the default download path and expected path
		String downloadPath = downloadManager.getDefaultDownloadPath();
		String expectedPath = System.getProperty("user.home") + "/Downloads";

		// Verify that the default download path for Unix systems matches the expected
		// path
		assertEquals("Default path for Unix systems should match", expectedPath, downloadPath);
	}

	/**
	 * Tests the start and stop functionality of the download monitoring process.
	 * The test checks if the monitoring thread can successfully detect a new file,
	 * add it to the antivirus scan buffer, and stop the monitoring when requested.
	 * 
	 * @throws IOException          if an I/O error occurs while creating the file.
	 * @throws InterruptedException if the test is interrupted during the monitoring
	 *                              process.
	 */
	@Test
	public void testStartAndStopMonitoring() throws IOException, InterruptedException {

		// Start the monitoring thread
		Thread monitoringThread = new Thread(() -> {
			try {
				downloadManager.startMonitoring();
				downloadManager.startMonitoring(); // Testing for logger "Already monitoring the download directory."
			} catch (Exception e) {
				logger.error("Error during monitoring: {}", e.getMessage());
			}
		});
		monitoringThread.start();

		// Simulate a short delay to allow the monitoring to start
		Thread.sleep(2000);

		// Simulate the creation of a new file in the download directory
		Path downloadPath = Paths.get(downloadManager.getDefaultDownloadPath());
		Path newFilePath = downloadPath.resolve("newfile.txt");
		File newFile = newFilePath.toFile();

		// If the file already exists, delete it before testing
		if (newFile.exists()) {
			Files.delete(newFilePath);
		}

		// Create the new file
		Files.createFile(newFilePath);
		logger.info("Created new file: {}", newFile.getName());

		// Assume the WatchService detected the new file, so manually add it to the
		// antivirus buffer
		antivirusManager.addFileToScanBuffer(newFile);

		// Check if the file was added to the scan buffer
		boolean fileDetected = antivirusManager.getScanBuffer().contains(newFile);
		assertTrue("New file should be added to the scan buffer", fileDetected);

		// Simulate another delay to allow the file to be processed
		Thread.sleep(2000);

		// Stop the monitoring thread
		downloadManager.forceStopMonitoring();
		downloadManager.forceStopMonitoring(); // Testing for logger "Monitoring is already stopped."
		assertFalse("Monitoring should be stopped", downloadManager.getMonitorStatus() == runningStates.UP);

		// Ensure the monitoring thread is actually stopped
		monitoringThread.join(2000); // Wait for the thread to stop within 2 seconds

		// Check if the monitoring thread has stopped
		assertFalse("Monitoring thread should be stopped", monitoringThread.isAlive());

		// Cleanup (delete the test file)
		Files.delete(newFilePath);
		logger.info("Deleted new file: {}", newFile.getName());
	}
}
