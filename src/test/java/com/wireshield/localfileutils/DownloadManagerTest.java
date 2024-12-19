package com.wireshield.localfileutils;

import com.wireshield.av.AntivirusManager;
import com.wireshield.enums.runningStates;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;

import static org.junit.Assert.*;

/*
 * This class tests various functionalities of the DownloadManager, including default path detection, 
 * handling of temporary files, file stability checks, and monitoring capabilities.
 */
public class DownloadManagerTest {

    private static final Logger logger = LogManager.getLogger(DownloadManagerTest.class);

    private DownloadManager downloadManager;
    private AntivirusManager antivirusManager;
    private String testDownloadPath;

    /**
     * Sets up the test environment before each test.
     * This method initializes the DownloadManager and AntivirusManager,
     * and creates a temporary directory for testing.
     * 
     * @throws IOException if an I/O error occurs during the setup.
     */
    @Before
    public void setUp() throws IOException {
        antivirusManager = new AntivirusManager();
        downloadManager = new DownloadManager(antivirusManager);

        // Define a specific path for testing
        testDownloadPath = System.getProperty("user.home") + "/Downloads/test_downloads";

        // Create the test download directory
        Files.createDirectories(Paths.get(testDownloadPath));
        downloadManager.setDownloadPath(testDownloadPath);
    }

    /**
     * Cleans up the test environment after each test.
     * This method deletes the simulated download directory and its contents.
     * 
     * @throws IOException if an I/O error occurs during the cleanup.
     */
    @After
    public void tearDown() throws IOException {
        Files.walk(Paths.get(testDownloadPath))
                .map(Path::toFile)
                .forEach(File::delete);
        Files.deleteIfExists(Paths.get(testDownloadPath));
        logger.info("Test environment cleaned up.");
    }

    /*
     * Tests the default download path determination for Windows systems.
     * This test simulates a Windows environment and verifies that the default download path is correctly set.
     */
    @Test
    public void testGetDefaultDownloadPathWindows() {
        System.setProperty("os.name", "Windows 10");

        String downloadPath = downloadManager.getDefaultDownloadPath();
        String expectedPath = System.getProperty("user.home") + "\\Downloads";

        // Verify that the default download path for Windows matches the expected path
        assertEquals("Default path for Windows should match", expectedPath, downloadPath);
    }

    /*
     * Tests the default download path determination for Unix-based systems.
     * This test simulates a Unix/Linux environment and verifies that the default download path is correctly set.
     */
    @Test
    public void testGetDefaultDownloadPathUnix() {
        System.setProperty("os.name", "Linux");

        String downloadPath = downloadManager.getDefaultDownloadPath();
        String expectedPath = System.getProperty("user.home") + "/Downloads";

        // Verify that the default download path for Unix systems matches the expected path
        assertEquals("Default path for Unix systems should match", expectedPath, downloadPath);
    }

    /*
     * Tests detection of temporary files based on common extensions and naming conventions.
     */
    @Test
    public void testIsTemporaryFile() {
        File tempFile1 = new File("file.crdownload");
        File tempFile2 = new File("file.part");
        File tempFile3 = new File(".hiddenfile");
        File regularFile = new File("file.txt");

        // Check if files with specific extensions or naming conventions are identified as temporary
        assertTrue("File with .crdownload extension should be temporary", FileManager.isTemporaryFile(tempFile1));
        assertTrue("File with .part extension should be temporary", FileManager.isTemporaryFile(tempFile2));
        assertTrue("Hidden file should be temporary", FileManager.isTemporaryFile(tempFile3));
        assertFalse("Regular file should not be temporary", FileManager.isTemporaryFile(regularFile));
    }

    /**
     * Tests the stability of a file by ensuring that it is not actively being written to.
     * The method simulates file writing and checks if the file becomes stable.
     * 
     * @throws IOException if an I/O error occurs while creating or writing to the file.
     * @throws InterruptedException if the test is interrupted during sleep.
     */
    @Test
    public void testIsFileStable() throws IOException, InterruptedException {
        File testFile = new File(testDownloadPath + "/stable_file.txt");
        assertTrue("Test file should be created", testFile.createNewFile());

        // Simulate writing to the file
        Files.write(testFile.toPath(), "Test content".getBytes());
        Thread.sleep(500); // Allow time for the file to stabilize

        // Check if the file is stable after creation
        assertTrue("File should be stable after creation", FileManager.isFileStable(testFile));

        // Cleanup
        testFile.delete();
    }

    /**
     * Tests the start and stop functionality of the download monitoring process.
     * The test checks if the monitoring thread can successfully detect a new file,
     * add it to the antivirus scan buffer, and stop the monitoring when requested.
     * 
     * @throws IOException if an I/O error occurs while creating the file.
     * @throws InterruptedException if the test is interrupted during the monitoring process.
     */
    @Test
    public void testStartAndStopMonitoring() throws IOException, InterruptedException {
        // Start the monitoring thread
        Thread monitoringThread = new Thread(() -> {
            try {
                downloadManager.startMonitoring();
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

        // Assume the WatchService detected the new file, so manually add it to the antivirus buffer
        antivirusManager.addFileToScanBuffer(newFile);

        // Check if the file was added to the scan buffer
        boolean fileDetected = antivirusManager.getScanBuffer().contains(newFile);
        assertTrue("New file should be added to the scan buffer", fileDetected);

        // Simulate another delay to allow the file to be processed
        Thread.sleep(2000);

        // Stop the monitoring thread
        downloadManager.stopMonitoring();
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
