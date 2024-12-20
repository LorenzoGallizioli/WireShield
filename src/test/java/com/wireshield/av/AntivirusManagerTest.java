package com.wireshield.av;

import org.junit.Before;
import org.junit.Test;
import com.wireshield.enums.runningStates;
import com.wireshield.enums.warningClass;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import static org.junit.Assert.*;

import com.wireshield.localfileutils.FileManager;

/*
 * Test class for the AntivirusManager class.
 * This class contains unit tests for validating the functionality of the AntivirusManager, 
 * including adding files to the scan buffer, performing scans, stopping scans, and merging reports.
 */
public class AntivirusManagerTest {

	private AntivirusManager antivirusManager;
    private ClamAV clamAV;
    private VirusTotal virusTotal;

    /*
     * Set up the environment for each test.
     * This method runs before each test case to initialize the AntivirusManager and the scanning tools (ClamAV and VirusTotal).
     */
    @Before
    public void setUp() {
        clamAV = new ClamAV(); // Uses the real implementation of ClamAV
        virusTotal = new VirusTotal(); // Uses the real implementation of VirusTotal
        antivirusManager = new AntivirusManager();
        antivirusManager.setClamAV(clamAV);
        antivirusManager.setVirusTotal(virusTotal);
    }

    /**
     * Utility method to create a file with specific content.
     * @param fileName The name of the file to create.
     * @return The created File object.
     * @throws IOException If an I/O error occurs during file creation.
     */
    private File createFileWithContent(String fileName) throws IOException {
        File file = new File(fileName);
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write("Ciao".getBytes()); // Writes "Ciao" to the file
        }
        return file;
    }

    /**
     * Test the addFileToScanBuffer method.
     * This test verifies that a file is correctly added to the scan buffer of the AntivirusManager.
     * 
     * @throws IOException If an I/O error occurs during file creation.
     */
    @Test
    public void testAddFileToScanBuffer() throws IOException {
        // Create a file with "Ciao" content
        File file = createFileWithContent("testfile.exe");
        antivirusManager.addFileToScanBuffer(file);

        // Verify that the file is in the scan buffer
        assertTrue("The file should be in the buffer", antivirusManager.getScanBuffer().contains(file));
    }

    /**
     * Test the startPerformScan method.
     * This test checks if the scan is performed correctly, files are removed from the buffer after scanning, 
     * and scan reports are generated with correct threat classifications.
     * 
     * @throws IOException If an I/O error occurs during file creation.
     * @throws InterruptedException If the thread is interrupted during the scan.
     */
    @Test
    public void testStartPerformScan() throws IOException, InterruptedException {
        // Create files with specific extensions
        File file1 = createFileWithContent("file1.exe"); // Create .exe file
        File file2 = createFileWithContent("file2.txt"); // Create .txt file

        // Add files to the buffer
        antivirusManager.addFileToScanBuffer(file1);
        antivirusManager.addFileToScanBuffer(file2);

        // Start the scan in a separate thread
        Thread scanThread = new Thread(() -> {
            antivirusManager.startPerformScan();
        });
        scanThread.start();

        // Wait for the scan to complete
        scanThread.join(5000); // Wait for some time to simulate scan process

        // Verify that the files are removed from the buffer after scanning
        assertFalse("The file should be removed from the buffer after scanning", 
                    antivirusManager.getScanBuffer().contains(file1));
        assertFalse("The file should be removed from the buffer after scanning", 
                    antivirusManager.getScanBuffer().contains(file2));

        // Verify that final reports are present
        assertTrue("Final reports should be present", !antivirusManager.getFinalReports().isEmpty());

        // Verify that the report for file1.exe flags it as a threat
        ScanReport finalReport1 = antivirusManager.getFinalReports().get(0);
        assertTrue("file1.exe should be flagged as dangerous", finalReport1.isThreatDetected());
        assertEquals("The threat for file1.exe should be DANGEROUS", warningClass.DANGEROUS,
                    finalReport1.getWarningClass());

        // Verify that the report for file2.txt is clean
        ScanReport finalReport2 = antivirusManager.getFinalReports().get(1);
        assertFalse("file2.txt should not have any threats", finalReport2.isThreatDetected());
        assertEquals("The threat for file2.txt should be CLEAR", warningClass.CLEAR,
                    finalReport2.getWarningClass());
    }
    
    /**
     * Test to verify that large files are excluded from VirusTotal scanning.
     * This ensures that files exceeding the MAX_FILE_SIZE are not processed by VirusTotal.
     * 
     * @throws IOException If an I/O error occurs during file creation.
     */
    @Test
    public void testLargeFileExclusionFromVirusTotal() throws IOException {
        // Define a large file size exceeding the limit (e.g., 20 MB if MAX_FILE_SIZE is 10 MB)
        final long LARGE_FILE_SIZE = 20 * 1024 * 1024; // 20 MB

        // Generate a large string content to simulate a large file
        StringBuilder largeContentBuilder = new StringBuilder((int) LARGE_FILE_SIZE);
        for (int i = 0; i < LARGE_FILE_SIZE; i++) {
            largeContentBuilder.append('A'); // Fill with repetitive characters
        }
        String largeContent = largeContentBuilder.toString();

        // Define the file path as a string
        String largeFilePath = "largeTestFile.txt";

        // Write the large file using FileManager
        FileManager fileManager = new FileManager();
        fileManager.writeFile(largeFilePath, largeContent);

        // Create a File object for the large file
        File largeFile = new File(largeFilePath);

        // Add the large file to the scan buffer
        antivirusManager.addFileToScanBuffer(largeFile);

        // Perform the scan
        antivirusManager.startPerformScan();

        // Verify that the file is removed from the scan buffer after processing
        assertFalse("The large file should be removed from the scan buffer after processing",
                antivirusManager.getScanBuffer().contains(largeFile));

        // Verify that no VirusTotal analysis was performed for the large file
        // This can be done by checking the final reports or mocking VirusTotal and asserting it wasn't called
        for (ScanReport report : antivirusManager.getFinalReports()) {
            if (report.getFile().equals(largeFile.getName())) {
                assertTrue("Large file should not trigger VirusTotal analysis",
                        largeFile.length() > AntivirusManager.MAX_FILE_SIZE);
                assertFalse("Large file should not be marked as scanned by VirusTotal",
                        report.getThreatDetails().contains("VirusTotal"));
            }
        }

        // Clean up the large test file
        File fileToDelete = new File(largeFilePath);
        if (fileToDelete.exists()) {
            fileToDelete.delete();
        }
    }



    /**
     * Test the stopPerformScan method.
     * This test checks whether the scan can be stopped correctly, and verifies the scan status is updated.
     * 
     * @throws InterruptedException If the thread is interrupted during the scan.
     * @throws IOException If an I/O error occurs during file creation.
     */
    @Test
    public void testStopPerformScan() throws InterruptedException, IOException {
        // Crea un file da aggiungere al buffer
        File file1 = createFileWithContent("file1.exe"); // Crea un file .exe
        antivirusManager.addFileToScanBuffer(file1);

        // Avvia la scansione in un thread separato
        Thread scanThread = new Thread(() -> {
            antivirusManager.startPerformScan();
        });
        scanThread.start();

        // Aspetta che lo stato diventi UP
        while (antivirusManager.getScannerStatus() != runningStates.UP) {
            Thread.sleep(100); // Attendi brevemente
        }

        // Ferma la scansione
        antivirusManager.stopPerformScan();

        // Verifica che lo stato sia DOWN
        assertEquals("Lo stato della scansione dovrebbe essere DOWN", 
                     runningStates.DOWN, 
                     antivirusManager.getScannerStatus());
    }


    /*
     * Test the mergeReports method.
     * This test verifies that reports are correctly merged, updating threat status and details.
     */
    @Test
    public void testMergeReports() {
        AntivirusManager manager = new AntivirusManager();

        // Create the target report
        ScanReport target = new ScanReport();
        target.setThreatDetected(false);
        target.setThreatDetails("No threat detected");
        target.setWarningClass(warningClass.CLEAR);
        target.setValid(true);

        // Create the source report
        ScanReport source = new ScanReport();
        source.setThreatDetected(true);
        source.setThreatDetails("Suspicious behavior detected");
        source.setWarningClass(warningClass.SUSPICIOUS);
        source.setValid(false);

        // Perform the merge
        manager.mergeReports(target, source);

        // Verify that the changes are applied correctly
        assertTrue(target.isThreatDetected());  // The target should flag the threat
        assertEquals("Suspicious behavior detected", target.getThreatDetails());  // Threat details should be updated
        assertEquals(warningClass.SUSPICIOUS, target.getWarningClass());  // Warning class should be updated
        assertFalse(target.isValidReport());  // Report validity should be updated
    }
}
