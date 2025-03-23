package com.wireshield.av;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

import org.junit.After;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Before;
import org.junit.Test;

import com.wireshield.enums.runningStates;
import com.wireshield.enums.warningClass;

/**
 * Test class for the AntivirusManager class. This class contains unit tests for
 * validating the functionality of the AntivirusManager, including adding files
 * to the scan buffer, performing scans, stopping scans, and merging reports.
 */
public class AntivirusManagerTest {

	private AntivirusManager antivirusManager;
	private ClamAV clamAV;
	runningStates avStatus = runningStates.DOWN; // Initial state is DOWN

	/**
	 * Set up the environment for each test. This method runs before each test case
	 * to initialize the AntivirusManager and the scanning tools (ClamAV and
	 * VirusTotal).
	 */
	@Before
	public void setUp() {

		clamAV = ClamAV.getInstance(); // Uses the real implementation of ClamAV
		antivirusManager = AntivirusManager.getInstance();
		antivirusManager.setClamAV(clamAV);
	}

	/**
	 * Clean up the files created during the tests. This method will be executed
	 * after each test to delete the created files.
	 */
	@After
	public void tearDown() {
		// List of files to delete
		File file1 = new File("file1.exe");
		File file2 = new File("file2.txt");
		File file3 = new File("file3.com");
		File file4 = new File("file4.pdf");
		File fakeFile = new File("fakeFile.txt");
		File testFile = new File("testfile.exe");
		// Delete the files if they exist
		file1.delete();
		file2.delete();
		file3.delete();
		file4.delete();
		fakeFile.delete();
		testFile.delete();
	}

	/**
	 * Utility method to create a file with specific content.
	 * 
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
	 * Test the addFileToScanBuffer method. This test verifies that a file is
	 * correctly added to the scan buffer of the AntivirusManager.
	 * 
	 * @throws IOException          If an I/O error occurs during file creation.
	 * @throws InterruptedException
	 */
	@Test
	public void testAddFileToScanBuffer() throws IOException {

		// Create a file reference to a non-existing file
		File fakeFile = new File("fakeFile.txt");

		// Verify that the non-existing file does not exist
		assertFalse("Il file non dovrebbe esistere.", fakeFile.exists());

		// Add the non-existing file to the buffer
		antivirusManager.addFileToScanBuffer(fakeFile);

		// Verify that the buffer does not contain non-existing files
		assertEquals("Il buffer non dovrebbe contenere file inesistenti.", 0, antivirusManager.getScanBuffer().size());

		// Create a sample file named "testfile.exe"
		File file = createFileWithContent("testfile.exe");

		// Add the file to the buffer for the first time
		antivirusManager.addFileToScanBuffer(file);
		antivirusManager.addFileToScanBuffer(file);

		// Verify that the file is present in the buffer
		assertTrue("Il file dovrebbe essere nel buffer", antivirusManager.getScanBuffer().contains(file));

		// Add the same file again to the buffer (this should activate the 'else'
		// branch)
		assertEquals("Il buffer non dovrebbe contenere file duplicati.", 1, antivirusManager.getScanBuffer().size());

	}

	/**
	 * Test the startPerformScan method. This test checks if the scan is performed
	 * correctly, files are removed from the buffer after scanning, and scan reports
	 * are generated with correct threat classifications.
	 * 
	 * @throws IOException          If an I/O error occurs during file creation.
	 * @throws InterruptedException If the thread is interrupted during the scan.
	 */
	@Test
	public void testStartScan() throws InterruptedException, IOException {

		antivirusManager.startScan();
		antivirusManager.startScan();

		antivirusManager.stopScan();

		// Declare the initial antivirus service state
		avStatus = runningStates.DOWN; // Initial state is DOWN

		// Create sample files
		File file1 = createFileWithContent("file1.exe"); // First file
		File file2 = createFileWithContent("file2.txt"); // Second file
		File file3 = new File("file3.com");
		FileWriter writer = new FileWriter(file3);
		writer.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
		writer.close();

		// Clear any previously scanned files or reports before starting the test
		antivirusManager.getScanBuffer().clear();
		antivirusManager.getFinalReports().clear();

		// Add the files to the scan buffer
		antivirusManager.addFileToScanBuffer(file1);
		antivirusManager.addFileToScanBuffer(file2);
		antivirusManager.addFileToScanBuffer(file3);

		// Verify that the files have been added correctly
		assertEquals("The scan buffer should contain 3 files", 3, antivirusManager.getScanBuffer().size());

		// Change state to UP and start the antivirus service
		avStatus = runningStates.UP;

		if (avStatus == runningStates.UP && antivirusManager.getScannerStatus() != runningStates.UP) {
			try {
				antivirusManager.startScan();
			} catch (Exception e) {
				fail("Error starting the antivirus service: " + e.getMessage());
			}
		}

		// Wait for the scan buffer to be empty and reports to be generated
		while (!antivirusManager.getScanBuffer().isEmpty() || antivirusManager.getFinalReports().size() < 3)

		{
			Thread.sleep(1000); // Wait briefly before checking again
		}

		// Verify that the scan buffer is empty after scanning
		assertTrue("The buffer should be empty after the scan", antivirusManager.getScanBuffer().isEmpty());

		// Verify that the final reports have been generated
		List<ScanReport> finalReports = antivirusManager.getFinalReports();
		assertFalse("Final reports should be present", finalReports.isEmpty());

		// Verify that there are exactly 2 reports for the files being tested
		assertEquals("There should be exactly 4 reports", 3, finalReports.size());

		// Verify the report for file1.exe, file2.txt, and file3.com
		boolean foundFile1 = false;
		boolean foundFile2 = false;
		boolean foundFile3 = false;

		// Iterate over the reports and check for the presence of file1.exe, file2.txt,
		// file3.com
		for (ScanReport report : finalReports) {
			String fileName = report.getFile().getName();
			System.out.println("Report file: '" + fileName + "'"); // Debugging: Print file name

			// Check for file1.exe
			if ("file1.exe".equals(fileName)) {
				foundFile1 = true;
				System.out.println("foundFile1 set to true for file1.exe");
				assertFalse("file1.exe should not be detected as a threat", report.isThreatDetected());
				assertEquals("The threat level for file1.exe should be CLEAR", warningClass.CLEAR,
						report.getWarningClass());
			}

			// Check for file2.txt
			if ("file2.txt".equals(fileName)) {
				foundFile2 = true;
				System.out.println("foundFile2 set to true for file2.txt");
				assertFalse("file2.txt should not be detected as a threat", report.isThreatDetected());
				assertEquals("The threat level for file2.txt should be CLEAR", warningClass.CLEAR,
						report.getWarningClass());
			}

			// Check for file3.com
			if ("file3.com".equals(fileName)) {
				foundFile3 = true;
				System.out.println("foundFile3 set to true for file3.com");
				assertTrue("file3.com should be detected as a threat", report.isThreatDetected());
				assertEquals("The threat level for file3.com should be DANGEROUS", warningClass.DANGEROUS,
						report.getWarningClass());
			}
		}

		// Output debug information for found files
		System.out.println("foundFile1: " + foundFile1);
		System.out.println("foundFile2: " + foundFile2);
		System.out.println("foundFile3: " + foundFile3);

		// Assert that both files were found in the reports
		assertTrue(foundFile1);
		assertTrue(foundFile2);
		assertTrue(foundFile3);
	}

	/**
	 * Test the stopPerformScan method. This test checks whether the scan can be
	 * stopped correctly, and verifies the scan status is updated.
	 * 
	 * @throws InterruptedException If the thread is interrupted during the scan.
	 * @throws IOException          If an I/O error occurs during file creation.
	 */
	@Test
	public void testStopScan() throws InterruptedException, IOException {

		antivirusManager.stopScan();
		antivirusManager.stopScan();

		// Create a file to add to the scan buffer
		File file4 = createFileWithContent("file4.pdf");
		antivirusManager.addFileToScanBuffer(file4);
		System.out.println("File added to scan buffer: file4.pdf");

		// Start the scan in a separate thread
		Thread scanThread = new Thread(() -> {
			antivirusManager.startScan();
		});
		scanThread.start();

		// Add a brief delay to allow the thread to start
		Thread.sleep(500); // Wait 500 ms to allow the scan to start

		System.out.println("Scanner status is UP, now stopping the scan.");

		// Stop the scan
		antivirusManager.stopScan();

		// Verify that the scan status is DOWN (indicating the scan has stopped)
		assertEquals("Lo stato della scansione dovrebbe essere DOWN", runningStates.DOWN,
				antivirusManager.getScannerStatus());

		// Ensure the scan thread terminates properly
		scanThread.join(); // Wait for the scan thread to finish before continuing the test

		System.out.println("Scan thread stopped successfully.");
	}

	/**
	 * Test the mergeReports method. This test verifies that reports are correctly
	 * merged, updating threat status and details.
	 */
	@Test
	public void testMergeReports() {
		AntivirusManager manager = AntivirusManager.getInstance();

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
		assertTrue(target.isThreatDetected()); // The target should flag the threat
		assertEquals("Suspicious behavior detected", target.getThreatDetails()); // Threat details should be updated
		assertEquals(warningClass.SUSPICIOUS, target.getWarningClass()); // Warning class should be updated
		assertFalse(target.isValidReport()); // Report validity should be updated
	}
}
