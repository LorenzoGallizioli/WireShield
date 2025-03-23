package com.wireshield.av;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

import com.wireshield.enums.warningClass;

/**
 * Test class for ScanReport. This class tests the functionality of the
 * ScanReport class, including its constructors, setters, getters, and the
 * toString method.
 */
public class ScanReportTest {

	private ScanReport scanReport;

	/**
	 * Sets up the test environment before each test. Initializes a new ScanReport
	 * object.
	 */
	@Before
	public void setUp() {
		scanReport = new ScanReport(); // Initialize the ScanReport object before each test
		scanReport = new ScanReport(new File("testfile.txt")); // Initialize ScanReport with a scanId and a file
	}

	/**
	 * Tests the default constructor of the ScanReport class. Verifies the default
	 * values of the fields.
	 */
	@Test
	public void testDefaultConstructor() {
		assertNotNull(scanReport); // Verifies that the object is not null
		assertFalse(scanReport.isThreatDetected()); // Default value of threatDetected should be false
		assertEquals("No threat detected", scanReport.getThreatDetails()); // Default threat details
		assertEquals(warningClass.CLEAR, scanReport.getWarningClass()); // Default warning class should be CLEAR
		assertTrue(scanReport.isValidReport()); // The report should be valid by default
	}

	/**
	 * Tests the setFile and getFile methods. Verifies that the file can be
	 * correctly set and retrieved.
	 */
	@Test
	public void testSetAndGetFile() {
		File file = new File("testfile.txt");
		scanReport.setFile(file);
		assertEquals(file, scanReport.getFile()); // Verifies that the set file matches the get file
	}

	/**
	 * Tests the setThreatDetected and getThreatDetected methods. Verifies that the
	 * threat detection status changes based on the warning class.
	 */
	@Test
	public void testSetAndGetThreatDetected() {
		// Set the warning class to DANGEROUS and check if threat is detected
		scanReport.setWarningClass(warningClass.DANGEROUS);
		assertTrue(scanReport.isThreatDetected()); // Threat should be detected with DANGEROUS

		// Set the warning class to CLEAR and check if threat is not detected
		scanReport.setWarningClass(warningClass.CLEAR);
		assertFalse(scanReport.isThreatDetected()); // Threat should not be detected with CLEAR

		// Set the warning class to SUSPICIOUS and check if threat is detected
		scanReport.setWarningClass(warningClass.SUSPICIOUS);
		assertTrue(scanReport.isThreatDetected()); // Threat should be detected with SUSPICIOUS
	}

	/**
	 * Tests the setThreatDetails and getThreatDetails methods. Verifies that threat
	 * details are correctly set and retrieved.
	 */
	@Test
	public void testSetAndGetThreatDetails() {
		scanReport.setThreatDetails("Malware detected");
		assertEquals("Malware detected", scanReport.getThreatDetails()); // Verifies that threat details are updated
																			// correctly
	}

	/**
	 * Tests the setWarningClass and getWarningClass methods. Verifies that the
	 * warning class is correctly set and retrieved.
	 */
	@Test
	public void testSetAndGetWarningClass() {
		scanReport.setWarningClass(warningClass.SUSPICIOUS);
		assertEquals(warningClass.SUSPICIOUS, scanReport.getWarningClass()); // Verifies that the warning class is
																				// updated correctly

		scanReport.setWarningClass(warningClass.CLEAR);
		assertEquals(warningClass.CLEAR, scanReport.getWarningClass()); // Verifies that the warning class is updated
																		// correctly
	}

	/**
	 * Tests the setValid and isValidReport methods. Verifies that the report's
	 * validity status is correctly set and retrieved.
	 */
	@Test
	public void testSetAndGetIsValid() {
		scanReport.setValid(false);
		assertFalse(scanReport.isValidReport()); // Verifies that the report is marked as invalid

		scanReport.setValid(true);
		assertTrue(scanReport.isValidReport()); // Verifies that the report is marked as valid
	}

	/**
	 * Tests the toString method of the ScanReport class. Verifies that the toString
	 * method returns the correct string representation of the ScanReport object.
	 */
	@Test
	public void testToString() {
		// Set values for the test
		File file = new File("testfile.txt");
		scanReport.setFile(file);
		scanReport.setThreatDetected(true);
		scanReport.setThreatDetails("Malware detected");
		scanReport.setWarningClass(warningClass.SUSPICIOUS);
		scanReport.setValid(false);

		// Expected string representation
		String expectedString = "ScanReport {file=testfile.txt, threatDetected=true, threatDetails='Malware detected', warningClass=SUSPICIOUS, isValid=false}";
		assertEquals(expectedString, scanReport.toString()); // Verifies that toString() returns the correct string
																// representation
	}

	/**
	 * Tests the printReport method of the ScanReport class. Verifies that the print
	 * output contains the expected values.
	 */
	@Test
	public void testPrintReport() {
		// Set values for the test
		File file = new File("testfile.txt");
		scanReport.setFile(file);
		scanReport.setThreatDetected(true);
		scanReport.setThreatDetails("Malware detected");
		scanReport.setWarningClass(warningClass.SUSPICIOUS);
		scanReport.setValid(false);

		// Create a ByteArrayOutputStream to capture the printed output
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		PrintStream originalSystemOut = System.out;
		System.setOut(new PrintStream(outputStream));

		// Call the printReport method
		scanReport.printReport();

		// Reset System.out
		System.setOut(originalSystemOut);

		// Verify the printed output
		String printedReport = outputStream.toString();

		// Check that the output contains the expected information
		assertTrue(printedReport.contains("File                : testfile.txt"));
		assertTrue(printedReport.contains("Threat Detected     : Yes"));
		assertTrue(printedReport.contains("Threat Details      : Malware detected"));
		assertTrue(printedReport.contains("Warning Class       : SUSPICIOUS"));
		assertTrue(printedReport.contains("Report Status       : Invalid"));
	}
}
