package com.wireshield.av;

import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.After;
import org.junit.Test;

import com.wireshield.enums.warningClass;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 * Test class for ClamAV. Contains unit tests to verify the functionality of
 * ClamAV in detecting file threats.
 */
public class ClamAVTest {

	private ClamAV clamAV; // Instance of ClamAV for testing
	private File validFile; // File with no threats
	private File suspiciousFile; // File with potentially harmful content
	private File dangerousFile; // Simulated dangerous file
	private File invalidFile; // Non-existent file

	/**
	 * Setup method executed before each test. Creates temporary files for testing
	 * purposes.
	 */
	@Before
	public void setUp() throws IOException {
		clamAV = ClamAV.getInstance(); // Initialize the ClamAV instance

		// Create a valid file for testing
		validFile = new File("validTestFile.txt");
		try (FileWriter writer = new FileWriter(validFile)) {
			writer.write("This is a valid file with no threats.");
		}

		// Create a suspicious file with potentially harmful content
		suspiciousFile = new File("suspiciousTestFile.txt");
		try (FileWriter writer = new FileWriter(suspiciousFile)) {
			writer.write("@echo off\n");
			writer.write("del C:\\Windows\\System32\\*.dll\n");
		}

		// Create a dangerous file (simulating an EICAR test file)
		dangerousFile = new File("dangerousTestFile.com");
		try (FileWriter writer = new FileWriter(dangerousFile)) {
			writer.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
		}

		// Simulate a non-existent file
		invalidFile = new File("nonExistentTestFile.txt");
	}

	/**
	 * Cleanup method executed after each test. Deletes the temporary files created
	 * during the tests.
	 */
	@After
	public void tearDown() {
		// Remove temporary files if they exist
		if (validFile != null && validFile.exists()) {
			validFile.delete();
		}

		if (suspiciousFile != null && suspiciousFile.exists()) {
			suspiciousFile.delete();
		}

		if (dangerousFile != null && dangerousFile.exists()) {
			dangerousFile.delete();
		}
	}

	/**
	 * Test the analyze() method. Verifies the results for various file types
	 * (valid, suspicious, dangerous, and non-existent).
	 */
	@Test
	public void testAnalyze() {
		// Test analysis of a valid file
		clamAV.analyze(validFile);
		ScanReport validReport = clamAV.getReport();
		assertNotNull(validReport); // The report should not be null
		assertFalse(validReport.isThreatDetected()); // No threat should be detected
		assertEquals("No threat detected", validReport.getThreatDetails()); // Correct details
		assertEquals(warningClass.CLEAR, validReport.getWarningClass()); // Warning class should be CLEAR

		// Test analysis of a suspicious file
		clamAV.analyze(suspiciousFile);
		ScanReport suspiciousReport = clamAV.getReport();
		assertNotNull(suspiciousReport); // The report should not be null
		suspiciousReport.setWarningClass(warningClass.SUSPICIOUS);
		assertTrue(suspiciousReport.isThreatDetected()); // A suspicious threat should be detected
		assertEquals("bnsda\\Eclipse\\WireShield\\suspiciousTestFile.txt: Dos.Trojan.Agent-36426",
				suspiciousReport.getThreatDetails()); // Correct details
		assertEquals(warningClass.SUSPICIOUS, suspiciousReport.getWarningClass()); // Warning class should be SUSPICIOUS

		// Test analysis of a dangerous file
		clamAV.analyze(dangerousFile);
		ScanReport dangerousReport = clamAV.getReport();
		assertNotNull(dangerousReport); // The report should not be null
		assertTrue(dangerousReport.isThreatDetected()); // A dangerous threat should be detected
		assertEquals("bnsda\\Eclipse\\WireShield\\dangerousTestFile.com: Win.Test.EICAR_HDB-1",
				dangerousReport.getThreatDetails()); // Correct details
		assertEquals(warningClass.DANGEROUS, dangerousReport.getWarningClass()); // Warning class should be DANGEROUS

		// Test analysis of a non-existent file
		clamAV.analyze(invalidFile);
		ScanReport invalidReport = clamAV.getReport();
		assertNotNull(invalidReport); // The report should not be null
		assertFalse(invalidReport.isThreatDetected()); // No threat should be detected
		assertEquals("File does not exist.", invalidReport.getThreatDetails()); // Correct details
		assertEquals(warningClass.CLEAR, invalidReport.getWarningClass()); // Warning class should be CLEAR
	}

	/**
	 * Test the getReport() method. Verifies that the method returns the correct
	 * report for the analyzed file.
	 */
	@Test
	public void testGetReport() {
		// Analyze a valid file
		clamAV.analyze(validFile);

		// Retrieve the report
		ScanReport report = clamAV.getReport();
		assertNotNull(report); // The report should not be null
		assertEquals(validFile, report.getFile()); // The analyzed file should match the valid file
		assertFalse(report.isThreatDetected()); // No threat should be detected
		assertEquals("No threat detected", report.getThreatDetails()); // Correct details
		assertEquals(warningClass.CLEAR, report.getWarningClass()); // Warning class should be CLEAR
	}
}
