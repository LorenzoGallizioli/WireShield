package com.wireshield.av;

import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.After;
import org.junit.Test;

import com.wireshield.enums.warningClass;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/*
 * Test class for ClamAV. This class contains unit tests for the ClamAV class to verify
 * its functionality in detecting threats in files.
 */
public class ClamAVTest {

    // ClamAV object to test
    private ClamAV clamAV;  
    // Example files for testing
    private File validFile;
    private File suspiciousFile;
    private File invalidFile;

    /*
     * Setup method for tests. Creates temporary files to be used during tests.
     * This is run before each test.
     */
    @Before
    public void setUp() throws IOException {
        clamAV = new ClamAV();  // Initializes the ClamAV object to be tested

        // Create temporary files for testing
        validFile = File.createTempFile("validfile", ".txt");
        writeToFile(validFile, "This is a valid file for testing.");

        suspiciousFile = File.createTempFile("suspiciousfile", ".txt");
        writeToFile(suspiciousFile, "Suspicious content for testing.");

        invalidFile = new File("nonexistentfile.txt");  // Non-existent file
    }

    /*
     * Cleanup method after each test. Deletes the temporary files created for tests.
     * This is run after each test.
     */
    @After
    public void tearDown() {
        // Deletes temporary files after the tests
        if (validFile != null && validFile.exists()) {
            validFile.delete();
        }
        if (suspiciousFile != null && suspiciousFile.exists()) {
            suspiciousFile.delete();
        }
        if (invalidFile != null && invalidFile.exists()) {
            invalidFile.delete();
        }
    }

    /**
     * Helper method to write content to a file.
     * 
     * @param file The file to write to
     * @param content The content to write into the file
     * @throws IOException If an error occurs during file writing
     */
    private void writeToFile(File file, String content) throws IOException {
        FileWriter writer = new FileWriter(file);
        writer.write(content);
        writer.close();
    }

    /*
     * Test for the analyze() method. Verifies that the analysis function
     * produces the correct results for different types of files:
     * 
     * - Valid file
     * - Suspicious file
     * - Non-existent file
     */
    @Test
    public void testAnalyze() throws IOException {
        // Test for the valid file
        clamAV.analyze(validFile);
        ScanReport validReport = clamAV.getReport();
        assertNotNull(validReport);  // The report should not be null
        assertFalse(validReport.isThreatDetected());  // No threat should be detected
        assertEquals("No threat detected", validReport.getThreatDetails());  // Correct details
        assertEquals(warningClass.CLEAR, validReport.getWarningClass());  // Warning class should be CLEAR

        // Test for the suspicious file
        clamAV.analyze(suspiciousFile);
        ScanReport suspiciousReport = clamAV.getReport();
        assertNotNull(suspiciousReport);  // The report should not be null
        assertTrue(suspiciousReport.isThreatDetected());  // A suspicious threat should be detected
        assertEquals("Suspicious activity detected", suspiciousReport.getThreatDetails());  // Correct details
        assertEquals(warningClass.SUSPICIOUS, suspiciousReport.getWarningClass());  // Warning class should be SUSPICIOUS

        // Test for the non-existent file
        clamAV.analyze(invalidFile);
        ScanReport invalidReport = clamAV.getReport();
        assertNotNull(invalidReport);  // The report should not be null
        assertFalse(invalidReport.isThreatDetected());  // No threat should be detected
        assertEquals("File does not exist.", invalidReport.getThreatDetails());  // Correct details
        assertEquals(warningClass.CLEAR, invalidReport.getWarningClass());  // Warning class should be CLEAR
    }

    /*
     * Test for the getReport() method. Verifies that getReport returns the correct
     * report after analyzing a valid file.
     * 
     * Verifies that the report contains the correct details for the analyzed file.
     */
    @Test
    public void testGetReport() throws IOException {
        // First, analyze the valid file
        clamAV.analyze(validFile);

        // Now test that getReport returns the correct report
        ScanReport report = clamAV.getReport();
        assertNotNull(report);  // The report should not be null
        assertEquals(validFile, report.getFile());  // The analyzed file should match the valid file
        assertFalse(report.isThreatDetected());  // No threat should be detected
        assertEquals("No threat detected", report.getThreatDetails());  // Correct details
        assertEquals(warningClass.CLEAR, report.getWarningClass());  // Warning class should be CLEAR
    }
}
