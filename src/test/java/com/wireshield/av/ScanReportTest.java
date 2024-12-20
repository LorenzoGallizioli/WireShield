package com.wireshield.av;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

import java.io.File;
import com.wireshield.enums.warningClass;

/*
 * Test class for ScanReport.
 * This class tests the functionality of the ScanReport class, including its constructors, setters, getters, 
 * and the toString method.
 */
public class ScanReportTest {

    private ScanReport scanReport;

    /*
     * Sets up the test environment before each test.
     * Initializes a new ScanReport object.
     */
    @Before
    public void setUp() {
        scanReport = new ScanReport(); // Initialize the ScanReport object before each test
    }

    /*
     * Tests the default constructor of the ScanReport class.
     * Verifies the default values of the fields.
     */
    @Test
    public void testDefaultConstructor() {
        assertNotNull(scanReport);  // Verifies that the object is not null
        assertFalse(scanReport.isThreatDetected());  // Default value of threatDetected should be false
        assertEquals("No threat detected", scanReport.getThreatDetails());  // Default threat details
        assertEquals(warningClass.CLEAR, scanReport.getWarningClass());  // Default warning class should be CLEAR
        assertTrue(scanReport.isValidReport());  // The report should be valid by default
        assertEquals(0, scanReport.getMaliciousCount());  // Default malicious count should be 0
        assertEquals(0, scanReport.getHarmlessCount());  // Default harmless count should be 0
        assertEquals(0, scanReport.getSuspiciousCount());  // Default suspicious count should be 0
        assertEquals(0, scanReport.getUndetectedCount());  // Default undetected count should be 0
    }

    /*
     * Tests the setFile and getFile methods.
     * Verifies that the file can be correctly set and retrieved.
     */
    @Test
    public void testSetAndGetFile() {
        File file = new File("testfile.txt");
        scanReport.setFile(file);
        assertEquals(file, scanReport.getFile());  // Verifies that the set file matches the get file
    }

    /*
     * Tests the setSha256 and getSha256 methods.
     * Verifies that the SHA-256 hash is correctly set and retrieved.
     */
    @Test
    public void testSetAndGetSha256() {
        String sha256 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        scanReport.setSha256(sha256);
        assertEquals(sha256, scanReport.getSha256());  // Verifies that the SHA-256 value is updated correctly
    }

    /*
     * Tests the setThreatDetected and getThreatDetected methods.
     * Verifies that the threat detection status changes based on the warning class.
     */
    @Test
    public void testSetAndGetThreatDetected() {
        // Set the warning class to DANGEROUS and check if threat is detected
        scanReport.setWarningClass(warningClass.DANGEROUS);
        assertTrue(scanReport.isThreatDetected());  // Threat should be detected with DANGEROUS

        // Set the warning class to CLEAR and check if threat is not detected
        scanReport.setWarningClass(warningClass.CLEAR);
        assertFalse(scanReport.isThreatDetected());  // Threat should not be detected with CLEAR

        // Set the warning class to SUSPICIOUS and check if threat is detected
        scanReport.setWarningClass(warningClass.SUSPICIOUS);
        assertTrue(scanReport.isThreatDetected());  // Threat should be detected with SUSPICIOUS
    }

    /*
     * Tests the setThreatDetails and getThreatDetails methods.
     * Verifies that threat details are correctly set and retrieved.
     */
    @Test
    public void testSetAndGetThreatDetails() {
        scanReport.setThreatDetails("Malware detected");
        assertEquals("Malware detected", scanReport.getThreatDetails());  // Verifies that threat details are updated correctly
    }

    /*
     * Tests the setWarningClass and getWarningClass methods.
     * Verifies that the warning class is correctly set and retrieved.
     */
    @Test
    public void testSetAndGetWarningClass() {
        scanReport.setWarningClass(warningClass.SUSPICIOUS);
        assertEquals(warningClass.SUSPICIOUS, scanReport.getWarningClass());  // Verifies that the warning class is updated correctly

        scanReport.setWarningClass(warningClass.CLEAR);
        assertEquals(warningClass.CLEAR, scanReport.getWarningClass());  // Verifies that the warning class is updated correctly
    }

    /*
     * Tests the setValid and isValidReport methods.
     * Verifies that the report's validity status is correctly set and retrieved.
     */
    @Test
    public void testSetAndGetIsValid() {
        scanReport.setValid(false);
        assertFalse(scanReport.isValidReport());  // Verifies that the report is marked as invalid

        scanReport.setValid(true);
        assertTrue(scanReport.isValidReport());  // Verifies that the report is marked as valid
    }

    /*
     * Tests the malicious, harmless, suspicious, and undetected counts.
     * Verifies that the respective counts are correctly updated and retrieved.
     */
    @Test
    public void testDetectionCounts() {
        scanReport.setMaliciousCount(5);
        scanReport.setHarmlessCount(2);
        scanReport.setSuspiciousCount(3);
        scanReport.setUndetectedCount(4);

        assertEquals(5, scanReport.getMaliciousCount());  // Verifies the malicious count
        assertEquals(2, scanReport.getHarmlessCount());  // Verifies the harmless count
        assertEquals(3, scanReport.getSuspiciousCount());  // Verifies the suspicious count
        assertEquals(4, scanReport.getUndetectedCount());  // Verifies the undetected count
    }

    /*
     * Tests the toString method of the ScanReport class.
     * Verifies that the toString method returns the correct string representation of the ScanReport object.
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
        scanReport.setSha256("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

        // Expected string representation
        String expectedString = "ScanReport {scanId='', file=testfile.txt, threatDetected=true, threatDetails='Malware detected', warningClass=SUSPICIOUS, isValid=false, maliciousCount=0, harmlessCount=0, suspiciousCount=0, undetectedCount=0}";
        assertEquals(expectedString, scanReport.toString());  // Verifies that toString() returns the correct string representation
    }
}
