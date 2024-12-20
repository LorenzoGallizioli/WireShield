package com.wireshield.av;

import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.After;
import org.junit.Test;

import com.wireshield.enums.warningClass;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Queue;
import java.util.LinkedList;

public class VirusTotalTest {

    // VirusTotal object to test
    private VirusTotal virusTotal;
    // Example files for testing
    private File validFile;
    private File eicarFile;

    // API Key
    private static final String testApiKey = "895b6aece66d9a168c9822eb4254f2f44993e347c5ea0ddf90708982e857d613";
    
    // A Queue to simulate request timestamps (for testing canMakeRequest method)
    private Queue<Long> requestTimestamps;

    /*
     * Setup method for tests. Creates temporary files to be used during tests. This
     * is run before each test.
     */
    @Before
    public void setUp() throws IOException {
        virusTotal = new VirusTotal(); // Initializes the VirusTotal object to be tested

        // Create temporary files for testing
        validFile = File.createTempFile("validfile", ".txt");
        writeToFile(validFile, "This is a valid file for testing.");

        // Create the EICAR test virus file
        eicarFile = File.createTempFile("eicar_test", ".com");
        writeToFile(eicarFile, "X5O!P%@AP[4\\PZX54(P^)7CC)7}$A*G!");

        // Initialize Queue for rate-limiting tests
        requestTimestamps = new LinkedList<>();
    }

    /*
     * Cleanup method after each test. Deletes the temporary files created for
     * tests. This is run after each test.
     */
    @After
    public void tearDown() {
        // Deletes temporary files after the tests
        if (validFile != null && validFile.exists()) {
            validFile.delete();
        }
        if (eicarFile != null && eicarFile.exists()) {
            eicarFile.delete();
        }
    }

    /**
     * Helper method to write content to a file.
     * 
     * @param file    The file to write to
     * @param content The content to write into the file
     * @throws IOException If an error occurs during file writing
     */
    private void writeToFile(File file, String content) throws IOException {
        FileWriter writer = new FileWriter(file);
        writer.write(content);
        writer.close();
    }

    /*
     * Test for the analyze() method. Verifies that the analysis function produces
     * the correct results for different types of files:
     * 
     * - Valid file - Suspicious file - Non-existent file
     */
    @Test
    public void testAnalyze() throws IOException {
        // Test for the valid file
        virusTotal.analyze(validFile);
        ScanReport validReport = virusTotal.getReport();
        assertNotNull(validReport); // The report should not be null
        assertFalse(validReport.isThreatDetected()); // No threat should be detected
        assertEquals("The file is clean: no threats detected.", validReport.getThreatDetails()); // Correct details
        assertEquals(warningClass.CLEAR, validReport.getWarningClass()); // Warning class should be CLEAR
    }

    /*
     * Test for the analyze() method using the EICAR test virus file. Verifies that
     * the EICAR test file is detected as a threat.
     */
    @Test
    public void testAnalyzeWithEICAR() throws IOException {
        // Analyze the EICAR file
        virusTotal.analyze(eicarFile);
        ScanReport eicarReport = virusTotal.getReport();

        // Assert that it is detected as a threat
        assertNotNull(eicarReport);
        assertTrue(eicarReport.isThreatDetected()); // This should detect the EICAR test virus
        assertEquals("Moderate risk: the file might be harmful.", eicarReport.getThreatDetails()); // Correct details
        assertEquals(warningClass.SUSPICIOUS, eicarReport.getWarningClass()); // Warning class should be suspicious
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
        virusTotal.analyze(validFile);

        // Now test that getReport returns the correct report
        ScanReport report = virusTotal.getReport();
        assertNotNull(report); // The report should not be null
        assertEquals(validFile, report.getFile()); // The analyzed file should match the valid file
        assertFalse(report.isThreatDetected()); // No threat should be detected
        assertEquals("The file is clean: no threats detected.", report.getThreatDetails()); // Correct details
        assertEquals(warningClass.CLEAR, report.getWarningClass()); // Warning class should be CLEAR
    }

    /*
     * Test for uploading and receiving the scan ID via VirusTotal's API.
     */
    @Test
    public void testUploadAndGetScanId() throws IOException {
        // Upload the file to VirusTotal and get the report
        virusTotal.analyze(validFile);
        ScanReport report = virusTotal.getReport();

        // Check if the scan ID was received
        assertNotNull(report.getScanId());
    }

    /*
     * Test the getApiKey() method. Verifies that the API key is correctly read
     * from the file.
     */
    @Test
    public void testGetApiKey() {
        // Simulate reading an API key from the file
        String apiKey = virusTotal.getApiKey();
        assertNotNull(apiKey);  // Ensure the API key is not null
        assertEquals(testApiKey, apiKey); // Check if it matches the expected API key
    }

    /*
     * Test the ensureApiKeyFileExists() method. Verifies that it correctly handles
     * file existence and creates a new API key file if necessary.
     */
    @Test
    public void testEnsureApiKeyFileExists() {
        // Simulate the case where the API key file doesn't exist or is empty
        virusTotal.ensureApiKeyFileExists();

        // Check if the API key file is created
        File apiKeyFile = new File("api_key.txt");
        assertTrue(apiKeyFile.exists()); // Verify the file was created

        // Simulate the file containing a valid API key
        String apiKey = virusTotal.getApiKey();
        assertNotNull(apiKey); // The API key should exist
    }

    /*
     * Test the canMakeRequest() method. Verifies that it respects the request
     * limit and returns true when the limit has not been reached.
     */
    @Test
    public void testCanMakeRequest() {
        // Inizializza l'oggetto VirusTotal
        VirusTotal virusTotal = new VirusTotal();

        // Simula il riempimento della coda con richieste valide
        long currentTime = System.currentTimeMillis();
        System.out.println("Current time: " + currentTime);  // Debug

        for (int i = 0; i < VirusTotal.REQUEST_LIMIT; i++) {
            virusTotal.requestTimestamps.add(currentTime - (i * 10)); // Aggiunge richieste con intervalli minimi
            System.out.println("Added timestamp: " + (currentTime - (i * 10)));  // Debug
        }

        // Ora il limite dovrebbe essere stato raggiunto
        boolean canRequest = virusTotal.canMakeRequest();
        System.out.println("Can make request (before adding new): " + canRequest);  // Debug

        // Dovrebbe restituire false, quindi l'asserzione assertFalse dovrebbe passare
        assertFalse(canRequest);

        // Simula il passare del tempo e l'aggiunta di una nuova richiesta
        virusTotal.requestTimestamps.poll(); // Rimuove una richiesta vecchia
        System.out.println("Removed one old request. Current timestamps: " + virusTotal.requestTimestamps);  // Debug

        canRequest = virusTotal.canMakeRequest();
        System.out.println("Can make request (after adding new): " + canRequest);  // Debug

        // Ora dovrebbe essere consentito fare una richiesta, quindi l'asserzione assertTrue dovrebbe passare
        assertTrue(canRequest);
    }

}