package com.wireshield.av;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Scanner;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.wireshield.enums.warningClass;

/**
 * Implements antivirus scanning functionality using ClamAV. This class uses the
 * ClamAV command-line tool (`clamscan.exe`) to analyze files for potential
 * threats. It processes the output from ClamAV to generate detailed scan
 * reports. This class follows the Singleton design pattern to ensure a single
 * instance is used throughout the application.
 */
public class ClamAV implements AVInterface {

    // Logger for logging ClamAV-related information and errors.
    private static final Logger logger = LogManager.getLogger(ClamAV.class);

    // Singleton instance of ClamAV.
    private static ClamAV instance;
    // Scan report generated after the most recent file analysis.
    private ScanReport clamavReport;

    // Manager for handling file operations
    private AntivirusManager antivirusManager;

    /**
     * Private constructor to enforce Singleton pattern. Initializes ClamAV and
     * logs the creation of the instance.
     */
    private ClamAV() {
        this.clamavReport = null; // Initialize the scan report as null
        this.antivirusManager = AntivirusManager.getInstance(); // Get instance of AntivirusManager
        logger.info("ClamAV initialized.");
    }

    /**
     * Retrieves the Singleton instance of ClamAV. Ensures that only one
     * instance of this class is created and used throughout the application.
     *
     * @return The single instance of ClamAV.
     */
    public static synchronized ClamAV getInstance() {
        if (instance == null) {
            instance = new ClamAV();
        }
        return instance;
    }

    /**
     * Analyzes a file for potential threats using ClamAV. This method interacts
     * with the ClamAV command-line tool (`clamscan.exe`) to scan the specified
     * file. The scan results are processed and stored in a scan report, which
     * includes information about whether the file contains threats or
     * suspicious activity.
     *
     * @param file The file to be analyzed. It must not be null and must exist
     * on the filesystem. If the file is invalid, the method will create an
     * appropriate error report.
     */
    public void analyze(File file) {
        // Check if the file is null or does not exist
        if (file == null || !file.exists()) {
            clamavReport = new ScanReport(); // Initialize an error scan report
            clamavReport.setFile(file); // Associate the (invalid) file with the report
            clamavReport.setValid(false); // Mark the report as invalid
            clamavReport.setThreatDetails("File does not exist."); // Add error details
            clamavReport.setWarningClass(warningClass.CLEAR); // Mark as clear (no threat)

            // Log appropriate warnings based on file validity
            if (file == null) {
                logger.warn("il file è nullo."); // Log warning if the file is null
            } else {
                logger.warn("File does not exist: {}", file.getAbsolutePath()); // Log file path if it doesn't exist
            }

            return; // Exit the method as the file is invalid
        }

        try {
            // Define the path to the ClamAV executable
            String clamavPath = "C:\\Program Files\\ClamAV\\clamscan.exe";
            logger.info("ClamAV path: {}", clamavPath); // Log the path for debugging purposes

            // Create a ProcessBuilder to execute the ClamAV scan
            ProcessBuilder processBuilder = new ProcessBuilder(clamavPath, file.getAbsolutePath());
            processBuilder.redirectErrorStream(true); // Redirect error stream to standard output
            Process process = processBuilder.start(); // Start the ClamAV process

            // BufferedReader to capture ClamAV's output
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line; // Holds each line of output from ClamAV
            boolean threatDetected = false; // Flag for detected threats
            boolean suspiciousDetected = false; // Flag for detected suspicious activity
            String threatDetails = ""; // To store detailed information about threats

            // Process each line of ClamAV's output
            while ((line = reader.readLine()) != null) {
                logger.debug("ClamAV output: {}", line); // Log each line for debugging

                // Check for threats in the output
                if (line.contains("FOUND")) {
                    threatDetected = true; // Set the threat flag to true

                    // Extract threat details from the output line
                    threatDetails = line.substring(line.indexOf(":") + 2, line.lastIndexOf("FOUND")).trim();
                    logger.info("Threat detected: {}", threatDetails); // Log the detected threat
                    break; // Stop processing further lines

                } else if (line.contains("suspicious")) { // Check for suspicious activity
                    suspiciousDetected = true; // Set the suspicious flag to true
                    // Extract details about the suspicious activity
                    threatDetails = line.substring(line.indexOf(":") + 2).trim();
                    logger.info("Suspicious activity detected: {}", threatDetails); // Log suspicious activity
                    break; // Stop processing further lines
                }
            }

            // Create and populate the scan report
            clamavReport = new ScanReport();
            clamavReport.setFile(file); // Associate the scanned file with the report
            clamavReport.setValid(true); // Mark the report as valid
            clamavReport.setThreatDetected(threatDetected || suspiciousDetected); // Set the detection flag

            // Process the file based on the scan results
            if (threatDetected || suspiciousDetected) {
                // Update file status in quarantine metadata
                antivirusManager.updateQuarantineStatus(file, true, threatDetails);

                // Block file execution for infected files
                FileManager.blockFileExecution(file);

                // Set appropriate warning class and details
                if (threatDetected) {
                    clamavReport.setThreatDetails(threatDetails); // Add threat details
                    clamavReport.setWarningClass(warningClass.DANGEROUS); // Classify the file as dangerous
                    logger.warn("Threat found, marking as dangerous and keeping in quarantine."); // Log the classification
                } else {
                    clamavReport.setThreatDetails("Suspicious activity detected"); // Add suspicious details
                    clamavReport.setWarningClass(warningClass.SUSPICIOUS); // Classify the file as suspicious
                    logger.warn("Suspicious activity detected, marking as suspicious and keeping in quarantine."); // Log the classification
                }
                // Now, interact with the user to decide what to do
                postScanActions(file);

            } else {

                // File is clean, restore it from quarantine
                File restoredFile = antivirusManager.restoreFromQuarantine(file);

                if (restoredFile != null) {
                    logger.info("Clean file restored from quarantine: {}", restoredFile.getAbsolutePath());

                    // Update the report to reference the restored file
                    clamavReport.setFile(restoredFile);
                    clamavReport.setThreatDetails("No threat detected"); // Indicate no threats
                    clamavReport.setWarningClass(warningClass.CLEAR); // Mark the file as clear
                } else {
                    logger.error("Failed to restore clean file from quarantine: {}", file.getAbsolutePath());
                    clamavReport.setThreatDetails("No threat detected but restoration failed"); // Indicate no threats but restoration failed
                    clamavReport.setWarningClass(warningClass.CLEAR); // Mark the file as clear
                }
            }

            reader.close(); // Close the reader after processing output

        } catch (IOException e) {
            // Handle exceptions during the scanning process
            clamavReport = new ScanReport(); // Create an error scan report
            clamavReport.setFile(file); // Associate the file with the report
            clamavReport.setValid(false); // Mark the report as invalid
            clamavReport.setThreatDetails("Error during scan: " + e.getMessage()); // Add error details
            clamavReport.setWarningClass(warningClass.CLEAR); // Mark as clear (no threats due to error)
            logger.error("Error during scan: {}", e.getMessage(), e); // Log the exception details
        }
    }

    public void postScanActions(File file) {
        // Solo se il file è stato trovato infetto o sospetto
        if (clamavReport.getWarningClass() == warningClass.DANGEROUS || clamavReport.getWarningClass() == warningClass.SUSPICIOUS) {
            Scanner scanner = new Scanner(System.in);

            // Chiedi cosa fare con il file
            System.out.println("Il file " + file.getAbsolutePath() + " è stato trovato infetto o sospetto.");
            System.out.println("1. Cancellare il file");
            System.out.println("2. Ripristinare il file");
            System.out.println("3. Lasciare il file in quarantena");

            String userChoice = scanner.nextLine().trim();

            if ("1".equals(userChoice)) {
                // L'utente ha scelto di cancellare il file
                if (file.delete()) {
                    logger.info("File cancellato: {}", file.getAbsolutePath());
                    clamavReport.setThreatDetails("File deleted by user.");
                    clamavReport.setWarningClass(warningClass.CLEAR);
                } else {
                    logger.error("Errore durante la cancellazione del file: {}", file.getAbsolutePath());
                    clamavReport.setThreatDetails("Error deleting the file.");
                    clamavReport.setWarningClass(warningClass.CLEAR);
                }
            } else if ("2".equals(userChoice)) {
                // L'utente ha scelto di ripristinare il file
                File restoredFile = antivirusManager.restoreFromQuarantine(file);
                if (restoredFile != null) {
                    logger.info("File ripristinato dalla quarantena: {}", restoredFile.getAbsolutePath());
                    clamavReport.setThreatDetails("File restored from quarantine.");
                    clamavReport.setWarningClass(warningClass.CLEAR);
                } else {
                    logger.error("Errore durante il ripristino del file: {}", file.getAbsolutePath());
                    clamavReport.setThreatDetails("Error restoring the file.");
                    clamavReport.setWarningClass(warningClass.CLEAR);
                }
            } else if ("3".equals(userChoice)) {
                // L'utente ha scelto di lasciare il file in quarantena
                logger.info("File lasciato in quarantena: {}", file.getAbsolutePath());
                clamavReport.setThreatDetails("File left in quarantine.");
                clamavReport.setWarningClass(warningClass.SUSPICIOUS); // Puoi anche usare DANGEROUS a seconda della minaccia
            } else {
                // Input non valido, quindi rimaniamo nella quarantena
                logger.warn("Scelta non valida, il file rimarrà in quarantena.");
                clamavReport.setThreatDetails("Invalid choice, file remains in quarantine.");
                clamavReport.setWarningClass(warningClass.SUSPICIOUS); // O DANGEROUS
            }
        }
    }

    /**
     * Retrieves the most recent scan report generated by ClamAV.
     *
     * @return The scan report, or null if no scan has been performed.
     */
    public ScanReport getReport() {
        return clamavReport; // Return the most recent scan report
    }
}
