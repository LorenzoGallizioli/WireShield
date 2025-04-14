package com.wireshield.av;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
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
     *             on the filesystem. If the file is invalid, the method will create
     *             an appropriate error report.
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
                logger.warn("The file is null."); // Log warning if the file is null
            } else {
                logger.warn("File does not exist: {}", file.getAbsolutePath()); // Log file path if it doesn't exist
            }

            return; // Exit the method as the file is invalid
        }

        try {
            // Define the path to the ClamAV executable
            String clamavPath = "C:\\Program Files\\ClamAV\\clamscan.exe";
            logger.info("ClamAV path: {}", clamavPath); // Log the path for debugging purposes

            File clamavExecutable = new File(clamavPath);
            if (!clamavExecutable.exists()) {
                throw new IOException("ClamAV executable not found at: " + clamavPath);
            }

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
            int exitCode = process.waitFor();
            logger.info("ClamAV process exited with code: {}", exitCode);

        } catch (IOException e) {
            // Handle exceptions during the scanning process
            clamavReport = new ScanReport(); // Create an error scan report
            clamavReport.setFile(file); // Associate the file with the report
            clamavReport.setValid(false); // Mark the report as invalid
            clamavReport.setThreatDetails("Error during scan: " + e.getMessage()); // Add error details
            clamavReport.setWarningClass(warningClass.CLEAR); // Mark as clear (no threats due to error)
            logger.error("Error during scan: {}", e.getMessage(), e); // Log the exception details

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); // To restore the interrupted state
            clamavReport = new ScanReport();
            clamavReport.setFile(file);
            clamavReport.setValid(false);
            clamavReport.setThreatDetails("Scan interrupted: " + e.getMessage());
            clamavReport.setWarningClass(warningClass.CLEAR);
            logger.error("Scan interrupted: {}", e.getMessage(), e);
        }
    }

    /**
     * Asks the user what to do with the file after the scan.
     * If the file was found to be infected or suspicious, asks the user to delete the file or restore it
     * from quarantine.
     * If the user chooses to delete the file, deletes the associated metadata file as well.
     * If the user chooses to restore the file, restores the file from quarantine and updates the report
     * to reference the restored file.
     * If the user enters an invalid input, the file remains in quarantine.
     * @param file the file to process
     */
    public void postScanActions(File file) {
        // Only if the file was found to be infected or suspicious
        if (clamavReport.getWarningClass() == warningClass.DANGEROUS
                || clamavReport.getWarningClass() == warningClass.SUSPICIOUS) {

            // Don't close the scanner inside the method
            Scanner scanner = new Scanner(System.in); // Keep the scanner open
            try {
                // Ask the user what to do with the file
                System.out.println("The file " + file.getAbsolutePath() + " was found to be infected or suspicious.");
                System.out.println("1. Delete the file");
                System.out.println("2. Restore the file");

                String userChoice = scanner.nextLine().trim(); // Read the user's choice

                if ("1".equals(userChoice)) {
                    // The user chose to delete the file
                    boolean fileDeleted = false;

                    // Check if the file was renamed with the .blocked extension
                    String blockedFilePath = file.getAbsolutePath() + ".blocked";
                    File blockedFile = new File(blockedFilePath);

                    // If the renamed file exists, try to delete it
                    if (blockedFile.exists()) {
                        if (blockedFile.delete()) {
                            logger.info("Infected file deleted: {}", blockedFile.getAbsolutePath());
                            fileDeleted = true;
                        } else {
                            logger.error("Error deleting the infected file: {}", blockedFile.getAbsolutePath());
                        }
                    } else {
                        // If the renamed file doesn't exist, delete the original file
                        if (file.delete()) {
                            logger.info("File deleted: {}", file.getAbsolutePath());
                            fileDeleted = true;
                        } else {
                            logger.error("Error deleting the file: {}", file.getAbsolutePath());
                        }
                    }

                    // Delete the associated metadata file as well
                    if (fileDeleted) {
                        // Determine the path of the metadata file
                        Path metadataPath = Paths.get(file.getAbsolutePath() + ".meta");
                        try {
                            if (Files.deleteIfExists(metadataPath)) {
                                logger.info("Metadata file deleted: {}", metadataPath);
                                clamavReport.setThreatDetails("File and metadata deleted by user.");
                            } else {
                                logger.warn("Metadata file not found: {}", metadataPath);
                                clamavReport.setThreatDetails("File deleted by user. Metadata not found.");
                            }
                        } catch (IOException e) {
                            logger.error("Error deleting the metadata file: {}", metadataPath, e);
                            clamavReport.setThreatDetails("File deleted, but error deleting metadata.");
                        }
                        clamavReport.setWarningClass(warningClass.CLEAR);
                    } else {
                        clamavReport.setThreatDetails("Error deleting the file.");
                        clamavReport.setWarningClass(warningClass.CLEAR);
                    }
                }

                else if ("2".equals(userChoice)) {
                    // The user chose to restore the file
                    File blockedFile = new File(file.getAbsolutePath() + ".blocked"); // Check if the file was renamed

                    // If the renamed file exists, unblock it and restore it from quarantine
                    if (blockedFile.exists()) {
                        // Remove the .blocked extension to get the original file name
                        File unblockedFile = FileManager.unblockFileExecution(blockedFile); // Function that removes the .blocked extension

                        if (unblockedFile != null) {
                            // Once the file is unblocked, restore it from quarantine
                            File restoredFile = antivirusManager.restoreFromQuarantine(unblockedFile);

                            if (restoredFile != null) {
                                logger.info("Infected file restored from quarantine: {}",
                                        restoredFile.getAbsolutePath());

                                // Update the report to reference the restored file
                                clamavReport.setFile(restoredFile);
                                clamavReport.setThreatDetails("No threat detected after restore"); // Indicates that no threats were found after restore
                                clamavReport.setWarningClass(warningClass.CLEAR); // Marks the file as clear
                            } else {
                                logger.error("Failed to restore infected file from quarantine: {}",
                                        unblockedFile.getAbsolutePath());
                                clamavReport.setThreatDetails("Infected file restoration failed"); // Indicates that the restore failed
                                clamavReport.setWarningClass(warningClass.DANGEROUS); // Keeps the warning class
                            }
                        } else {
                            logger.error("Failed to unblock infected file: {}", blockedFile.getAbsolutePath());
                            clamavReport.setThreatDetails("Failed to unblock infected file"); // Indicates that the file was not unblocked
                            clamavReport.setWarningClass(warningClass.DANGEROUS); // Keeps the warning class
                        }
                    } else {
                        // If the file was not renamed or not found, restore the original file
                        File restoredFile = antivirusManager.restoreFromQuarantine(file);

                        if (restoredFile != null) {
                            logger.info("Clean file restored from quarantine: {}", restoredFile.getAbsolutePath());

                            // Update the report to reference the restored file
                            clamavReport.setFile(restoredFile);
                            clamavReport.setThreatDetails("No threat detected"); // Indicates that no threats were found
                            clamavReport.setWarningClass(warningClass.CLEAR); // Marks the file as clear
                        } else {
                            logger.error("Failed to restore clean file from quarantine: {}", file.getAbsolutePath());
                            clamavReport.setThreatDetails("No threat detected but restoration failed"); // Indicates that no threats were found, but the restore failed
                            clamavReport.setWarningClass(warningClass.CLEAR); // Marks the file as clear
                        }
                    }

                } else {
                    // Invalid input, so the file remains in quarantine
                    logger.warn("Invalid choice, file remains in quarantine.");
                    clamavReport.setThreatDetails("Invalid choice, file remains in quarantine.");
                    clamavReport.setWarningClass(warningClass.SUSPICIOUS); // Or DANGEROUS
                }
            } catch (Exception e) {
                logger.error("Error reading user's choice.", e);
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
