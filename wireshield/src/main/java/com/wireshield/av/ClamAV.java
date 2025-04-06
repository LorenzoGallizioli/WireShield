package com.wireshield.av;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

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

	/**
	 * Private constructor to enforce Singleton pattern. Initializes ClamAV and logs
	 * the creation of the instance.
	 */
	private ClamAV() {
		this.clamavReport = null; // Initialize the scan report as null
		logger.info("ClamAV initialized.");
	}

	/**
	 * Retrieves the Singleton instance of ClamAV. Ensures that only one instance of
	 * this class is created and used throughout the application.
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
	 * includes information about whether the file contains threats or suspicious
	 * activity.
	 * 
	 * @param file The file to be analyzed. It must not be null and must exist on
	 *             the filesystem. If the file is invalid, the method will create an
	 *             appropriate error report.
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

			// Populate the scan report based on the analysis results
			if (threatDetected) {
				clamavReport.setThreatDetails(threatDetails); // Add threat details
				clamavReport.setWarningClass(warningClass.DANGEROUS); // Classify the file as dangerous
				logger.warn("Threat found, marking as dangerous."); // Log the classification
			} else if (suspiciousDetected) {
				clamavReport.setThreatDetails("Suspicious activity detected"); // Add suspicious details
				clamavReport.setWarningClass(warningClass.SUSPICIOUS); // Classify the file as suspicious
				logger.warn("Suspicious activity detected, marking as suspicious."); // Log the classification
			} else {
				clamavReport.setThreatDetails("No threat detected"); // Indicate no threats
				clamavReport.setWarningClass(warningClass.CLEAR); // Mark the file as clear
				logger.info("No threat detected."); // Log the result
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

	/**
	 * Retrieves the most recent scan report generated by ClamAV.
	 * 
	 * @return The scan report, or null if no scan has been performed.
	 */
	public ScanReport getReport() {
		return clamavReport; // Return the most recent scan report
	}
}
