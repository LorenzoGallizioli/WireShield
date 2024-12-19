package com.wireshield.av;

import java.io.File;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.wireshield.enums.warningClass;

/*
 * This class uses ClamAV to scan files for threats, analyzing files via the ClamAV command-line tool (`clamscan.exe`)
 * and generating scan reports based on the results.
 */
public class ClamAV {

	// Logger for ClamAV-related logs
	private static final Logger logger = LogManager.getLogger(ClamAV.class);
	private ScanReport clamavReport;

	// Constructor for initializing ClamAV
	public ClamAV() {
		this.clamavReport = null;
		logger.info("ClamAV initialized.");
	}

	/**
	 * Analyzes a file with ClamAV to check for threats.
	 * 
	 * @param file The file to be scanned.
	 */
	public void analyze(File file) {
		// Check if the file exists before proceeding
		if (file == null || !file.exists()) {
			clamavReport = new ScanReport(); // Initialize the scan report
			clamavReport.setFile(file);
			clamavReport.setValid(false);
			clamavReport.setThreatDetails("File does not exist.");
			clamavReport.setWarningClass(warningClass.CLEAR); // Mark the file as clear (no threat)
			logger.warn("File does not exist: {}", file.getAbsolutePath());
			return;
		}

		try {
			// Define the path to the ClamAV command-line tool (clamscan.exe)
			String clamavPath = "C:\\Program Files\\ClamAV\\clamscan.exe";
			logger.info("ClamAV path: {}", clamavPath);

			// Initialize the process builder to run the ClamAV scan command
			ProcessBuilder processBuilder = new ProcessBuilder(clamavPath, file.getAbsolutePath());
			processBuilder.redirectErrorStream(true); // Redirect error stream to the output stream
			Process process = processBuilder.start(); // Start the scan process

			// Read the output from the ClamAV scan process
			BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
			String line;
			boolean threatDetected = false; // Flag for threat detection
			boolean suspiciousDetected = false; // Flag for suspicious activity detection
			String threatDetails = ""; // To store the threat details

			// Process each line of ClamAV output
			while ((line = reader.readLine()) != null) {
				logger.debug("ClamAV output: {}", line);

				// Check if ClamAV has found a threat
				if (line.contains("FOUND")) {
					threatDetected = true;
					threatDetails = line.substring(line.indexOf(":") + 2, line.lastIndexOf("FOUND")).trim();
					logger.info("Threat detected: {}", threatDetails);
					break; // Stop processing after a threat is found
				}
				// Check if ClamAV has detected suspicious activity
				else if (line.contains("suspicious")) {
					suspiciousDetected = true;
					threatDetails = line.substring(line.indexOf(":") + 2).trim();
					logger.info("Suspicious activity detected: {}", threatDetails);
					break; // Stop processing after suspicious activity is detected
				}
			}

			// Prepare the scan report
			clamavReport = new ScanReport();
			clamavReport.setFile(file);
			clamavReport.setValid(true); // Mark the report as valid
			clamavReport.setThreatDetected(threatDetected || suspiciousDetected); // Mark as true if any threat or suspicious activity detected

			// Handle the detected threats or suspicious activity
			if (threatDetected) {
				clamavReport.setThreatDetails(threatDetails); // Set threat details
				clamavReport.setWarningClass(warningClass.DANGEROUS); // Classify as dangerous
				logger.warn("Threat found, marking as dangerous.");
			} else if (suspiciousDetected) {
				clamavReport.setThreatDetails("Suspicious activity detected");
				clamavReport.setWarningClass(warningClass.SUSPICIOUS); // Classify as suspicious
				logger.warn("Suspicious activity detected, marking as suspicious.");
			} else {
				clamavReport.setThreatDetails("No threat detected");
				clamavReport.setWarningClass(warningClass.CLEAR); // Mark as clear (no threat)
				logger.info("No threat detected.");
			}

			reader.close(); // Close the reader after processing the output

		} catch (IOException e) {
			// Handle errors during the scanning process
			clamavReport = new ScanReport();
			clamavReport.setFile(file);
			clamavReport.setValid(false); // Mark the report as invalid
			clamavReport.setThreatDetails("Error during scan: " + e.getMessage());
			clamavReport.setWarningClass(warningClass.CLEAR); // Mark as clear due to error
			logger.error("Error during scan: {}", e.getMessage(), e); // Log the error details

		}
	}

	// Returns the generated scan report
	public ScanReport getReport() {
		return clamavReport;
	}
}
