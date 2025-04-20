package com.wireshield.av;

import java.io.File;
import java.util.UUID;

import com.wireshield.enums.warningClass;

/**
 * Represents the scan report for a file, including threat detection results and
 * details.
 */
public class ScanReport {

	private Boolean threatDetected; // Indicates if a threat was detected
	private String threatDetails; // Details about the detected threat
	private File file; // The file that was scanned
	private warningClass warningState; // The warning classification (CLEAR, SUSPICIOUS, DANGEROUS)
	private Boolean isValid; // Indicates if the scan report is valid
	private final UUID id; // Serialization ID

	/**
	 * Default constructor initializing default values for the scan report.
	 */
	public ScanReport() {
		this.threatDetected = false;
		this.threatDetails = "No threat detected";
		this.warningState = warningClass.CLEAR;
		this.isValid = true;
		this.id = generateUniqueId();
	}

	/**
	 * Constructor initializing the scan report with a scanId and file.
	 * 
	 * @param file The file being scanned
	 */
	public ScanReport(File file) {
		this();
		this.file = file;
	}

	/**
	 * Checks if a threat was detected in the scanned file.
	 *
	 * @return True if a threat was detected, otherwise false.
	 */
	public Boolean isThreatDetected() {
		return threatDetected || 
			   warningState == warningClass.DANGEROUS || 
			   warningState == warningClass.SUSPICIOUS;
	}

	/**
	 * Generates a unique identifier for the peer using UUID.
	 * 
	 * @return A unique identifier string for the peer.
	 * @see java.util.UUID#randomUUID()
	 */
	private static UUID generateUniqueId() {
		return UUID.randomUUID();
	}

	/**
	 * Gets the unique identifier of the scan report.
	 *
	 * @return The unique identifier.
	 */
	public UUID getId() {
		return this.id;
	}

	/**
	 * Sets whether a threat was detected in the scanned file.
	 *
	 * @param threatDetected True if a threat was detected, otherwise false.
	 */
	public void setThreatDetected(Boolean threatDetected) {
		this.threatDetected = threatDetected;
	}

	/**
	 * Gets the details of the detected threat.
	 *
	 * @return The threat details.
	 */
	public String getThreatDetails() {
		return this.threatDetails;
	}


	/**
	 * Sets the details of the detected threat.
	 *
	 * @param threatDetails The threat details to set.
	 */
	public void setThreatDetails(String threatDetails) {
		this.threatDetails = threatDetails;
	}

	/**
	 * Gets the file that was scanned.
	 *
	 * @return The scanned file.
	 */
	public File getFile() {
		return file;
	}

	/**
	 * Sets the file that was scanned.
	 *
	 * @param file The file to set.
	 */
	public void setFile(File file) {
		this.file = file;
	}

	/**
	 * Gets the warning classification of the scan.
	 *
	 * @return The warning classification.
	 */
	public warningClass getWarningClass() {
		return warningState;
	}

	/**
	 * Sets the warning classification of the scan.
	 *
	 * @param warningClass The warning classification to set.
	 */
	public void setWarningClass(warningClass warningClass) {
		this.warningState = warningClass;
	}


	/**
	 * Checks if the scan report is valid.
	 *
	 * @return True if the report is valid, otherwise false.
	 */
	public Boolean isValidReport() {
		return isValid;
	}

	/**
	 * Sets the validity of the scan report.
	 *
	 * @param isValid True if the report is valid, otherwise false.
	 */
	public void setValid(Boolean isValid) {
		this.isValid = isValid;
	}

	/**
	 * Prints the scan report in a structured format.
	 */
	public void printReport() {
		String separator = "-------------------------------------------------";

		System.out.println(separator);
		System.out.println("Scan Report");
		System.out.println(separator);

		// Display all information in a tabular format
		System.out.printf("%-20s: %s%n", "File", file.getName());
		System.out.printf("%-20s: %s%n", "Threat Detected", isThreatDetected() ? "Yes" : "No");
		System.out.printf("%-20s: %s%n", "Threat Details", threatDetails);
		System.out.printf("%-20s: %s%n", "Warning Class", warningState);
		System.out.printf("%-20s: %s%n", "Report Status", isValidReport() ? "Valid" : "Invalid");

		System.out.println(separator);
	}

	/**
	 * @return a string representation of the scan report.
	 */
	@Override
	public String toString() {
		return "ScanReport {" + "file=" + (file != null ? file.getName() : "null")
				+ ", threatDetected=" + threatDetected + ", threatDetails='" + threatDetails + '\'' + ", warningClass="
				+ warningState + ", isValid=" + isValid + '}';
	}
}
