package com.wireshield.av;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.wireshield.enums.runningStates;
import com.wireshield.enums.warningClass;
import com.wireshield.windows.ServicesUtils;

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

	private static ClamAV instance;
	private ScanReport clamavReport;
	private runningStates clamdState = runningStates.DOWN; // State of ClamAV service

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
			this.clamavReport = new ScanReport(); // Initialize an error scan report
			this.clamavReport.setFile(file); // Associate the (invalid) file with the report
			this.clamavReport.setValid(false); // Mark the report as invalid
			this.clamavReport.setThreatDetails("File does not exist."); // Add error details
			this.clamavReport.setWarningClass(warningClass.CLEAR); // Mark as clear (no threat)

			// Log appropriate warnings based on file validity
			if (file == null) {
				logger.warn("il file è nullo."); // Log warning if the file is null
			} else {
				logger.warn("File does not exist: {}", file.getAbsolutePath()); // Log file path if it doesn't exist
			}

			return; // Exit the method as the file is invalid
		}

		try {

			String clamavPath = FileManager.getConfigValue("CLAMAV_STD_PATH");
			File folder = new File(clamavPath);
			if (folder.exists() && folder.isDirectory()) {
				clamavPath += File.separator + "clamdscan.exe";
			} else {
				logger.error("ClamAV path is not a directory: {}", clamavPath);
				return;
			}

			ProcessBuilder processBuilder = new ProcessBuilder(clamavPath, file.getAbsolutePath());
			processBuilder.redirectErrorStream(true);
			Process process = processBuilder.start();

			BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
			String line;
			boolean threatDetected = false;
			boolean suspiciousDetected = false;
			String threatDetails = "";

			while ((line = reader.readLine()) != null) {
				logger.debug("ClamAV output: {}", line);

				if (line.contains("FOUND")) {
					threatDetected = true;

					threatDetails = line.substring(line.indexOf(":") + 2, line.lastIndexOf("FOUND")).trim();
					logger.info("Threat detected: {}", threatDetails);
					break;

				} else if (line.contains("suspicious")) {
					suspiciousDetected = true;
					threatDetails = line.substring(line.indexOf(":") + 2).trim();
					logger.info("Suspicious activity detected: {}", threatDetails);
					break;
				}
				
				this.clamavReport = new ScanReport();
				this.clamavReport.setFile(file);
				this.clamavReport.setValid(true);
				this.clamavReport.setThreatDetected(threatDetected || suspiciousDetected);
				
				if (threatDetected) {
					this.clamavReport.setThreatDetails(threatDetails);
					this.clamavReport.setWarningClass(warningClass.DANGEROUS);
					logger.warn("Threat found, marking as dangerous.");
				} else if (suspiciousDetected) {
					this.clamavReport.setThreatDetails("Suspicious activity detected");
					this.clamavReport.setWarningClass(warningClass.SUSPICIOUS);
					logger.warn("Suspicious activity detected, marking as suspicious.");
				} else {
					this.clamavReport.setThreatDetails("No threat detected");
					this.clamavReport.setWarningClass(warningClass.CLEAR);
					logger.info("No threat detected.");
				}
				
				reader.close();
			}
				
		} catch (IOException e) {
			this.clamavReport = new ScanReport();
			this.clamavReport.setFile(file);
			this.clamavReport.setValid(false);
			this.clamavReport.setThreatDetails("Error during scan: " + e.getMessage());
			this.clamavReport.setWarningClass(warningClass.CLEAR);
			logger.error("Error during scan: {}", e.getMessage(), e);
		}
	}
					

	/**
     * Starts the "clamd" service in a daemon thread if it exists.
     * If the service is found, attempts to start it and logs the result.
     */
	public void startClamdService(){

		Runnable clamdServiceTask = () -> {
			String serviceName = "clamd";

			try {

				if (ServicesUtils.serviceExists(serviceName)) {

					if(ServicesUtils.isServiceRunning(serviceName)) {
						logger.info("Service " + serviceName + " is already running.");
						this.clamdState = runningStates.UP;
						return;
					}

					if(ServicesUtils.startService(serviceName)){

						while(!ServicesUtils.isServiceRunning("clamd")){
							try {
								Thread.sleep(200);
							} catch (InterruptedException e) {
								logger.error("Error while waiting for clamd service to start: {}", e.getMessage());
								Thread.currentThread().interrupt();
							}
						}

						this.clamdState = runningStates.UP;
						logger.info("Service " + serviceName + " started successfully.");

					} else {
						logger.info("Failed to start service " + serviceName);
					}

				} else {
					logger.info("Service " + serviceName + " not found.");
				}
			} catch (Exception e) {
				e.printStackTrace();

			}
		};
		
		Thread clamdServiceThread = new Thread(clamdServiceTask);
		clamdServiceThread.setDaemon(false);
		clamdServiceThread.start();
	}

	/**
     * Stops the "clamd" service in a daemon thread if it is currently running.
     * Checks for service existence and running state before attempting to stop it.
     */
	public void stopClamdService(){

		Runnable clamdServiceTask = () -> {
			String serviceName = "clamd";

			try {
                if (ServicesUtils.serviceExists(serviceName)) {
                    
					if (!ServicesUtils.isServiceRunning(serviceName)) {
						logger.info("Service " + serviceName + " is already not running.");
						this.clamdState = runningStates.DOWN;
						return;
					}

                    ServicesUtils.stopService(serviceName);

					while(ServicesUtils.isServiceRunning("clamd")){
						try {
							Thread.sleep(200);
						} catch (InterruptedException e) {
							logger.error("Error while waiting for clamd service to start: {}", e.getMessage());
							Thread.currentThread().interrupt();
						}
					}
						
					this.clamdState = runningStates.DOWN;
					logger.info("Service " + serviceName + " stopped successfully.");
				}
				else {
                    logger.info("Service " + serviceName + " not found.");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
		};
		Thread clamdServiceThread = new Thread(clamdServiceTask);
		clamdServiceThread.setDaemon(false);
		clamdServiceThread.start();
	}


	/**
	 * Retrieves the most recent scan report generated by ClamAV.
	 * 
	 * @return The scan report, or null if no scan has been performed.
	 */
	public ScanReport getReport() {
		return this.clamavReport; // Return the most recent scan report
	}

	public runningStates getClamdState() {
		return this.clamdState; // Return the current state of the ClamAV service
	}
}
