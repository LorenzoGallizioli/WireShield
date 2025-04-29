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

	Thread clamdServiceStartThread;
	Thread clamdServiceStopThread;

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
            String clamavPath = FileManager.getConfigValue("CLAMAV_STD_PATH");
			File folder = new File(clamavPath);
			if (folder.exists() && folder.isDirectory()) {
				clamavPath += File.separator + "clamdscan.exe";
			} else {
				logger.error("ClamAV path is not a directory: {}", clamavPath);
				return;
			}

			logger.info("cmd: {}", clamavPath + " " + file.getAbsolutePath());
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
	 * Starts the "clamd" service in a daemon thread if it exists.
	 * If the service is found, attempts to start it and logs the result.
	 */
	public void startClamdService() {

		Runnable clamdServiceTask = () -> {
			String serviceName = "clamd";
			Boolean closeflag = false;

			try {

				if (ServicesUtils.serviceExists(serviceName)) {

					if (ServicesUtils.isServiceRunning(serviceName)) {
						logger.info("Service " + serviceName + " is already running.");
						this.clamdState = runningStates.UP;
						return;
					}

					if (ServicesUtils.startService(serviceName)) {

						while (ServicesUtils.isServiceStarting(serviceName)
								&& !Thread.currentThread().isInterrupted()) {
							logger.info("Service " + serviceName + " is starting... " + closeflag);
							try {
								Thread.sleep(200);
							} catch (InterruptedException e) {
								closeflag = true;
								Thread.currentThread().interrupt();
							}
						}

						if (closeflag) {
							Runtime.getRuntime().addShutdownHook(new Thread(() -> {
								ServicesUtils.stopService(serviceName);
							}));
							closeflag = false;
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

			logger.info("Thread stopped - [startClamdService()] starting clamd service thread terminated.");
		};

		this.clamdServiceStartThread = new Thread(clamdServiceTask);

		this.clamdServiceStartThread.setDaemon(false);
		this.clamdServiceStartThread.start();
	}

	/**
	 * Stops the "clamd" service in a daemon thread if it is currently running.
	 * Checks for service existence and running state before attempting to stop it.
	 */
	public void stopClamdService() {

		Runnable clamdServiceTask = () -> {
			String serviceName = "clamd";

			try {
				if (ServicesUtils.serviceExists(serviceName)) {

					// this method was been called simultaneously with the UI.stopAllThreads()
					// method. The thread interruption was been generating an exeption in
					// isServiceRunning() --> return false;.
					// So, whitout the while loop in UI.closeWindow(), isServiceRunning() returned
					// false even if the service was running.
					// ServicesUtils.isServiceRunning(serviceName);

					if (!ServicesUtils.isServiceRunning(serviceName)) {
						logger.info("Service " + serviceName + " is already not running.");
						this.clamdState = runningStates.DOWN;
						return;
					}

					ServicesUtils.stopService(serviceName);

					while (ServicesUtils.isServiceRunning(serviceName) && !Thread.currentThread().isInterrupted()) {
						try {
							Thread.sleep(200);
						} catch (InterruptedException e) {
							logger.error("Error while waiting for clamd service to start: {}", e.getMessage());
							Thread.currentThread().interrupt();
						}
					}

					this.clamdState = runningStates.DOWN;
					logger.info("Service " + serviceName + " stopped successfully.");
				} else {
					logger.info("Service " + serviceName + " not found.");
				}
			} catch (Exception e) {
				e.printStackTrace();
			}

			logger.info("Thread stopped - [stopClamdService()] stopping clamd service thread terminated.");
		};

		this.clamdServiceStopThread = new Thread(clamdServiceTask);

		this.clamdServiceStopThread.setDaemon(false);
		this.clamdServiceStopThread.start();
	}

	/**
	 * Retrieves the most recent scan report generated by ClamAV.
	 * 
	 * @return The scan report, or null if no scan has been performed.
	 */
	public ScanReport getReport() {
		return this.clamavReport; // Return the most recent scan report
	}

	/**
	 * Retrieves the most recent clamd state.
	 * 
	 * @return runningState.
	 */
	public runningStates getClamdState() {
		return this.clamdState;
	}

	/**
	 * Interrupts all threads associated with the `clamdServiceStart` and
	 * `clamdServiceStop` services, if they are active.
	 * Checks if each thread is not null and is alive before attempting to interrupt
	 * it.
	 */
	public void interruptAllThreads() throws InterruptedException {

		/**
		 * clamdServiceStopThread must stopped before clamdServiceStartThread
		 * in the case of stopping during clamd startup, the fact that
		 * thread.interrupt()
		 * is called on clamdServiceStopThread at this time ensures that the thread will
		 * not be interrupted if started by clamdServiceStartThread
		 */
		if (this.clamdServiceStopThread != null && this.clamdServiceStopThread.isAlive()) {
			this.clamdServiceStopThread.interrupt();
			this.clamdServiceStopThread.join();
		}
		if (this.clamdServiceStartThread != null && this.clamdServiceStartThread.isAlive()) {
			this.clamdServiceStartThread.interrupt();
			this.clamdServiceStartThread.join();
		}
	}

	/**
	 * Updates ClamAV virus definitions using freshclam in a separate thread.
	 * 
	 * This method starts a new thread that runs the freshclam command-line tool
	 * to update the virus definitions. The method takes a callback that is called
	 * when the update is completed.
	 * 
	 * @param onComplete
	 *                   a callback to be called when the update is completed.
	 */
	public void updateFreshClam(Runnable onComplete) {
		Thread freshclamThread = new Thread(() -> {
			try {
				// Retrieve the ClamAV path from the configuration file
				String clamavPath = FileManager.getConfigValue("CLAMAV_STD_PATH");

				// Check if the ClamAV path is valid
				File folder = new File(clamavPath);
				String freshclamPath;

				if (folder.exists() && folder.isDirectory()) {
					// Construct the freshclam command-line path
					freshclamPath = clamavPath + File.separator + "freshclam.exe";
				} else {
					logger.error("ClamAV path is not valid: {}", clamavPath);
					return;
				}

				// Start the freshclam command-line tool
				logger.info("Running freshclam from path: {}", freshclamPath);
				ProcessBuilder processBuilder = new ProcessBuilder(freshclamPath);
				processBuilder.redirectErrorStream(true);
				Process process = processBuilder.start();

				// Wait for the process to complete and log its output
				try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
					String line;
					while ((line = reader.readLine()) != null) {
						logger.info("[freshclam] {}", line);
					}
				}

				// Wait for the process to complete and log its exit code
				int exitCode = process.waitFor();
				logger.info("freshclam exited with code: {}", exitCode);

			} catch (IOException | InterruptedException e) {
				// Handle any errors that occur during the update
				logger.error("Error running freshclam: {}", e.getMessage(), e);
				Thread.currentThread().interrupt();
			} finally {
				// Log a message when the update is complete
				logger.info("Freshclam update completed.");
				if (onComplete != null) {
					// Call the callback when the update is complete
					onComplete.run();
				}
			}
		});

		// Set the thread as a daemon thread so that it does not prevent the JVM from exiting
		freshclamThread.setDaemon(true);
		freshclamThread.start();
	}
}
