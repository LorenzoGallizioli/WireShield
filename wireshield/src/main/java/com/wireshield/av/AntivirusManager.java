package com.wireshield.av;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;

import javax.swing.JOptionPane;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.wireshield.enums.runningStates;
import com.wireshield.enums.warningClass;

/**
 * Manages antivirus scanning tasks and orchestrates file analysis using ClamAV
 * and VirusTotal. Implements a singleton pattern to ensure a single instance
 * manages all scanning operations.
 */
public class AntivirusManager {

	private static final Logger logger = LogManager.getLogger(AntivirusManager.class);

	private static AntivirusManager instance;

	private ClamAV clamAV;
	private Queue<File> scanBuffer = new LinkedList<>();
	private List<File> filesToRemove = new ArrayList<>();
	private List<ScanReport> finalReports = new ArrayList<>();
	private runningStates scannerStatus;
	private runningStates clamdStatus;

	private Thread scanThread;

	private AntivirusManager() {
		logger.info("AntivirusManager initialized.");
		scannerStatus = runningStates.DOWN;
		clamAV = ClamAV.getInstance();
	}

	/**
	 * Retrieves the singleton instance of the AntivirusManager.
	 *
	 * @return the singleton instance of AntivirusManager.
	 */
	public static synchronized AntivirusManager getInstance() {
		if (instance == null) {
			instance = new AntivirusManager();
		}
		return instance;
	}

	/**
	 * Adds a file to the scan buffer for later analysis.
	 *
	 * @param file the file to add to the scan buffer.
	 */
	public synchronized void addFileToScanBuffer(File file) {
		if (file == null || !file.exists()) {
			logger.error("Invalid file or file does not exist.");
			return;
		}
		if (!scanBuffer.contains(file)) {
			scanBuffer.add(file);
			logger.info("File added to scan buffer: {}", file.getName());
			notifyAll(); // Notify the scanning thread of new file
			
		} else {
			logger.warn("File is already in the scan buffer: {}", file.getName());
		}
	}

	/**
	 * Starts the antivirus scan process in a separate thread. If a scan is already
	 * running, it logs a warning and exits.
	 */
	public void startScan() {
		if (scannerStatus == runningStates.UP) {
			logger.warn("Scan process is already running.");
			return;
		}

		scanThread = new Thread(() -> {
			scannerStatus = runningStates.UP;

			while(clamdStatus == runningStates.DOWN){
				try {
					Thread.sleep(200);
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				}
			};

			performScan();
			scannerStatus = runningStates.DOWN;
		});

		scanThread.setDaemon(true);
		scanThread.start();
	}

	private void performScan(){
		while (!Thread.currentThread().isInterrupted()) {
			File fileToScan;

			if (clamAV == null) {
				logger.error("ClamAV object not exists - Shutting down AV scanner"); 
				Thread.currentThread().interrupt();		
			}

			synchronized (scanBuffer) {
				fileToScan = scanBuffer.poll();
			}

			if (fileToScan == null) {
				synchronized (this) {
					try {
						
						wait();
						
					} catch (InterruptedException e) {
						Thread.currentThread().interrupt();
					}
				}
				continue;
			}
						
			ScanReport finalReport = new ScanReport();
			finalReport.setFile(fileToScan);

			clamAV.analyze(fileToScan);
			ScanReport clamAVReport = clamAV.getReport();
			
			if (clamAVReport != null) mergeReports(finalReport, clamAVReport);

			finalReports.add(finalReport);

			if (finalReport.getWarningClass() == warningClass.DANGEROUS || finalReport.getWarningClass() == warningClass.SUSPICIOUS) {
				logger.warn("Threat detected in file: {}", fileToScan.getName());
				
				JOptionPane.showMessageDialog(null, "Threat detected in file: " + fileToScan.getName(), "Threat Detected", JOptionPane.WARNING_MESSAGE); // Show warning dialog
				filesToRemove.add(fileToScan);
			}
		}
	}

    /*
     * Stops the ongoing antivirus scan process gracefully.
     */
    public void stopScan() {
    	if (scannerStatus == runningStates.DOWN) {
        		logger.warn("No scan process is running.");
        		return;
    	}

		if (scanThread != null && scanThread.isAlive()) {
			scanThread.interrupt();
			
			try {
				scanThread.join(); // Wait for the thread to terminate
			} catch (InterruptedException e) {}
		}
    }



	/**
	 * Sets the ClamAV engine for file analysis.
	 *
	 * @param ClamAV the ClamAV instance.
	 */
	public void setClamAV(ClamAV clamAV) {
		this.clamAV = clamAV;
	}

	/**
	 * return the ClamAV object.
	 *
	 * @return the ClamAV object.
	 */
	public ClamAV getClamAV() {
		return this.clamAV;
	}

	/**
	 * Retrieves the current status of the ClamAV service.
	 *
	 * @return the clamd service status.
	 */
	public runningStates getClamdStatus() {
		return clamdStatus;
	}

	/**
	 * Retrieves the current status of the scanner.
	 *
	 * @return the scanner status.
	 */
	public runningStates getScannerStatus() {
		return scannerStatus;
	}

	/**
	 * Retrieves the list of final scan reports.
	 *
	 * @return the list of scan reports.
	 */
	public List<ScanReport> getFinalReports() {
		return finalReports;
	}

	/**
	 * Retrieves the current state of the scan buffer.
	 *
	 * @return a copy of the scan buffer.
	 */
	public synchronized List<File> getScanBuffer() {
		return new ArrayList<>(scanBuffer);
	}

	/**
	 * Merges details from one scan report into another.
	 *
	 * @param target the target report to be updated.
	 * @param source the source report to merge from.
	 */
	void mergeReports(ScanReport target, ScanReport source) {
		if (source != null && source.isThreatDetected()) {
			target.setThreatDetected(true);
			target.setThreatDetails(source.getThreatDetails());

			if (source.getWarningClass().compareTo(target.getWarningClass()) > 0) {
				target.setWarningClass(source.getWarningClass());
			}
			target.setValid(target.isValidReport() && (source.isValidReport()));
		}
	}
}