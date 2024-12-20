package com.wireshield.av;

import java.io.File;
import java.util.List;
import java.util.ArrayList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.wireshield.enums.runningStates;
import com.wireshield.enums.warningClass;
import java.util.Queue;
import java.util.LinkedList;

/*
 * AntivirusManager manages antivirus scanning of files. 
 * It integrates ClamAV and VirusTotal for scanning files, 
 * tracks the scanning process, and stores the results.
 */
public class AntivirusManager {

    private static final Logger logger = LogManager.getLogger(AntivirusManager.class);

    private ClamAV clamAV; // Instance for ClamAV scanning
    private VirusTotal virusTotal; // Instance for VirusTotal scanning
    private Queue<File> scanBuffer = new LinkedList<>(); // Queue for file handling (FIFO)
    private List<File> filesToRemove = new ArrayList<>(); // Files flagged for removal post-scan
    private List<ScanReport> finalReports = new ArrayList<>(); // Consolidated scan reports
    private runningStates scannerStatus; // Current operational state of the scanner

    private Thread scanThread; // Reference to the thread managing scans
    static final long MAX_FILE_SIZE = 10 * 1024 * 1024; // Max file size for VirusTotal (10 MB)

    /*
     * Constructor to initialize the AntivirusManager.
     * Sets the initial scanner state to DOWN.
     */
    public AntivirusManager() {
        logger.info("AntivirusManager initialized.");
        scannerStatus = runningStates.DOWN;
    }

    /**
     * Adds a file to the scan buffer if it is valid and not already in the queue.
     * Notifies the scanning thread to process the new file.
     *
     * @param file The file to add to the scan buffer.
     */
    public synchronized void addFileToScanBuffer(File file) {
        if (file == null || !file.exists()) {
            logger.error("Invalid file or file does not exist: {}", file);
            return;
        }
        if (!scanBuffer.contains(file)) {
            scanBuffer.add(file);
            logger.info("File added to scan buffer: {}", file.getName());
            notify(); // Notify scanning thread
        } else {
            logger.warn("File is already in the scan buffer: {}", file.getName());
        }
    }

    /*
     * Starts the antivirus scanning process. Scans all files in the buffer until stopped.
     * Prevents multiple scans from running concurrently.
     */
    public void startPerformScan() {
        if (scannerStatus == runningStates.UP) {
            logger.warn("Scan process is already running.");
            return;
        }

        scannerStatus = runningStates.UP;
        logger.info("Starting antivirus scan process...");

        scanThread = new Thread(() -> {
            while (scannerStatus == runningStates.UP) {
                File fileToScan;

                synchronized (scanBuffer) {
                    fileToScan = scanBuffer.poll(); // Retrieve file from the queue
                }

                if (fileToScan == null) {
                    logger.info("No files to scan, waiting for new files...");
                    synchronized (this) {
                        try {
                            wait(); // Wait until a new file is added
                        } catch (InterruptedException e) {
                            logger.error("Scanning interrupted.", e);
                            break;
                        }
                    }
                    continue;
                }

                logger.info("Scanning file: {}", fileToScan.getName());
                ScanReport finalReport = new ScanReport();
                finalReport.setFile(fileToScan);

                // Scan with ClamAV
                if (clamAV != null) {
                    clamAV.analyze(fileToScan);
                    ScanReport clamAVReport = clamAV.getReport();
                    if (clamAVReport != null) {
                        mergeReports(finalReport, clamAVReport);
                    }
                }

                // Scan with VirusTotal if applicable
                if (finalReport.isThreatDetected() && virusTotal != null && fileToScan.length() <= MAX_FILE_SIZE) {
                    logger.info("Scanning with VirusTotal for file: {}", fileToScan.getName());
                    virusTotal.analyze(fileToScan);
                    ScanReport virusTotalReport = virusTotal.getReport();
                    if (virusTotalReport != null) {
                        mergeReports(finalReport, virusTotalReport);
                    }
                } else if (fileToScan.length() > MAX_FILE_SIZE) {
                    logger.warn("File is too large for VirusTotal analysis (> 10 MB): {}", fileToScan.getName());
                }

                // Handle detected threats
                if (finalReport.getWarningClass() == warningClass.DANGEROUS
                        || finalReport.getWarningClass() == warningClass.SUSPICIOUS) {
                    logger.warn("Threat detected in file: {}", fileToScan.getName());
                    filesToRemove.add(fileToScan);
                }

                finalReports.add(finalReport); // Save the final report
                logger.info("Scan completed for file: {}", fileToScan.getName());
                finalReport.printReport();
            }

            logger.info("Scanning process finished or stopped.");
        });

        scanThread.start();
    }

    /*
     * Stops the antivirus scanning process if it is running.
     */
    public void stopPerformScan() {
        if (scannerStatus == runningStates.DOWN) {
            logger.warn("No scan process is running.");
            return;
        }

        scannerStatus = runningStates.DOWN;
        logger.info("Scanning process stopped.");

        if (scanThread != null && scanThread.isAlive()) {
            scanThread.interrupt();
        }
    }

    /**
     * Sets the ClamAV scanner instance for file analysis.
     *
     * @param clamAV The ClamAV instance to set.
     */
    public void setClamAV(ClamAV clamAV) {
        this.clamAV = clamAV;
    }

    /**
     * Sets the VirusTotal scanner instance for file analysis.
     *
     * @param virusTotal The VirusTotal instance to set.
     */
    public void setVirusTotal(VirusTotal virusTotal) {
        this.virusTotal = virusTotal;
    }
    
    /**
     * Returns the current state of the scanner.
     *
     * @return The scanner's operational state.
     */
    public runningStates getScannerStatus() {
        return scannerStatus;
    }

    /**
     * Retrieves the list of final scan reports for all processed files.
     *
     * @return A list of ScanReport objects.
     */
    public List<ScanReport> getFinalReports() {
        return finalReports;
    }

    /**
     * Retrieves the current files in the scan buffer.
     *
     * @return A list of files waiting for scanning.
     */
    public synchronized List<File> getScanBuffer() {
        logger.info("Returning the current state of the scan buffer. Size: {}", scanBuffer.size());
        return new ArrayList<>(scanBuffer);
    }
    
    /**
     * Merges the details from a source ScanReport into a target ScanReport.
     * Updates threat status, details, warning class, and detection counts.
     *
     * @param target The target ScanReport to update.
     * @param source The source ScanReport with additional details.
     */
    void mergeReports(ScanReport target, ScanReport source) {
        if (source != null && source.isThreatDetected()) {
            target.setThreatDetected(true);
            target.setThreatDetails(source.getThreatDetails());

            if (source.getWarningClass().compareTo(target.getWarningClass()) > 0) {
                target.setWarningClass(source.getWarningClass());
            }

            target.setMaliciousCount(target.getMaliciousCount() + source.getMaliciousCount());
            target.setHarmlessCount(target.getHarmlessCount() + source.getHarmlessCount());
            target.setSuspiciousCount(target.getSuspiciousCount() + source.getSuspiciousCount());
            target.setUndetectedCount(target.getUndetectedCount() + source.getUndetectedCount());
        }

        if (source != null && source.getSha256() != null && !source.getSha256().equals(target.getSha256())) {
            target.setSha256(source.getSha256());
        }

        target.setValid(target.isValidReport() && (source != null && source.isValidReport()));
    }
}
