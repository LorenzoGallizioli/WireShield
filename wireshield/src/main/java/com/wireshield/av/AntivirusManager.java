package com.wireshield.av;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
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

    private Thread scanThread;

    private AntivirusManager() {
        logger.info("AntivirusManager initialized.");
        scannerStatus = runningStates.DOWN;
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
     * Starts the antivirus scan process in a separate thread. If a scan is
     * already running, it logs a warning and exits.
     */
    public void startScan() {
        if (scannerStatus == runningStates.UP) {
            logger.warn("Scan process is already running.");
            return;
        }
        scannerStatus = runningStates.UP;
        logger.info("Starting antivirus scan process...");

        scanThread = new Thread(() -> {

            performScan();

        });

        scanThread.setDaemon(true);
        scanThread.start();
    }

    private void performScan() {
        while (!Thread.currentThread().isInterrupted()) {
            File fileToScan;

            if (clamAV == null) {
                logger.error("ClamAV object not exists - Shutting down AV scanner");
                Thread.currentThread().interrupt();
            }

            // Retrieve the next file to scan from the buffer
            synchronized (scanBuffer) {
                fileToScan = scanBuffer.poll();
            }

            // Wait for new files if the buffer is empty
            if (fileToScan == null) {
                synchronized (this) {
                    try {

                        wait();

                    } catch (InterruptedException e) {
                        // error occurred - Shut down service
                        Thread.currentThread().interrupt();
                    }
                }
                continue;
            }

            // Create a new scan report for the file
            ScanReport finalReport = new ScanReport();
            finalReport.setFile(fileToScan);

            // Analyze the file using ClamAV
            clamAV.analyze(fileToScan);
            ScanReport clamAVReport = clamAV.getReport();

            if (clamAVReport != null)
                mergeReports(finalReport, clamAVReport);

            // Add the final report to the results list
            finalReports.add(finalReport);

            // If the file is dangerous or suspicious, take action
            if (finalReport.getWarningClass() == warningClass.DANGEROUS
                    || finalReport.getWarningClass() == warningClass.SUSPICIOUS) {
                logger.warn("Threat detected in file: {}", fileToScan.getName());

                JOptionPane.showMessageDialog(null, "Threat detected in file: " + fileToScan.getName(),
                        "Threat Detected", JOptionPane.WARNING_MESSAGE); // Show warning dialog
                filesToRemove.add(fileToScan);
            }
        }
        scannerStatus = runningStates.DOWN;
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
            } catch (InterruptedException e) {
            }
        }
    }

    /**
     * Sets the ClamAV engine for file analysis.
     *
     * @param clamAV the ClamAV instance.
     */
    public void setClamAV(ClamAV clamAV) {
        this.clamAV = clamAV;
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

    /**
     * Moves the specified file to a quarantine directory for further analysis.
     * The file is relocated to a hidden '.QUARANTINE' folder within the user's
     * Downloads directory. If the file already exists in quarantine, it is left
     * unchanged. Metadata about the file, including its original path and size,
     * is stored in a separate metadata file.
     *
     * If the quarantine directory does not exist, it is created and made hidden.
     * Access control lists (ACLs) are set to ensure full access for the program
     * while restricting other users to read-only access.
     *
     * @param originalFile the file to be moved to quarantine
     * @return the quarantined file, or null if an error occurs
     */
    public File moveToQuarantine(File originalFile) {
        if (originalFile == null || !originalFile.exists()) {
            logger.warn("File is null or does not exist, cannot quarantine it.");
            return null;
        }

        // Check if the file is already in quarantine
        String quarantineDirPath = System.getProperty("user.home") + File.separator + "Downloads" + File.separator
                + ".QUARANTINE";
        if (originalFile.getAbsolutePath().startsWith(quarantineDirPath)) {
            logger.info("File is already in quarantine: {}", originalFile.getAbsolutePath());
            return originalFile;
        }

        // Create the quarantine directory inside "Downloads"
        String downloadsDirPath = System.getProperty("user.home") + File.separator + "Downloads";
        Path quarantineDir = Paths.get(downloadsDirPath, ".QUARANTINE");

        try {
            if (!Files.exists(quarantineDir)) {
                Files.createDirectories(quarantineDir);

                // Make the directory hidden in Windows
                Files.setAttribute(quarantineDir, "dos:hidden", true);
                logger.info("Created quarantine directory: {}", quarantineDir);

                try {
                    AclFileAttributeView aclAttrView = Files.getFileAttributeView(quarantineDir,
                            AclFileAttributeView.class);

                    if (aclAttrView != null) {
                        // Service for getting the user from the system
                        UserPrincipalLookupService lookupService = FileSystems.getDefault()
                                .getUserPrincipalLookupService();

                        // Get the current user (who is an administrator)
                        UserPrincipal currentUser = lookupService
                                .lookupPrincipalByName(System.getProperty("user.name"));

                        // Full access for the program (administrator) - read, write, delete
                        AclEntry fullAccess = AclEntry.newBuilder()
                                .setType(AclEntryType.ALLOW)
                                .setPrincipal(currentUser) // The program administrator
                                .setPermissions(AclEntryPermission.values()) // Full permissions
                                .build();

                        // Read-only for **all** other users (both local and non-local)
                        AclEntry readOnlyAccess = AclEntry.newBuilder()
                                .setType(AclEntryType.ALLOW)
                                .setPrincipal(lookupService.lookupPrincipalByName("Everyone")) // SID for Everyone apply read-only for all users
                                .setPermissions(
                                        AclEntryPermission.READ_DATA,
                                        AclEntryPermission.READ_ATTRIBUTES,
                                        AclEntryPermission.READ_ACL)
                                .build();

                        // Set the ACL for the quarantine directory
                        // - Full access for the program (administrator)
                        // - Read-only for **all** other users
                        aclAttrView.setAcl(Arrays.asList(fullAccess, readOnlyAccess));
                        logger.info("Set ACL: full access for the program (administrator), read-only for all users.");
                    }
                } catch (IOException e) {
                    logger.warn("Error setting ACL on quarantine", e);
                }
            }

            // Generate a unique file name
            String quarantineFileName = originalFile.getName();
            Path targetPath = quarantineDir.resolve(quarantineFileName);
            int counter = 1;
            while (Files.exists(targetPath)) {
                String baseName = quarantineFileName;
                String extension = "";
                int dotIndex = quarantineFileName.lastIndexOf('.');
                if (dotIndex > 0) {
                    baseName = quarantineFileName.substring(0, dotIndex);
                    extension = quarantineFileName.substring(dotIndex);
                }
                quarantineFileName = baseName + " (" + counter + ")" + extension;
                targetPath = quarantineDir.resolve(quarantineFileName);
                counter++;
            }

            // Create a preliminary metadata file (without scan result)
            Path metadataPath = quarantineDir.resolve(quarantineFileName + ".meta");
            Properties metadata = new Properties();
            metadata.setProperty("originalPath", originalFile.getAbsolutePath());
            metadata.setProperty("quarantineDate", new Date().toString());
            metadata.setProperty("scanStatus", "pending"); // awaiting scan
            metadata.setProperty("fileSize", String.valueOf(originalFile.length()));

            // Save metadata
            try (OutputStream out = Files.newOutputStream(metadataPath)) {
                metadata.store(out, "Quarantine metadata");
            }

            // Move the blocked file to quarantine
            Files.move(originalFile.toPath(), targetPath, StandardCopyOption.REPLACE_EXISTING);
            File quarantinedFile = targetPath.toFile();
            logger.info("File moved to quarantine for scanning: {}", targetPath);

            return quarantinedFile;
        } catch (IOException e) {
            logger.error("Error while moving the file to quarantine", e);
            return null;
        }
    }

    /**
     * Updates the quarantine status of a given file based on the scan results.
     * If the file is identified as a threat, the threat details are also updated
     * in the file's metadata. The metadata file is expected to be located at
     * the same path as the quarantined file with a ".meta" extension.
     *
     * @param quarantinedFile The file whose quarantine status is to be updated.
     *                        This file must not be null and must exist in the
     *                        filesystem.
     * @param isThreat        A boolean indicating whether the file is considered a
     *                        threat.
     * @param threatDetails   The details of the threat if one is detected. This
     *                        parameter
     *                        is used only if isThreat is true.
     * @return True if the metadata is successfully updated, otherwise false.
     *         Returns false if the file or its metadata cannot be found or if an
     *         error occurs during the update process.
     */
    public boolean updateQuarantineStatus(File quarantinedFile, boolean isThreat, String threatDetails) {
        if (quarantinedFile == null || !quarantinedFile.exists()) {
            logger.warn("Invalid file for updating quarantine status: {}", quarantinedFile);
            return false;
        }

        Path metadataPath = Paths.get(quarantinedFile.getAbsolutePath() + ".meta");
        if (!Files.exists(metadataPath)) {
            logger.warn("Metadata file not found: {}", metadataPath);
            return false;
        }

        try {
            // Load existing metadata
            Properties metadata = new Properties();
            try (InputStream in = Files.newInputStream(metadataPath)) {
                metadata.load(in);
            }

            // Update with scan results
            metadata.setProperty("scanStatus", isThreat ? "threat" : "clean");
            metadata.setProperty("scanDate", new Date().toString());
            if (isThreat && threatDetails != null) {
                metadata.setProperty("threatDetails", threatDetails);
            }

            // Save updated metadata
            try (OutputStream out = Files.newOutputStream(metadataPath)) {
                metadata.store(out, "Updated quarantine metadata after scan");
            }

            logger.info("Metadata updated for quarantined file: {} (Threat: {})",
                    quarantinedFile, isThreat);
            return true;
        } catch (IOException e) {
            logger.error("Error while updating metadata", e);
            return false;
        }
    }

    /**
     * Restores a quarantined file to its original location.
     * 
     * @param quarantinedFile the quarantined file to restore
     * @return the restored file if successful, otherwise null
     *         Restores the file to its original location and deletes the metadata
     *         file.
     *         Returns null if the file or its metadata cannot be found or if an
     *         error
     *         occurs during the restoration process.
     */
    public File restoreFromQuarantine(File quarantinedFile) {
        if (quarantinedFile == null || !quarantinedFile.exists()) {
            logger.warn("Invalid file for restoration from quarantine: {}", quarantinedFile);
            return null;
        }

        try {
            // 1. Read metadata
            Path metadataPath = Paths.get(quarantinedFile.getAbsolutePath() + ".meta");
            if (!Files.exists(metadataPath)) {
                logger.warn("Metadata file not found for restoration: {}", metadataPath);
                return null;
            }

            Properties metadata = new Properties();
            try (InputStream in = Files.newInputStream(metadataPath)) {
                metadata.load(in);
            }

            String originalPath = metadata.getProperty("originalPath");
            if (originalPath == null) {
                logger.warn("Original path not available in metadata: {}", quarantinedFile);
                return null;
            }

            // 2. Move the file to the original location
            Path targetPath = Paths.get(originalPath);
            Files.createDirectories(targetPath.getParent()); // ensure folder exists
            Files.move(quarantinedFile.toPath(), targetPath, StandardCopyOption.REPLACE_EXISTING);

            File restoredFile = targetPath.toFile();

            // 3. Delete metadata
            Files.deleteIfExists(metadataPath);

            logger.info("File restored from quarantine: {}", restoredFile.getAbsolutePath());

            return restoredFile;

        } catch (IOException e) {
            logger.error("Error during file restoration from quarantine", e);
            try {
                Path metadataPath = Paths.get(quarantinedFile.getAbsolutePath() + ".meta");
                Files.deleteIfExists(metadataPath);
                logger.info("Metadata file deleted after restoration failure.");
            } catch (IOException ex) {
                logger.warn("Unable to delete metadata file after restoration error", ex);
            }
            return null;
        }
    }
}
