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
        this.scannerStatus = runningStates.DOWN;
        this.clamAV = ClamAV.getInstance();
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
        if (this.scannerStatus == runningStates.UP) {
            logger.warn("Scan Thread is already running.");
            return;
        }

        this.scanThread = new Thread(() -> {
            this.scannerStatus = runningStates.UP;

            while (clamAV.getClamdState() == runningStates.DOWN && !Thread.currentThread().isInterrupted()) { // to be introduced a method to stop this thread if clamdservice fails startup
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            };

            performScan();
            this.scannerStatus = runningStates.DOWN;

            logger.info("Thread stopped - [startScan()] ScannerThread interrupted.");
        });

        this.scanThread.setDaemon(false);
        this.scanThread.start();
    }

    private void performScan() {
        while (!Thread.currentThread().isInterrupted()) {
            File fileToScan;

            if (this.clamAV == null) {
                logger.error("ClamAV object not exists - Shutting down AV scanner");
                Thread.currentThread().interrupt();
            }

            synchronized (this.scanBuffer) {
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

            // Process the file based on the scan results
            if (clamAVReport.getWarningClass() == warningClass.SUSPICIOUS || clamAVReport.getWarningClass() == warningClass.DANGEROUS) {

                this.updateQuarantineStatus(clamAVReport.getFile(), true, clamAVReport.getThreatDetails());
                FileManager.blockFileExecution(clamAVReport.getFile());
                //this.postScanActions(clamAVReport.getFile());

            } else {
                this.restoreFromQuarantine(clamAVReport.getFile());
            }

            if (clamAVReport != null) {
                mergeReports(finalReport, clamAVReport);
            }

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
        if (this.scannerStatus == runningStates.DOWN) {
            logger.warn("No scan process is running.");
            return;
        }

        if (this.scanThread != null && this.scanThread.isAlive()) {
            scanThread.interrupt();

            try {
                scanThread.join();
            } catch (InterruptedException e) {
            }
        }
    }

    /**
     * Deletes the specified file from the quarantine directory. If the file is
     * not found in quarantine, it attempts to delete the original file.
     *
     * @param report The scan report containing the file to be deleted.
     * @return true if the file was successfully deleted, false otherwise.
     */
    public boolean deleteFileFromQuarantine(ScanReport report) {

        File file = report.getFile();
        boolean fileDeleted = false;

        String blockedFilePath = file.getAbsolutePath() + ".blocked";
        File blockedFile = new File(blockedFilePath);

        if (blockedFile.exists()) {

            if (blockedFile.delete()) {
                logger.info("Infected file deleted: {}", blockedFile.getAbsolutePath());

                for (ScanReport r : finalReports) {
                    if (report.getId() == r.getId()) {
                        finalReports.remove(r); // Remove the report from the list
                    }
                }

                fileDeleted = true;

            } else {
                logger.error("Error deleting the infected file: {}", blockedFile.getAbsolutePath());
            }

        } else {

            if (file.delete()) {
                logger.info("File deleted: {}", file.getAbsolutePath());

                for (ScanReport r : finalReports) {
                    if (report.getId() == r.getId()) {
                        finalReports.remove(r); // Remove the report from the list
                    }
                }

                fileDeleted = true;
            } else {
                logger.error("Error deleting the file: {}", file.getAbsolutePath());
            }
        }

        return fileDeleted;
    }

    /**
     * Restores a file from quarantine. If the file is blocked, it first
     * unblocks it and then restores it to its original location.
     *
     * @param report The scan report containing the file to be restored.
     * @return true if the file was successfully restored, false otherwise.
     */
    public boolean restoreFileFromQuarantine(ScanReport report) {

        File file = report.getFile();
        File blockedFile = new File(file.getAbsolutePath() + ".blocked");

        if (blockedFile.exists()) {
            File unblockedFile = FileManager.unblockFileExecution(blockedFile);

            if (unblockedFile != null) {
                File restoredFile = restoreFromQuarantine(unblockedFile);

                if (restoredFile != null) {
                    logger.info("Infected file restored from quarantine: {}",
                            restoredFile.getAbsolutePath());

                    report.setFile(restoredFile);
                    report.setThreatDetails("RESTORED: user choice");
                    report.setWarningClass(warningClass.CLEAR);

                    // Replace the old report with the new one in the finalReports list
                    for (ScanReport r : finalReports) {
                        if (report.getId() == r.getId()) {
                            finalReports.remove(r);
                            finalReports.add(report);
                        }
                    }

                    return true;

                } else {
                    logger.error("Failed to restore infected file from quarantine: {}", unblockedFile.getAbsolutePath());
                    report.setThreatDetails("Infected file restoration failed");
                    return false;

                }
            } else {
                logger.error("Failed to unblock infected file: {}", blockedFile.getAbsolutePath());
                report.setThreatDetails("Failed to unblock infected file");
                report.setWarningClass(warningClass.DANGEROUS);
            }
        }

        return false;
    }

    /**
     * for test use only
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
        return clamAV.getClamdState();
    }

    /**
     * Retrieves the current status of the scanner.
     *
     * @return the scanner status.
     */
    public runningStates getScannerStatus() {
        return this.scannerStatus;
    }

    /**
     * Retrieves the list of final scan reports.
     *
     * @return the list of scan reports.
     */
    public List<ScanReport> getFinalReports() {
        return this.finalReports;
    }

    /**
     * Retrieves the current state of the scan buffer.
     *
     * @return a copy of the scan buffer.
     */
    public synchronized List<File> getScanBuffer() {
        return new ArrayList<>(this.scanBuffer);
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
     * If the quarantine directory does not exist, it is created and made
     * hidden. Access control lists (ACLs) are set to ensure full access for the
     * program while restricting other users to read-only access.
     *
     * @param originalFile the file to be moved to quarantine
     * @return the quarantined file, or null if an error occurs
     */
    public File moveToQuarantine(File originalFile) {

        if (originalFile == null || !originalFile.exists()) {
            logger.warn("File is null or does not exist, cannot quarantine it.");
            return null;
        }

        Path quarantineDir = Paths.get(FileManager.getConfigValue("FOLDER_TO_SCAN_PATH"), ".QUARANTINE");

        try {
            if (!Files.exists(quarantineDir)) {
                Files.createDirectories(quarantineDir);

                Files.setAttribute(quarantineDir, "dos:hidden", true);
                logger.info("Created quarantine directory: {}", quarantineDir);

                try {
                    AclFileAttributeView aclAttrView = Files.getFileAttributeView(quarantineDir,
                            AclFileAttributeView.class);

                    if (aclAttrView != null) {
                        UserPrincipalLookupService lookupService = FileSystems.getDefault()
                                .getUserPrincipalLookupService();

                        UserPrincipal currentUser = lookupService
                                .lookupPrincipalByName(System.getProperty("user.name"));

                        AclEntry fullAccess = AclEntry.newBuilder()
                                .setType(AclEntryType.ALLOW)
                                .setPrincipal(currentUser)
                                .setPermissions(AclEntryPermission.values())
                                .build();

                        AclEntry readOnlyAccess = AclEntry.newBuilder()
                                .setType(AclEntryType.ALLOW)
                                .setPrincipal(lookupService.lookupPrincipalByName("Everyone"))
                                .setPermissions(
                                        AclEntryPermission.READ_DATA,
                                        AclEntryPermission.READ_ATTRIBUTES,
                                        AclEntryPermission.READ_ACL)
                                .build();

                        aclAttrView.setAcl(Arrays.asList(fullAccess, readOnlyAccess));
                        logger.info("Set ACL: full access for the program (administrator), read-only for all users.");
                    }
                } catch (IOException e) {
                    logger.warn("Error setting ACL on quarantine", e);
                }
            }

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

            Path metadataPath = quarantineDir.resolve(quarantineFileName + ".meta");
            Properties metadata = new Properties();
            metadata.setProperty("originalPath", originalFile.getAbsolutePath());
            metadata.setProperty("quarantineDate", new Date().toString());
            metadata.setProperty("scanStatus", "pending");
            metadata.setProperty("fileSize", String.valueOf(originalFile.length()));

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
     * If the file is identified as a threat, the threat details are also
     * updated in the file's metadata. The metadata file is expected to be
     * located at the same path as the quarantined file with a ".meta"
     * extension.
     *
     * @param quarantinedFile The file whose quarantine status is to be updated.
     * This file must not be null and must exist in the filesystem.
     * @param isThreat A boolean indicating whether the file is considered a
     * threat.
     * @param threatDetails The details of the threat if one is detected. This
     * parameter is used only if isThreat is true.
     * @return True if the metadata is successfully updated, otherwise false.
     * Returns false if the file or its metadata cannot be found or if an error
     * occurs during the update process.
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
            Properties metadata = new Properties();
            try (InputStream in = Files.newInputStream(metadataPath)) {
                metadata.load(in);
            }

            metadata.setProperty("scanStatus", isThreat ? "threat" : "clean");
            metadata.setProperty("scanDate", new Date().toString());
            if (isThreat && threatDetails != null) {
                metadata.setProperty("threatDetails", threatDetails);
            }

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
     * @return the restored file if successful, otherwise null Restores the file
     * to its original location and deletes the metadata file. Returns null if
     * the file or its metadata cannot be found or if an error occurs during the
     * restoration process.
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
            Files.createDirectories(targetPath.getParent());

            if (Files.exists(targetPath)) {

                if (FileManager.calculateFileHash(targetPath).equals(FileManager.calculateFileHash(quarantinedFile.toPath()))) {
                    logger.warn("Identic file already exists at the original location: {}", targetPath);

                    File file = targetPath.toFile();
                    Files.deleteIfExists(metadataPath);

                    return file;

                } 
                else 
                {

                    int counter = 1;
                    while (Files.exists(targetPath)) {
                        String Name = targetPath.getFileName().toString();
                        String extension = "";
                        String baseName = "";

                        Path parentDir = targetPath.getParent();
                        if (parentDir != null) {
                            baseName = parentDir.toString();
                        }

                        int dotIndex = Name.lastIndexOf('.');
                        if (dotIndex > 0) {
                            extension = Name.substring(dotIndex);
                            Name = Name.substring(0, dotIndex);
                        }

                        Name = baseName + " (" + counter + ")" + extension;

                        targetPath = parentDir.resolve(Name);
                        counter++;
                    }
                }
            }

            Files.move(quarantinedFile.toPath(), targetPath, StandardCopyOption.REPLACE_EXISTING);
            File restoredFile = targetPath.toFile();
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

    public boolean isFileInQuarantine(File file) {
        if (file == null || !file.exists()) {
            logger.warn("File is null or does not exist, cannot check quarantine status.");
            return false;
        }

        String quarantineDirPath = System.getProperty("user.home") + File.separator + "Downloads" + File.separator
                + ".QUARANTINE";
        return file.getAbsolutePath().startsWith(quarantineDirPath);
    }

    /**
     * Interrupts `scanThread` thread, if is active. Checks if each thread is
     * not null and is alive before attempting to interrupt it.
     */
    public void interruptAllThreads() throws InterruptedException {
        if (this.scanThread != null && this.scanThread.isAlive()) {
            this.scanThread.interrupt();
            this.scanThread.join();
        }
    }
}
