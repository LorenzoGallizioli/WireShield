package com.wireshield.av;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
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
    private VirusTotal virusTotal;
    private Queue<File> scanBuffer = new LinkedList<>();
    private List<File> filesToRemove = new ArrayList<>();
    private List<ScanReport> finalReports = new ArrayList<>();
    private runningStates scannerStatus;

    private Thread scanThread;
    static final long MAX_FILE_SIZE = 10L * 1024 * 1024; // Maximum file size for VirusTotal analysis (10 MB)

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

            if (clamAVReport != null) {
                mergeReports(finalReport, clamAVReport);
            }

            // If a threat is detected and the file is small enough, use VirusTotal
            if (virusTotal != null) {
                if (finalReport.isThreatDetected() && fileToScan.length() <= MAX_FILE_SIZE) {

                    virusTotal.analyze(fileToScan);
                    ScanReport virusTotalReport = virusTotal.getReport();

                    if (virusTotalReport != null) {
                        mergeReports(finalReport, virusTotalReport);
                    }

                } else if (fileToScan.length() > MAX_FILE_SIZE) {
                    logger.warn("File {} is too large for VirusTotal analysis (>10 MB)", fileToScan.getName());

                }
            }

            // Add the final report to the results list
            finalReports.add(finalReport);

            // If the file is dangerous or suspicious, take action
            if (finalReport.getWarningClass() == warningClass.DANGEROUS || finalReport.getWarningClass() == warningClass.SUSPICIOUS) {
                logger.warn("Threat detected in file: {}", fileToScan.getName());

                JOptionPane.showMessageDialog(null, "Threat detected in file: " + fileToScan.getName(), "Threat Detected", JOptionPane.WARNING_MESSAGE); // Show warning dialog
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
     * Sets the VirusTotal engine for file analysis.
     *
     * @param virusTotal the VirusTotal instance.
     */
    public void setVirusTotal(VirusTotal virusTotal) {
        this.virusTotal = virusTotal;
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

    /**
     * Sposta un file nella quarantena temporanea per la scansione, dopo averlo
     * preventivamente bloccato.
     *
     * @param originalFile il file da mettere in quarantena
     * @return il file in quarantena, oppure null in caso di errore
     */
    public File moveToQuarantine(File originalFile) {
        if (originalFile == null || !originalFile.exists()) {
            logger.warn("File nullo o non esistente, impossibile metterlo in quarantena.");
            return null;
        }

        // Creazione della cartella di quarantena all'interno di "Downloads"
        String downloadsDirPath = System.getProperty("user.home") + File.separator + "Downloads";
        Path quarantineDir = Paths.get(downloadsDirPath, ".QUARANTINE");

        try {
            if (!Files.exists(quarantineDir)) {
                Files.createDirectories(quarantineDir);
                // Rendi la cartella nascosta in Windows
                Files.setAttribute(quarantineDir, "dos:hidden", true);
                logger.info("Creata cartella di quarantena: {}", quarantineDir);
            }

            // Genera un nome file univoco
            String quarantineFileName = originalFile.getName();

            // Usa lo stesso nome del file originale
            Path targetPath = quarantineDir.resolve(originalFile.getName());

            // Crea file di metadati preliminare (senza risultato scansione)
            Path metadataPath = quarantineDir.resolve(quarantineFileName + ".meta");
            Properties metadata = new Properties();
            metadata.setProperty("originalPath", originalFile.getAbsolutePath());
            metadata.setProperty("quarantineDate", new Date().toString());
            metadata.setProperty("scanStatus", "pending"); // in attesa di scansione
            metadata.setProperty("fileSize", String.valueOf(originalFile.length()));

            // Salva metadata
            try (OutputStream out = Files.newOutputStream(metadataPath)) {
                metadata.store(out, "Quarantine metadata");
            }

            // Sposta il file bloccato in quarantena
            Files.move(originalFile.toPath(), targetPath, StandardCopyOption.REPLACE_EXISTING);
            File quarantinedFile = targetPath.toFile();
            logger.info("File spostato in quarantena per la scansione: {}", targetPath);

            return quarantinedFile;
        } catch (IOException e) {
            logger.error("Errore durante il trasferimento del file in quarantena", e);
            return null;
        }
    }

    /**
     * Aggiorna i metadati di un file in quarantena dopo la scansione con
     * ClamAV.
     *
     * @param quarantinedFile il file in quarantena
     * @param isThreat se il file è una minaccia
     * @param threatDetails dettagli sulla minaccia rilevata, o null se pulito
     * @return true se l'aggiornamento è riuscito
     */
    public boolean updateQuarantineStatus(File quarantinedFile, boolean isThreat, String threatDetails) {
        if (quarantinedFile == null || !quarantinedFile.exists()) {
            logger.warn("File non valido per l'aggiornamento dello stato: {}", quarantinedFile);
            return false;
        }

        Path metadataPath = Paths.get(quarantinedFile.getAbsolutePath() + ".meta");
        if (!Files.exists(metadataPath)) {
            logger.warn("File di metadati non trovato: {}", metadataPath);
            return false;
        }

        try {
            // Carica i metadati esistenti
            Properties metadata = new Properties();
            try (InputStream in = Files.newInputStream(metadataPath)) {
                metadata.load(in);
            }

            // Aggiorna con i risultati della scansione
            metadata.setProperty("scanStatus", isThreat ? "threat" : "clean");
            metadata.setProperty("scanDate", new Date().toString());
            if (isThreat && threatDetails != null) {
                metadata.setProperty("threatDetails", threatDetails);
            }

            // Salva i metadati aggiornati
            try (OutputStream out = Files.newOutputStream(metadataPath)) {
                metadata.store(out, "Updated quarantine metadata after scan");
            }

            logger.info("Metadati aggiornati per file in quarantena: {} (Minaccia: {})",
                    quarantinedFile, isThreat);
            return true;
        } catch (IOException e) {
            logger.error("Errore durante l'aggiornamento dei metadati", e);
            return false;
        }
    }

    public File restoreToQuarantine(File quarantinedFile) {
        if (quarantinedFile == null || !quarantinedFile.exists()) {
            logger.warn("File non valido per il ripristino dalla quarantena: {}", quarantinedFile);
            return null;
        }

        try {
            // 1. Leggi i metadati
            Path metadataPath = Paths.get(quarantinedFile.getAbsolutePath() + ".meta");
            if (!Files.exists(metadataPath)) {
                logger.warn("File di metadati non trovato per il ripristino: {}", metadataPath);
                return null;
            }

            Properties metadata = new Properties();
            try (InputStream in = Files.newInputStream(metadataPath)) {
                metadata.load(in);
            }

            String originalPath = metadata.getProperty("originalPath");
            if (originalPath == null) {
                logger.warn("Percorso originale non disponibile nei metadati: {}", quarantinedFile);
                return null;
            }

            // 2. Costruisci il nome ripristinato (rimuove .blocked)
            String originalFileName = quarantinedFile.getName().replaceFirst("\\.blocked$", "");
            Path targetPath = Paths.get(originalPath).getParent().resolve(originalFileName);

            // 3. Sposta il file nella posizione originale
            Files.createDirectories(targetPath.getParent()); // assicura esistenza cartella
            Files.move(quarantinedFile.toPath(), targetPath, StandardCopyOption.REPLACE_EXISTING);

            File restoredFile = targetPath.toFile();

            // 4. Sblocca esecuzione e accesso
            boolean accessUnblocked = FileManager.unblockFileAccess(restoredFile);
            File unblockedFile = FileManager.unblockFileExecution(restoredFile);

            // 5. Elimina metadati
            Files.deleteIfExists(metadataPath);

            logger.info("File ripristinato dalla quarantena e sbloccato: {} (accesso: {}, esecuzione: {})",
                    unblockedFile != null ? unblockedFile.getAbsolutePath() : restoredFile.getAbsolutePath(),
                    accessUnblocked,
                    unblockedFile != null);

            return unblockedFile != null ? unblockedFile : restoredFile;

        } catch (IOException e) {
            logger.error("Errore durante il ripristino del file dalla quarantena", e);
            return null;
        }
    }
}
