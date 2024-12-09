package com.wireshield.localfileutils;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.util.HashSet;
import java.util.Set;

public class DownloadManager {

    private String downloadPath;
    private final Set<String> detectedFiles = new HashSet<>();
    public DownloadManager() {
        this.downloadPath = getDefaultDownloadPath();
    }

    private String getDefaultDownloadPath() {
        String userHome = System.getProperty("user.home");
        String downloadFolder = "Downloads";
        return System.getProperty("os.name").toLowerCase().contains("win")
                ? userHome + "\\" + downloadFolder
                : userHome + "/" + downloadFolder;
    }

    public void startMonitoring() {
        try (WatchService watchService = FileSystems.getDefault().newWatchService()) {
            Path path = Paths.get(downloadPath);
            path.register(watchService, StandardWatchEventKinds.ENTRY_CREATE);

            System.out.println("Monitoring directory: " + downloadPath);

            while (true) {
                WatchKey key = watchService.take(); // Blocco fino all'evento
                for (WatchEvent<?> event : key.pollEvents()) {
                    if (event.kind() == StandardWatchEventKinds.ENTRY_CREATE) {
                        Path newFilePath = path.resolve((Path) event.context());
                        File newFile = newFilePath.toFile();

                        // Verifica se il file è nuovo e non temporaneo
                        if (!isTemporaryFile(newFile) && isFileStable(newFile)) {
                            String fileName = newFile.getAbsolutePath();
                            if (!detectedFiles.contains(fileName)) {
                                detectedFiles.add(fileName);
                                System.out.println("New file detected: " + newFile.getName());
                            }
                        }
                    }
                }
                
                key.reset();
            }
        } catch (IOException | InterruptedException e) {
            System.err.println("Error monitoring directory: " + e.getMessage());
        }
    }

    private boolean isTemporaryFile(File file) {
        String fileName = file.getName().toLowerCase();
        return fileName.endsWith(".crdownload") || fileName.endsWith(".part") || fileName.startsWith(".");
    }

    private boolean isFileStable(File file) {
        try {
            Thread.sleep(500); // Attendi 500ms per verificare se il file è stabile
            return file.exists() && file.canRead() && file.length() > 0;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    // TESTING
    public static void main(String[] args) {
        DownloadManager downloadManager = new DownloadManager();
        downloadManager.startMonitoring();
    }
}
