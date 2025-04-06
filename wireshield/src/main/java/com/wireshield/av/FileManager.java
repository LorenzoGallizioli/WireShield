package com.wireshield.av;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

/**
 * Utility class for managing files, including creation, reading, writing,
 * deletion, and hash computation. Provides methods for interacting with JSON
 * configuration files and checking file states (e.g., temporary, stable).
 */
public class FileManager {

    // Logger for logging information and errors.
    private static final Logger logger = LogManager.getLogger(FileManager.class);

    // Path to the configuration file.
    static String configPath = FileManager.getProjectFolder() + "\\config\\config.json";

    /**
     * Private constructor to prevent instantiation of this utility class.
     */
    private FileManager() {
        // Prevent instantiation
    }

    /**
     * Creates a new file at the specified path.
     *
     * @param filePath the path where the file will be created
     * @return true if the file is successfully created, false if the file
     * already exists or an error occurs
     */
    public static boolean createFile(String filePath) {
        File file = new File(filePath);
        try {
            if (file.createNewFile()) {
                logger.info("File created: {}", file.getName());
                return true;
            } else {
                logger.debug("File already exists.");
                return false;
            }
        } catch (IOException e) {
            logger.error("Error occured during file creation: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Writes the specified content to a file at the given path.
     *
     * @param filePath the path of the file to write to
     * @param content the content to write to the file
     * @return true if the content is successfully written, false if an error
     * occurs
     */
    public static boolean writeFile(String filePath, String content) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            writer.write(content);
            System.out.println("Scrittura completata.");
            return true;
        } catch (IOException e) {
            System.out.println("Errore durante la scrittura del file: " + e.getMessage());
            return false;
        }
    }

    /**
     * Reads the content of a file from the specified path.
     *
     * @param filePath the path of the file to read
     * @return the content of the file as a String, or null if an error occurs
     */
    public static String readFile(String filePath) {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        } catch (IOException e) {
            logger.error("Errore durante la lettura del file: {}", e.getMessage());
            return null;
        }
        return content.toString();
    }

    /**
     * Deletes the file at the specified path.
     *
     * @param filePath the path of the file to delete
     * @return true if the file is successfully deleted, false if an error
     * occurs or the file does not exist
     */
    public static boolean deleteFile(String filePath) {
        try {
            Files.delete(Paths.get(filePath)); // Elimina il file usando Files.delete
            logger.info("File eliminato: {}", filePath);
            return true;
        } catch (IOException e) {
            logger.error("Errore durante l'eliminazione del file {}: {}", filePath, e.getMessage());
            return false;
        }
    }

    /**
     * Retrieves the absolute path of the project folder.
     *
     * @return the absolute path of the project folder
     */
    public static String getProjectFolder() {
        return new File("").getAbsolutePath();
    }

    /**
     * Determines if a file is temporary or incomplete (e.g., `.crdownload`,
     * `.part` files).
     *
     * @param file the file to check
     * @return true if the file is temporary, false otherwise
     */
    public static boolean isTemporaryFile(File file) {
        String fileName = file.getName().toLowerCase();
        return fileName.endsWith(".crdownload") || fileName.endsWith(".part") || fileName.startsWith(".");
    }

    /**
     * Checks if a file is stable (i.e., exists, is readable, and is non-empty).
     *
     * @param file the file to check
     * @return true if the file is stable, false otherwise
     */
    public static boolean isFileStable(File file) {
        try {
            Thread.sleep(500); // Wait for potential ongoing writes to complete
            return file.exists() && file.canRead() && file.length() > 0; // File must exist, be readable, and non-empty
        } catch (InterruptedException e) {
            logger.error("Error checking file stability: {}", e.getMessage(), e);
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /**
     * Calculates the SHA256 hash of a given file.
     *
     * @param file the file to calculate the hash for
     * @return the SHA256 hash as a hexadecimal string, or null if an error
     * occurs
     */
    public static String calculateSHA256(File file) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (FileInputStream fis = new FileInputStream(file)) {
                byte[] byteArray = new byte[1024];
                int bytesCount;
                while ((bytesCount = fis.read(byteArray)) != -1) {
                    digest.update(byteArray, 0, bytesCount);
                }
            }
            byte[] bytes = digest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Reads the JSON configuration file and retrieves the value associated with
     * the given key.
     *
     * @param key the key whose associated value is to be returned
     * @return the value as a String, or null if the key does not exist
     */
    public static String getConfigValue(String key) {
        // Parse the JSON file
        JSONParser parser = new JSONParser();
        try (FileReader reader = new FileReader(configPath)) {
            // Read the JSON object from the file
            JSONObject jsonObject = (JSONObject) parser.parse(reader);

            // Retrieve the value associated with the key
            Object value = jsonObject.get(key);
            if (value != null) {
                return value.toString();
            } else {
                return null;
            }
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Writes a value to the JSON configuration file for the specified key.
     *
     * @param key the key to add or update
     * @param value the value to set for the key
     * @return true if the value is successfully written, false otherwise
     */
    public static boolean writeConfigValue(String key, String value) {
        JSONParser parser = new JSONParser();
        JSONObject jsonObject = null;

        File file = new File(configPath);

        // Load existing JSON data if the file exists
        if (file.exists()) {
            try (FileReader reader = new FileReader(file)) {
                jsonObject = (JSONObject) parser.parse(reader);
            } catch (Exception e) {
                logger.error("Error during JSON");
                return false;
            }
        } else {
            // If the file does not exist, initialize a new JSON object
            jsonObject = new JSONObject();
        }

        // Update or add the key-value pair
        jsonObject.put(key, value);

        // Write the updated JSON object back to the file
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(jsonObject.toJSONString());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // Other methods (createFile, writeFile, readFile, etc.) remain unchanged.
    /**
     * Mette un file in quarantena rinominandolo e bloccandone l'esecuzione. Il
     * file sarà rinominato con un suffisso che lo identifica chiaramente come
     * in quarantena.
     *
     * @param file il file da mettere in quarantena
     * @return il file rinominato, oppure null in caso di errore
     */
    public static File quarantineFile(File file) {
        if (file == null || !file.exists()) {
            logger.warn("File non valido per la quarantena: {}", file);
            return null;
        }

        // Rinominare il file con un suffisso ".quarantine" per indicare che è sotto analisi.
        String quarantinedFileName = file.getName() + ".quarantine";
        File quarantinedFile = new File(file.getParent(), quarantinedFileName);

        if (file.renameTo(quarantinedFile)) {
            logger.info("File spostato in quarantena: {}", quarantinedFile.getAbsolutePath());

            // Bloccare l'esecuzione del file, impedendo l'accesso e l'esecuzione.
            if (blockFileExecution(quarantinedFile)) {
                logger.info("File messo in quarantena e l'esecuzione è stata bloccata.");
            } else {
                logger.error("Impossibile bloccare l'esecuzione del file in quarantena.");
            }
            return quarantinedFile;
        } else {
            logger.error("Impossibile spostare il file in quarantena: {}", file.getAbsolutePath());
            return null;
        }
    }

    /**
     * Ripristina un file precedentemente messo in quarantena. Il suffisso
     * ".quarantine" viene rimosso per ripristinare il nome originale del file.
     *
     * @param quarantinedFile il file con estensione .quarantine
     * @return il file ripristinato, oppure null in caso di errore
     */
    public static File releaseFromQuarantine(File quarantinedFile) {
        if (quarantinedFile == null || !quarantinedFile.exists() || !quarantinedFile.getName().endsWith(".quarantine")) {
            logger.warn("File non valido o non in quarantena: {}", quarantinedFile);
            return null;
        }

        // Ripristinare il nome del file rimuovendo il suffisso ".quarantine"
        String originalName = quarantinedFile.getName().replaceFirst("\\.quarantine$", "");
        File restoredFile = new File(quarantinedFile.getParent(), originalName);

        if (quarantinedFile.renameTo(restoredFile)) {
            unblockFileExecution(restoredFile);
            logger.info("File ripristinato dalla quarantena: {}", restoredFile.getAbsolutePath());
            return restoredFile;
        } else {
            logger.error("Errore nel ripristino del file: {}", quarantinedFile.getAbsolutePath());
            return null;
        }
    }

    /**
     * Blocca l'esecuzione di un file tramite icacls negando i permessi di Read
     * ed Execute.
     *
     * @param file il file da bloccare
     * @return true se il blocco ha successo, false altrimenti
     */
    public static boolean blockFileExecution(File file) {
        if (file == null || !file.exists()) {
            logger.warn("File non esistente o nullo: {}", file);
            return false;
        }

        try {
            ProcessBuilder builder = new ProcessBuilder("icacls", file.getAbsolutePath(), "/deny", "Everyone:RX");
            Process process = builder.start();
            int exitCode = process.waitFor();

            if (exitCode == 0) {
                logger.info("Esecuzione bloccata per il file: {}", file.getAbsolutePath());
                return true;
            } else {
                logger.error("Errore nel blocco esecuzione (codice {}): {}", exitCode, file.getAbsolutePath());
            }
        } catch (IOException | InterruptedException e) {
            logger.error("Errore durante il blocco del file: {}", e.getMessage(), e);
            Thread.currentThread().interrupt(); // buona pratica per InterruptedException
        }

        return false;
    }

    /**
     * Sblocca l'esecuzione di un file rimuovendo il deny con icacls.
     *
     * @param file il file da sbloccare
     * @return true se lo sblocco ha successo, false altrimenti
     */
    public static boolean unblockFileExecution(File file) {
        if (file == null || !file.exists()) {
            logger.warn("File non esistente o nullo: {}", file);
            return false;
        }

        try {
            ProcessBuilder builder = new ProcessBuilder("icacls", file.getAbsolutePath(), "/remove:d", "Everyone");
            Process process = builder.start();
            int exitCode = process.waitFor();

            if (exitCode == 0) {
                logger.info("Esecuzione sbloccata per il file: {}", file.getAbsolutePath());
                return true;
            } else {
                logger.error("Errore nello sblocco esecuzione (codice {}): {}", exitCode, file.getAbsolutePath());
            }
        } catch (IOException | InterruptedException e) {
            logger.error("Errore durante lo sblocco del file: {}", e.getMessage(), e);
            Thread.currentThread().interrupt();
        }

        return false;
    }

    /**
     * Verifica se un file è stato messo in quarantena.
     *
     * @param file il file da verificare
     * @return true se il file è in quarantena, false altrimenti
     */
    public static boolean isInQuarantine(File file) {
        return file != null && file.getName().endsWith(".quarantine");
    }
}
