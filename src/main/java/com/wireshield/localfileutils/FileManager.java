package com.wireshield.localfileutils;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.MessageDigest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


public class FileManager {
	
	private static final Logger logger = LogManager.getLogger(FileManager.class);
	
	/**
     * Creates a new file at the specified path.
     *
     * @param filePath the path where the file will be created
     * @return true if the file is successfully created, false if the file already exists or an error occurs
     */
    public static boolean createFile(String filePath) {   	
        File file = new File(filePath);
        try {
            if (file.createNewFile()) {
                logger.info("File created: " + file.getName());
                return true;
            } else {
                logger.debug("File already exists.");
                return false;
            }
        } catch (IOException e) {
        	logger.error("Error occured during file creation: " + e.getMessage());
            return false;
        }
    }

    /**
     * Writes the specified content to a file at the given path.
     *
     * @param filePath the path of the file to write to
     * @param content the content to write to the file
     * @return true if the content is successfully written, false if an error occurs
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
        	logger.error("Errore durante la lettura del file: " + e.getMessage());
            return null;
        }
        return content.toString();
    }

    /**
     * Deletes the file at the specified path.
     *
     * @param filePath the path of the file to delete
     * @return true if the file is successfully deleted, false if an error occurs or the file does not exist
     */
    public static boolean deleteFile(String filePath) {
        File file = new File(filePath);
        if (file.delete()) {
        	logger.info("File eliminato: " + file.getName());
            return true;
        } else {
        	logger.debug("Errore durante l'eliminazione del file.");
            return false;
        }
    }

    /**
     * Retrieves the standard folder where the project is located.
     *
     * @return the absolute path of the project folder
     */
    public static String getProjectFolder() {
        return new File("").getAbsolutePath();
    }
    
    /**
     * Determines if a file is temporary or incomplete (e.g., `.crdownload`, `.part` files).
     *
     * @param file The file to check.
     * @return true if the file is temporary, false otherwise.
     */
    public static boolean isTemporaryFile(File file) {
        String fileName = file.getName().toLowerCase();
        return fileName.endsWith(".crdownload") || fileName.endsWith(".part") || fileName.startsWith(".");
    }

    /**
     * Checks if a file is stable, meaning the download is complete and the file can be safely processed.
     *
     * @param file The file to check.
     * @return true if the file is stable, false otherwise.
     */
    public static boolean isFileStable(File file) {
        try {
            Thread.sleep(500); // Wait for a short moment to confirm stability
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
	 * @param file The file to calculate the hash for.
	 * @return The SHA256 hash as a hexadecimal string, or null if an error occurs.
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
}
