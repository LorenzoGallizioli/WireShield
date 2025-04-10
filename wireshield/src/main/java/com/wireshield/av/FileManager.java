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
import java.util.Properties;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


/**
 * Utility class for managing files, including creation, reading, writing,
 * deletion, and hash computation. Provides methods for interacting with JSON
 * configuration files and checking file states (e.g., temporary, stable).
 */
public class FileManager {

	// Logger for logging information and errors.
	private static final Logger logger = LogManager.getLogger(FileManager.class);

	// Path to the configuration file.
	static String configPath = FileManager.getProjectFolder() + "\\config\\config.properties";

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
	 * @return true if the file is successfully created, false if the file already
	 *         exists or an error occurs
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
	 * @param content  the content to write to the file
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
			logger.error("Errore durante la lettura del file: {}", e.getMessage());
			return null;
		}
		return content.toString();
	}

	/**
	 * Deletes the file at the specified path.
	 *
	 * @param filePath the path of the file to delete
	 * @return true if the file is successfully deleted, false if an error occurs or
	 *         the file does not exist
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
	 * Determines if a file is temporary or incomplete (e.g., `.crdownload`, `.part`
	 * files).
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
	 * Reads the JSON configuration file and retrieves the value associated with the
	 * given key.
	 *
	 * @param key the key whose associated value is to be returned
	 * @return the value as a String, or null if the key does not exist
	 */
	public static String getConfigValue(String key) {
		Properties prop = new Properties();

        try (FileInputStream input = new FileInputStream(configPath)) {
            
			prop.load(input);
            String data = prop.getProperty(key);

			if (data != null) {
				return data;
			}
			return null;

        } catch (IOException ex) {
            ex.printStackTrace();
			return null;
        }
    }

	public static Boolean setConfigValue(String key, String value) {
		Properties prop = new Properties();
		try (FileInputStream input = new FileInputStream(configPath)) {
			prop.load(input);
			prop.setProperty(key, value);
			try (BufferedWriter writer = new BufferedWriter(new FileWriter(configPath))) {
				prop.store(writer, null);
				return true;
			}
		} catch (IOException e) {
			logger.error("Error setting config value: {}", e.getMessage(), e);
			return false;
		}
	}
	
}
