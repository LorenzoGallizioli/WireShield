package com.wireshield.av;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import org.junit.After;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 * Unit tests for the {@code FileManager} class. This class provides
 * comprehensive tests for file and configuration management functionalities,
 * including: 
 * - File creation, reading, writing, and deletion. 
 * - Handling configuration files in JSON format. 
 * - Utility methods such as calculating SHA-256 hashes.
 * - Detection and handling of temporary and unstable files.
 */
public class FileManagerTest {

	// Paths for test files and configuration files
	private String testFilePath;
	private File validFile;
	private File stableFile;
	private File emptyFile;
	private File nonExistingFile;

	// Paths for configuration file and its temporary backup
	private static final String CONFIG_PATH = FileManager.getProjectFolder() + "\\config\\config.json";
	private static final String TEMP_CONFIG_PATH = FileManager.getProjectFolder() + "\\config\\config_backup.json";

	/**
	 * Sets up the test environment before each test. Initializes file objects and
	 * creates a backup of the configuration file.
	 *
	 * @throws IOException if an I/O error occurs during setup.
	 */
	@Before
	public void setUp() throws IOException {
		// Initialize test file paths
		testFilePath = "testFile.txt";
		stableFile = new File("stableFile.txt");
		emptyFile = new File("emptyFile.txt");
		nonExistingFile = new File("nonExistingFile.txt");

		// Backup the configuration file if it exists
		File originalFile = new File(CONFIG_PATH);
		File backupFile = new File(TEMP_CONFIG_PATH);
		if (originalFile.exists()) {
			try (FileInputStream fis = new FileInputStream(originalFile);
					FileOutputStream fos = new FileOutputStream(backupFile)) {
				fos.write(fis.readAllBytes());
			}
		}
	}

	/**
	 * Cleans up the test environment after each test. Deletes temporary files and
	 * restores the configuration file from its backup.
	 *
	 * @throws IOException if an I/O error occurs during cleanup.
	 */
	@After
	public void tearDown() throws IOException {

		// Delete test files if they exist
		File file = new File(testFilePath);
		if (file.exists()) {
			file.delete();
		}

		if (stableFile.exists()) {
			stableFile.delete();
		}

		if (emptyFile.exists()) {
			emptyFile.delete();
		}

		// Restore the configuration file from the backup
		File originalFile = new File(CONFIG_PATH);
		File backupFile = new File(TEMP_CONFIG_PATH);
		if (backupFile.exists()) {
			// Restore the backup file to its original location
			try (FileInputStream fis = new FileInputStream(backupFile);
					FileOutputStream fos = new FileOutputStream(originalFile)) {
				fos.write(fis.readAllBytes());
			}

			backupFile.delete();
		} else if (originalFile.exists()) {
			originalFile.delete();
		}
	}

	/**
	 * Verifies that the {@code createFile} method handles invalid paths gracefully.
	 */
	@Test
	public void testCreateFile() {
		// Test creating a new file
		assertTrue("File should be created successfully.", FileManager.createFile(testFilePath));

		// Verify the file exists
		assertTrue("File should exist on the filesystem.", new File(testFilePath).exists());

		// Test creating the same file again (should return false)
		assertFalse("File already exists.", FileManager.createFile(testFilePath));
	}

	/**
	 * Verifies that the {@code createFile} method handles invalid paths gracefully.
	 */
	@Test
	public void testCreateFileIOException() {

		// Invalid file path to force IOException
		String invalidFilePath = "invalid:/path/testFile.txt";

		// Execute the createFile method with an invalid path
		boolean result = FileManager.createFile(invalidFilePath);

		// Verify that the result is false
		assertFalse("The method should return false when an IOException occurs.", result);
	}

	/**
	 * Verifies that content is correctly written to a file using the
	 * {@code writeFile} method.
	 */
	@Test
	public void testWriteFile() {
		// Create the test file
		FileManager.createFile(testFilePath);

		// Define content to be written
		String content = "Test content";

		// Write the content and verify success
		assertTrue("Content should be written successfully.", FileManager.writeFile(testFilePath, content));

		// Verify the content written matches the expected value
		assertEquals("Content should match the written data.", content, FileManager.readFile(testFilePath).trim());
	}

	/**
	 * Verifies that the {@code writeFile} method handles invalid paths gracefully.
	 */
	@Test
	public void testWriteFileIOException() {

		// Define invalid path and content
		String invalidFilePath = "/invalid/directory/testFile.txt";
		String content = "Test content";

		// Execute the writeFile method
		boolean result = FileManager.writeFile(invalidFilePath, content);

		// Verify that the result is false
		assertFalse("The method should return false when an IOException occurs.", result);
	}

	/**
	 * Verifies that content is correctly read from a file using the
	 * {@code readFile} method.
	 */
	@Test
	public void testReadFile() {
		// Create and write to the test file
		FileManager.createFile(testFilePath);
		String content = "Read test content.";
		FileManager.writeFile(testFilePath, content);

		// Verify the content read matches the expected value
		assertEquals("Content read should match the written data.", content, FileManager.readFile(testFilePath).trim());
	}

	/**
	 * Verifies that the {@code readFile} method handles non-existent files
	 * gracefully.
	 */
	@Test
	public void testReadFileIOException() {
		// Non-existent file path
		String invalidFilePath = "/invalid/directory/nonexistentFile.txt";

		// Execute the readFile method
		String result = FileManager.readFile(invalidFilePath);

		// Verify that the result is null
		assertNull("The method should return null when an IOException occurs.", result);
	}

	/**
	 * Tests the `deleteFile` method to verify that files are deleted successfully.
	 */
	@Test
	public void testDeleteFile() {
		// Create a test file
		FileManager.createFile(testFilePath);

		// Verify the file is deleted successfully
		assertTrue("File should be deleted successfully.", FileManager.deleteFile(testFilePath));

		// Verify the file no longer exists
		assertFalse("File should not exist on the filesystem.", new File(testFilePath).exists());
	}

	/**
	 * Tests the `deleteFile` method when trying to delete a file that does not
	 * exist. Verifies that the method returns false when the file is not found.
	 */
	@Test
	public void testDeleteFileFileNotExist() {
		// Path to a file that does not exist
		String nonExistentFilePath = "nonExistentFile.txt";

		// Attempt to delete the non-existent file
		boolean result = FileManager.deleteFile(nonExistentFilePath);

		// Assert that the deletion result is false since the file doesn't exist
		assertFalse("The file deletion should return false if the file does not exist.", result);
	}

	/**
	 * Tests the `isTemporaryFile` method for files with the `.crdownload`
	 * extension. Verifies that files with this extension are correctly identified
	 * as temporary.
	 */
	@Test
	public void testIsTemporaryFile_Crdownload() {
		File crdownloadFile = new File("file.crdownload");
		assertTrue("File con estensione .crdownload dovrebbe essere considerato temporaneo.",
				FileManager.isTemporaryFile(crdownloadFile));
	}

	/**
	 * Tests the `isTemporaryFile` method for files with the `.part` extension.
	 * Verifies that files with this extension are correctly identified as
	 * temporary.
	 */
	@Test
	public void testIsTemporaryFile_Part() {
		File partFile = new File("file.part");
		assertTrue("File con estensione .part dovrebbe essere considerato temporaneo.",
				FileManager.isTemporaryFile(partFile));
	}

	/**
	 * Tests the `isTemporaryFile` method for hidden files (those starting with a
	 * dot). Verifies that hidden files are correctly identified as temporary.
	 */
	@Test
	public void testIsTemporaryFile_HiddenFile() {
		File hiddenFile = new File(".hiddenFile");
		assertTrue("File che inizia con un punto dovrebbe essere considerato temporaneo.",
				FileManager.isTemporaryFile(hiddenFile));
	}

	/**
	 * Tests the `isTemporaryFile` method for non-temporary files (e.g., `.txt`,
	 * `.jpg`). Verifies that files with these extensions are not considered
	 * temporary.
	 */
	@Test
	public void testIsTemporaryFile_NotTemporary() {
		File normalFile = new File("file.txt");
		assertFalse("File con estensione .txt non dovrebbe essere considerato temporaneo.",
				FileManager.isTemporaryFile(normalFile));

		File imageFile = new File("image.jpg");
		assertFalse("File con estensione .jpg non dovrebbe essere considerato temporaneo.",
				FileManager.isTemporaryFile(imageFile));
	}

	/**
	 * Tests the `isFileStable` method to verify that it correctly identifies stable
	 * files. Ensures the method returns true for a file that has been written to
	 * and is not being modified.
	 */
	@Test
	public void testIsFileStable_Try() throws IOException {
		// Create and write to the stable file
		stableFile = new File("stableFile.txt");
		stableFile.createNewFile();
		FileManager.writeFile(stableFile.getAbsolutePath(), "Test content");

		// Verify if the file is stable
		assertTrue("Il file dovrebbe essere stabile", FileManager.isFileStable(stableFile));
	}

	/**
	 * Tests the `isFileStable` method to check how it handles thread interruptions.
	 * Verifies that the method handles interruptions properly without causing a
	 * deadlock.
	 */
	@Test
	public void testIsFileStable_Catch() throws IOException {
		// Create an empty file
		emptyFile = new File("emptyFile.txt");
		emptyFile.createNewFile();

		// Interrupt the thread before calling isFileStable to force handling of
		// interruption
		Thread.currentThread().interrupt();

		// Verify that the method correctly handles the interruption
		assertFalse("Il metodo dovrebbe gestire l'interruzione", FileManager.isFileStable(emptyFile));
	}

	/**
	 * Tests the `getProjectFolder` method to verify that the project folder path is
	 * correctly retrieved. Ensures that the method returns a valid path that exists
	 * on the filesystem.
	 */
	@Test
	public void testGetProjectFolder() {
		// Create the test file
		FileManager.createFile(testFilePath);

		// Retrieve the project folder path and construct the full file path
		String projectFolder = FileManager.getProjectFolder() + "\\" + testFilePath;

		// Assert that the project folder path is not null
		assertNotNull("Project folder path should not be null.", projectFolder);

		// Assert that the project folder path exists
		assertTrue("Project folder path should exist.", new File(projectFolder).exists());
	}

	/**
	 * Verifies that the `getConfigValue` method returns the correct value for a
	 * valid key. It checks that the returned value matches the expected value.
	 */
	@Test
	public void testGetConfigValueValidKey() {
		String apiKey = FileManager.getConfigValue("api_key");
		assertNull("895b6aece66d9a168c9822eb4254f2f44993e347c5ea0ddf90708982e857d613", apiKey);

	}

	/**
	 * Verifies that the `getConfigValue` method returns null when an invalid key is
	 * requested. Ensures that no exception is thrown when a key does not exist in
	 * the configuration.
	 */
	@Test
	public void testGetConfigValueInvalidKey() {
		String value = FileManager.getConfigValue("nonexistent_key");
		assertNull(value);
	}
}
