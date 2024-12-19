package com.wireshield.localfileutils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/*
 * Unit test class for the FileManager class. This class contains tests for
 * verifying the functionality of file management methods such as create, write,
 * read, delete, and utility methods like calculating SHA256 hashes and retrieving
 * the project folder.
 */
public class FileManagerTest {

    private String testFilePath; // Path for the test file used in tests
    private File validFile; // File object for a valid file

    /*
     * Setup method that initializes the test file path before each test.
     * This method is run before every test to ensure a clean setup.
     */
    @Before
    public void setUp() {
        testFilePath = "testFile.txt"; // Initialize the test file path
    }

    /*
     * Cleanup method that ensures the test file is deleted after each test.
     * This is run after every test to ensure that there are no leftover files.
     */
    @After
    public void tearDown() {
        File file = new File(testFilePath);
        if (file.exists()) {
            file.delete(); // Delete the test file if it exists
        }
    }

    /*
     * Test for the createFile() method. Verifies that a file is created
     * successfully when the method is called.
     */
    @Test
    public void testCreateFile() {
        // Assert that the file is created successfully
        assertTrue("File should be created successfully.", FileManager.createFile(testFilePath));
        
        // Assert that the file exists on the filesystem
        assertTrue("File should exist on the filesystem.", new File(testFilePath).exists());
    }

    /*
     * Test for the writeFile() method. Verifies that content is written
     * successfully to a file.
     */
    @Test
    public void testWriteFile() {
        // Create the test file
        FileManager.createFile(testFilePath);
        
        // Define the content to be written to the file
        String content = "Test content";
        
        // Write the content to the file and assert success
        assertTrue("Content should be written successfully.", FileManager.writeFile(testFilePath, content));
        
        // Assert that the content written to the file matches the expected content
        assertEquals("Content should match the written data.", content, FileManager.readFile(testFilePath).trim());
    }

    /*
     * Test for the readFile() method. Verifies that content can be read
     * correctly from a file.
     */
    @Test
    public void testReadFile() {
        // Create the test file and write content to it
        FileManager.createFile(testFilePath);
        String content = "Read test content.";
        FileManager.writeFile(testFilePath, content);
        
        // Assert that the content read from the file matches the expected content
        assertEquals("Content read should match the written data.", content, FileManager.readFile(testFilePath).trim());
    }

    /*
     * Test for the deleteFile() method. Verifies that a file is deleted
     * successfully from the filesystem.
     */
    @Test
    public void testDeleteFile() {
        // Create the test file
        FileManager.createFile(testFilePath);
        
        // Assert that the file is deleted successfully
        assertTrue("File should be deleted successfully.", FileManager.deleteFile(testFilePath));
        
        // Assert that the file no longer exists on the filesystem
        assertFalse("File should not exist on the filesystem.", new File(testFilePath).exists());
    }

    /*
     * Test for the getProjectFolder() method. Verifies that the project folder
     * path is retrieved correctly.
     */
    @Test
    public void testGetProjectFolder() {
        // Create the test file
        FileManager.createFile(testFilePath);
        
        // Retrieve the project folder path and build the full file path
        String projectFolder = FileManager.getProjectFolder() + "\\" + testFilePath;
        
        // Assert that the project folder path is not null
        assertNotNull("Project folder path should not be null.", projectFolder);
        
        // Assert that the project folder path exists
        assertTrue("Project folder path should exist.", new File(projectFolder).exists());
    }

    /*
     * Test for the correct SHA256 calculation of a file. Verifies that the
     * SHA256 hash is calculated correctly for a file.
     */
    @Test
    public void testCalculateSHA256() {
        // Calculate SHA256 for validFile (this file should be set up properly for the test)
        String sha256Hash = FileManager.calculateSHA256(validFile);
        
        // Assert that the SHA256 hash is not null
        assertNotNull(sha256Hash); 
        
        // Assert that the SHA256 hash has a length of 64 characters (as expected for a SHA256 hash)
        assertEquals(64, sha256Hash.length()); 
    }
}
