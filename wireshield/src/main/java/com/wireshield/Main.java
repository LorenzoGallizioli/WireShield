package com.wireshield;

import com.wireshield.ui.*;
import javax.swing.JOptionPane;
import java.io.IOException;

/**
 * The Main class serves as the entry point for the WireShield application. It
 * ensures the application is running with administrative privileges and then
 * launches the user interface.
 */
public class Main {
	/**
	 * The main method to launch the WireShield application. It verifies if the
	 * application has administrative rights before proceeding. If the application
	 * is not running as an administrator, it displays an informational message and
	 * terminates the execution.
	 *
	 * @param args Command-line arguments passed to the application.
	 */
	public static void main(String[] args) {
		
		if (!isRunningAsAdmin()) {
			JOptionPane.showMessageDialog(null, "You must run this application as an administrator.",
					"Administrator Required", JOptionPane.INFORMATION_MESSAGE);
			System.exit(0);
		}
		UserInterface.main(args); // Launch the user interface
	}

	/**
	 * Checks if the application is running with administrative privileges. It
	 * attempts to execute the "net session" command, which requires admin rights.
	 *
	 * @return {@code true} if the application is running as an administrator,
	 *         {@code false} otherwise.
	 */
	private static boolean isRunningAsAdmin() {
		try {
			ProcessBuilder processBuilder = new ProcessBuilder("net", "session");
			processBuilder.redirectErrorStream(true); // Combine error and output streams
			Process process = processBuilder.start();
			process.waitFor(); // Wait for the command to complete
			return process.exitValue() == 0; // Check if the command succeeded
		} catch (IOException e) {
			return false; // Command failed to execute
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt(); // Restore the thread's interrupted status
			return false;
		}
	}
}
