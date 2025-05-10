package com.wireshield.av;

import java.io.File;

/**
 * Represents the interface for antivirus scanning operations. Implementations
 * of this interface are responsible for analyzing files for potential threats
 * using specific antivirus software.
 */
public interface AVInterface {

	/**
	 * Analyzes a given file for potential threats using antivirus software. This
	 * method scans the specified file and produces results that can be accessed
	 * through the implementing class.
	 * 
	 * @param file The file to be scanned. It must not be null and should point to a
	 *             valid file on the filesystem.
	 * 
	 * @throws IllegalArgumentException If the file is null or does not exist.
	 */
	public abstract void analyze(File file);
}
