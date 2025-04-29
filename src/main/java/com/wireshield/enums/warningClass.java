package com.wireshield.enums;

/**
 * The warningClass enum represents the different levels of warnings that can be
 * assigned based on file analysis results.
 */
public enum warningClass {
	CLEAR, // Represents a clear state where no threats are detected.

	SUSPICIOUS, // Represents a suspicious state, indicating potential threats or a moderate
				// risk level.

	DANGEROUS, // Represents a dangerous state, indicating a high risk with confirmed malicious
				// activity.
}
