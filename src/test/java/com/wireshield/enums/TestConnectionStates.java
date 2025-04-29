package com.wireshield.enums;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * Unit test class for the {@code connectionStates} enum. This class ensures the
 * correctness of the enum's defined values.
 */
public class TestConnectionStates {

	/**
	 * Tests the values of the {@code connectionStates} enum. Verifies that the enum
	 * contains the expected values and that they can be retrieved using
	 * {@code valueOf}.
	 */
	@Test
	public void testEnumValues() {
		// Verify that the enum contains the correct values
		assertEquals(connectionStates.CONNECTED, connectionStates.valueOf("CONNECTED"));
		assertEquals(connectionStates.CONNECTION_IN_PROGRESS, connectionStates.valueOf("CONNECTION_IN_PROGRESS"));
		assertEquals(connectionStates.DISCONNECTED, connectionStates.valueOf("DISCONNECTED"));
	}
}
