package com.wireshield.enums;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * Unit test class for the {@code vpnOperations} enum. This class ensures that
 * the defined values in the enum are correct and can be accessed as expected.
 */
public class TestVpnOperations {

	/**
	 * Tests the values of the {@code vpnOperations} enum. Verifies that the enum
	 * contains the expected values and that they can be retrieved using
	 * {@code valueOf}.
	 */
	@Test
	public void testEnumValues() {
		// Verify that the enum contains the correct values
		assertEquals(vpnOperations.START, vpnOperations.valueOf("START"));
		assertEquals(vpnOperations.STOP, vpnOperations.valueOf("STOP"));
	}
}
