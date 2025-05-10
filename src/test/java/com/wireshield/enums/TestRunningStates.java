package com.wireshield.enums;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * Unit test class for the {@code runningStates} enum. This class ensures the
 * correctness of the enum's defined values.
 */
public class TestRunningStates {

	/**
	 * Tests the values of the {@code runningStates} enum. Verifies that the enum
	 * contains the expected values and that they can be retrieved using
	 * {@code valueOf}.
	 */
	@Test
	public void testEnumValues() {
		// Verify that the enum contains the correct values
		assertEquals(runningStates.UP, runningStates.valueOf("UP"));
		assertEquals(runningStates.DOWN, runningStates.valueOf("DOWN"));
	}
}
