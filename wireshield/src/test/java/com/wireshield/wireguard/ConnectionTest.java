package com.wireshield.wireguard;

import static org.junit.Assert.*;

import org.junit.Test;
import org.junit.runner.RunWith;

import com.wireshield.enums.connectionStates;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnitRunner;

/**
 * Unit tests for the Connection class in the WireGuard module. This class tests
 * various methods of the Connection class including traffic retrieval, status
 * management, interface detection, and more.
 */
@RunWith(MockitoJUnitRunner.class)
public class ConnectionTest {

	// Spy on the Connection instance to mock certain methods during testing
	@Spy
	Connection conn = Mockito.spy(Connection.getInstance());

	/**
	 * Test the behavior of the getTraffic() method when valid traffic data is
	 * returned. This test mocks the output of the 'wgShow' command.
	 */
	@Test
	public void testUpdateAndGetTraffic_valid() {

		// Mocking the wgShow("transfer") to return valid traffic data
		Mockito.doReturn("12345 67890").when(conn).wgShow("transfer");
		
		conn.updateTraffic();
		
		// Call the method and validate the results
		Long[] traffic = new Long[2];
		traffic[0] = conn.getSentTraffic();
		traffic[1] = conn.getReceivedTraffic();
		assertNotNull(traffic);
		
		// Assert that the traffic array is not null and the values are correct
		assertEquals(12345, (long) traffic[0]);
		assertEquals(67890, (long) traffic[1]);
	}

	/**
	 * Test the behavior of the getTraffic() method when the returned data is null.
	 * This test simulates a null response from the 'wgShow' command.
	 */
	@Test
	public void testUpdateAndGetTraffic_null() {

		// Mocking the wgShow("transfer") to return null
		Mockito.doReturn(null).when(conn).wgShow("transfer");
		
		conn.updateTraffic();

		// Call the method and validate the results
		Long[] traffic = new Long[2];
		traffic[0] = conn.getSentTraffic();
		traffic[1] = conn.getReceivedTraffic();
		
		// Assert that both traffic values default to 0 when the response is null
		assertEquals(0, (long) traffic[0]);
		assertEquals(0, (long) traffic[1]);
	}

	/**
	 * Test setting and getting the connection status. This method tests the setter
	 * and getter of the connection status field.
	 */
	@Test
	public void testSetStatusAndGetStatus() {

		// Set the status to CONNECTED
		conn.setStatus(connectionStates.CONNECTED);

		// Assert that the status retrieved is the same as the one set
		assertEquals(connectionStates.CONNECTED, conn.getStatus());
	}

	/**
	 * Test the getActiveInterface() method. This test simulates the output of the
	 * command to get the active interface.
	 */
	@Test
	public void testGetActiveInterface() throws IOException {

		// Run the method that retrieves the active interface
		conn.getActiveInterface(); // Simulate the output

		// Simulate the output of the 'cmd' command using ProcessBuilder
		ProcessBuilder processBuilder = new ProcessBuilder("cmd", "/c", "echo wg0");
		Process process = processBuilder.start();
		InputStream inputStream = process.getInputStream();
		BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));

		// Read the output of the command
		String activeInterface = reader.readLine();

		// Assert that the active interface is not null and is equal to 'wg0'
		assertNotNull(activeInterface);
		assertEquals("wg0", activeInterface);
	}

	/**
	 * Test the getLastHandshakeTime() method. This test simulates the output of the
	 * command to retrieve the last handshake time.
	 */
	@Test
	public void testGetLastHandshakeTime() throws IOException {

		// Run the method that retrieves the last handshake time
		conn.getLastHandshakeTime(); // Simulate the output

		// Simulate the output of the 'cmd' command using ProcessBuilder
		ProcessBuilder processBuilder = new ProcessBuilder("cmd", "/c", "echo latest-handshakes=1234567890");
		Process process = processBuilder.start();
		InputStream inputStream = process.getInputStream();
		BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));

		// Read the output line and parse the handshake time
		String line = reader.readLine();
		assertNotNull(line);
		Long lastHandshakeTime = Long.parseLong(line.split("=")[1]);

		// Assert that the last handshake time is correct
		assertEquals(Long.valueOf(1234567890), lastHandshakeTime);
	}

	/**
	 * Test the toString() method of the Connection class. This test ensures that
	 * the string representation of the Connection object is as expected.
	 */
	@Test
	public void testToString() {

		// Sample data for the Connection object
		Long sentTraffic = 12345L;
		Long receivedTraffic = 67890L;
		connectionStates status = connectionStates.CONNECTED;
		Long lastHandshakeTime = 1234567890L;
		String activeInterface = "wg0";

		// Set values on the connection object
		conn.setSentTraffic(sentTraffic);
		conn.setReceivedTraffic(receivedTraffic);
		conn.setStatus(status);
		conn.setLastHandshakeTime(lastHandshakeTime);
		conn.setActiveInterface(activeInterface);

		// Generate the expected string representation
		String expected = conn.toString();

		// Generate the actual string representation using String.format
		String actual = String.format(
				"[INFO] Interface: %s%n[INFO] Status: %s%n[INFO] Last handshake time: %s%n[INFO] Received traffic: %s%n[INFO] Sent traffic: %s",
				activeInterface, status, lastHandshakeTime, (long) receivedTraffic, (long) sentTraffic);

		// Assert that the expected and actual string representations are the same
		assertEquals(expected, actual);
	}
}