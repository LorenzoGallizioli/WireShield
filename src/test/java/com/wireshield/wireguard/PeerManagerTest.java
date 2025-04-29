
package com.wireshield.wireguard;

import static org.junit.Assert.*;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

/**
 * Unit tests for the PeerManager class in the WireGuard module. These tests
 * verify the functionality of managing peers such as adding, removing, and
 * retrieving peers, as well as parsing the peer configuration.
 */
public class PeerManagerTest {

	// Sample configuration string for testing purposes
	String testString = """
			[Interface]
			PrivateKey = cIm09yQB5PUxKIhUwyK8TwL6ulaemcllbuzSCaOG0UM=
			Address = 172.0.0.6/32
			DNS = 172.0.0.1
			MTU = 1420

			[Peer]
			PublicKey = DlaMue3dkdiExmuYtQVAPlreolMWXP5zg9l1omRUDDA=
			PresharedKey = 0GYNNk24bSVUKBVGQU2tS1+tu5wT/RV2dQ3Z2gFxrNU=
			AllowedIPs = 0.0.0.0/0, ::/0
			Endpoint = 140.238.212.179:51820
			""";

	// Parsed peer configuration data
	Map<String, Map<String, String>> extDatas = PeerManager.parsePeerConfig(testString);

	// PeerManager instance and peerId for test operations
	PeerManager pm;
	String peerId;

	/**
	 * Setup method that initializes the PeerManager instance before each test. This
	 * method is run before each test method is executed.
	 */
	@Before
	public void setUp() {
		pm = PeerManager.getInstance();
	}

	/**
	 * Test the removePeer() method by verifying if peers can be removed correctly.
	 * The test checks for edge cases (null or empty ID) and successful removal of a
	 * peer.
	 */
	@Test
	public void testRemovePeer() {

		// Create a peer and get its ID
		peerId = pm.createPeer(extDatas, "A");

		// Test removal with invalid peerId (null or empty string)
		assertFalse(pm.removePeer(null));
		assertFalse(pm.removePeer(""));

		// Get peers list before and after removal to check changes
		Peer[] pBefore = pm.getPeers();
		assertTrue(pm.removePeer(peerId));

		// Get the list of peers after removal and ensure it's different
		Peer[] pAfter = pm.getPeers();
		assertNotEquals(pAfter, pBefore);

	}

	/**
	 * Test the addPeer() and getPeers() methods. This test adds a peer and verifies
	 * if the peer is successfully added to the list.
	 */
	@Test
	public void testAddAndGetPeers() {

		// Create a new peer and get its ID
		peerId = pm.createPeer(extDatas, "B");

		// Retrieve the list of peers
		Peer[] p = pm.getPeers();

		// Assert that the list is not empty
		assertTrue("Peers list is empty", p.length > 0);

		// Verify the newly added peer is the last one in the list
		assertEquals(p[p.length - 1], pm.getPeerById(peerId));
	}

	/**
	 * Test the getPeerById() method. This test checks retrieving a peer by its ID,
	 * including invalid and valid scenarios.
	 */
	@Test
	public void testGetPeerById() {

		// Create a new peer and get its ID
		peerId = pm.createPeer(extDatas, "C");

		// Test invalid peerId (empty or null) should return null
		Peer peer = pm.getPeerById("");
		assertNull(peer);
		peer = pm.getPeerById(null);
		assertNull(peer);

		// Retrieve peer using its valid ID
		peer = pm.getPeerById(peerId);

		// Verify the retrieved peer matches the last peer in the list
		Peer[] p = pm.getPeers();
		assertEquals("Peer retrieved by ID does not match the first peer in the list", p[p.length - 1], peer);
	}

	/**
	 * Test the parsePeerConfig() method to ensure the configuration string is
	 * parsed correctly. This test checks if the parsed configuration values match
	 * the expected values.
	 */
	@Test
	public void testParsePeerConfig() {
		assertEquals("PrivateKey mismatch", "cIm09yQB5PUxKIhUwyK8TwL6ulaemcllbuzSCaOG0UM=",
				extDatas.get("Interface").get("PrivateKey"));
		assertEquals("Address mismatch", "172.0.0.6/32", extDatas.get("Interface").get("Address"));
		assertEquals("DNS mismatch", "172.0.0.1", extDatas.get("Interface").get("DNS"));
		assertEquals("MTU mismatch", "1420", extDatas.get("Interface").get("MTU"));
		assertEquals("PublicKey mismatch", "DlaMue3dkdiExmuYtQVAPlreolMWXP5zg9l1omRUDDA=",
				extDatas.get("Peer").get("PublicKey"));
		assertEquals("PresharedKey mismatch", "0GYNNk24bSVUKBVGQU2tS1+tu5wT/RV2dQ3Z2gFxrNU=",
				extDatas.get("Peer").get("PresharedKey"));
		assertEquals("AllowedIPs mismatch", "0.0.0.0/0, ::/0", extDatas.get("Peer").get("AllowedIPs"));
		assertEquals("Endpoint mismatch", "140.238.212.179:51820", extDatas.get("Peer").get("Endpoint"));
	}

}
