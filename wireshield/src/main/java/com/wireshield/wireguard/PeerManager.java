package com.wireshield.wireguard;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The PeerManager class manages WireGuard peers, providing functionality for
 * creating, removing, and retrieving peers.
 */
public class PeerManager {

	private static PeerManager instance;
	private List<Peer> peers;

	/**
	 * Private constructor for the PeerManager class. Initializes the peer list.
	 */
	private PeerManager() {
		this.peers = new ArrayList<>();
	}

	/**
	 * Provides the Singleton instance of PeerManager.
	 * 
	 * @return The single instance of PeerManager.
	 */
	public static synchronized PeerManager getInstance() {
		if (instance == null) {
			instance = new PeerManager();
		}
		return instance;

	}

	/**
	 * Creates a new Peer object using the provided peer data and adds it to the
	 * peer list.
	 * 
	 * @param peerData A map containing peer information.
	 * @param name     The name of the peer.
	 * 
	 * @return The ID of the newly created peer.
	 */
	public String createPeer(Map<String, Map<String, String>> peerData, String name) {
		String privateKey = peerData.get("Interface").get("PrivateKey");
		String address = peerData.get("Interface").get("Address");
		String dns = peerData.get("Interface").get("DNS");
		String mtu = peerData.get("Interface").get("MTU");
		String publicKey = peerData.get("Peer").get("PublicKey");
		String presharedKey = peerData.get("Peer").get("PresharedKey");
		String endpoint = peerData.get("Peer").get("Endpoint");
		String allowedIPs = peerData.get("Peer").get("AllowedIPs");

		Peer p = new Peer(privateKey, address, dns, mtu, publicKey, presharedKey, endpoint, allowedIPs, name);
		peers.add(p);
		return p.getId();
	}

	/**
	 * Removes a peer from the list by its ID.
	 * 
	 * @param id The ID of the peer to remove.
	 * 
	 * @return true if the peer was removed, false otherwise.
	 */
	public boolean removePeer(String id) {
		if (id != null && !id.isEmpty()) {
			return peers.removeIf(p -> id.equals(p.getId()));
		}
		return false;
	}

	/**
	 * Finds and returns a peer by its ID.
	 * 
	 * @param id The ID of the peer to find.
	 * 
	 * @return The peer with the specified ID, or null if not found.
	 */
	public Peer getPeerById(String id) {
		if (id != null && !id.isEmpty()) {
			for (Peer p : peers) {
				if (id.equals(p.getId())) {
					return p;
				}
			}

		}
		return null;
	}
	
	/**
	 * Finds and returns a peer by its name.
	 * 
	 * @param name The name of the peer to find.
	 * 
	 * @return The peer with the specified name, or null if not found.
	 */
	public Peer getPeerByName(String name) {
		if (name != null && !name.isEmpty()) {
			for (Peer p : peers) {
				if (name.equals(p.getName())) {
					return p;
				}
			}

		}
		return null;
	}

	/**
	 * Returns all the peers.
	 * 
	 * @return An array of all peers.
	 */
	public Peer[] getPeers() {
		return this.peers.toArray(new Peer[peers.size()]);
	}

	/**
	 * Parses a configuration string and returns a map of sections and their
	 * key-value pairs.
	 * 
	 * @param config The configuration string to parse.
	 * 
	 * @return A map where each section name (e.g., "Interface", "Peer") is mapped
	 *         to a map of key-value pairs for that section.
	 */
	public static Map<String, Map<String, String>> parsePeerConfig(String config) {
		Map<String, Map<String, String>> configSections = new HashMap<>();

		String[] sections = config.split("\\[");
		for (String section : sections) {
			if (section.trim().isEmpty()) {
				continue;
			}

			int endOfSectionName = section.indexOf("]");
			String sectionName = section.substring(0, endOfSectionName).trim();

			String sectionBody = section.substring(endOfSectionName + 1).trim();

			Map<String, String> sectionParams = new HashMap<>();
			String[] lines = sectionBody.split("\n");
			for (String line : lines) {
				line = line.trim();
				if (line.isEmpty() || line.startsWith("#")) {
					continue;
				}

				String[] keyValue = line.split("=", 2);
				if (keyValue.length == 2) {
					sectionParams.put(keyValue[0].trim(), keyValue[1].trim());
				}
			}

			configSections.put(sectionName, sectionParams);
		}

		return configSections;
	}
	
	
	public void resetPeerList() {
		this.peers.clear();;
	}
}
