package com.wireshield.wireguard;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javafx.collections.ObservableList;

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
	 * Creates a new peer with the specified configuration parameters and adds it to
	 * the list of peers.
	 * 
	 * @param peerData The configuration parameters for the peer.
	 * @param name     The name of the peer.
	 * 
	 * @return The ID of the created peer, or null if the peer could not be created.
	 */
	public String createPeer(Map<String, Map<String, String>> peerData, String name) {

		if (peerData == null || name == null || name.isEmpty()) {
			return null;
		}
		System.out.println(peerData.toString());

		String privateKey = peerData.get("Interface").get("PrivateKey");
		String address = peerData.get("Interface").get("Address");
		String dns = peerData.get("Interface").get("DNS");
		String mtu = peerData.get("Interface").get("MTU");

		ObservableList<String> permittedCIDRList = null;
		if (peerData.get("PostUp") != null){
			return null;
		}

		String publicKey = peerData.get("Peer").get("PublicKey");
		String presharedKey = peerData.get("Peer").get("PresharedKey");
		String endpoint = peerData.get("Peer").get("Endpoint");
		String allowedIPs = peerData.get("Peer").get("AllowedIPs");

		System.out.println(peerData.toString());
		Peer p = new Peer(privateKey, address, dns, mtu, publicKey, presharedKey, endpoint, allowedIPs, permittedCIDRList, name);
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
     * Parses the content of the .conf file and returns a map with the sections and their corresponding parameters.
     * It uses regex to robustly identify the sections and key-value pairs.
     *
     * @param config the content of the configuration file
     * @return a map with sections and associated parameters
     */
    public static Map<String, Map<String, String>> parsePeerConfig(String config) {
        Map<String, Map<String, String>> configSections = new HashMap<>();

        // Pattern to identify the sections: captures the section name between square brackets
        // and the content until the next section or the end of the file.
        Pattern sectionPattern = Pattern.compile("\\[\\s*(.+?)\\s*\\](.*?)(?=\\[|\\z)", Pattern.DOTALL);
        Matcher sectionMatcher = sectionPattern.matcher(config);

        while (sectionMatcher.find()) {
            String sectionName = sectionMatcher.group(1).trim();
            String sectionBody = sectionMatcher.group(2).trim();

            Map<String, String> sectionParams = new HashMap<>();

            // Pattern to find the key/value pairs.
            // (?m) enables multiline mode so that ^ and $ refer to the beginning and end of each line.
            Pattern keyValuePattern = Pattern.compile("(?m)^\\s*([^=]+?)\\s*=\\s*(.+)$");
            Matcher kvMatcher = keyValuePattern.matcher(sectionBody);

            while (kvMatcher.find()) {
                String key = kvMatcher.group(1).trim();
                String value = kvMatcher.group(2).trim();
                sectionParams.put(key, value);
            }

            configSections.put(sectionName, sectionParams);
        }
        return configSections;
    }
	
	
	public void resetPeerList() {
		this.peers.clear();;
	}
}
