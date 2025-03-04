package com.wireshield.wireguard;

import java.util.UUID;

/**
 * The Peer class represents a WireGuard peer, storing information such as keys,
 * address, DNS, and other configurations.
 */
public class Peer {
	private String privateKey;
	private String address;
	private String dns;
	private String mtu;
	private String publicKey;
	private String presharedKey;
	private String endPoint;
	private String allowedIPs;
	private String name;
	private String id;

	/**
	 * Constructs a new Peer with specified configuration parameters.
	 * 
	 * @param privateKey   The private key of the peer.
	 * @param address      The address of the peer.
	 * @param dns          The DNS of the peer.
	 * @param mtu          The MTU (Maximum Transmission Unit) of the peer.
	 * @param publicKey    The public key of the peer.
	 * @param presharedKey The preshared key of the peer.
	 * @param endPoint     The endpoint address of the peer.
	 * @param allowedIPs   The allowed IPs for the peer.
	 * @param name         The name of the peer.
	 */
	public Peer(String privateKey, String address, String dns, String mtu, String publicKey, String presharedKey, String endpoint, String allowedIPs, String name) {
		this.privateKey = privateKey;
		this.address = address;
		this.dns = dns;
		this.mtu = mtu;
		this.publicKey = publicKey;
		this.presharedKey = presharedKey;
		this.endPoint = endpoint;
		this.allowedIPs = allowedIPs;
		this.name = name;
		this.id = generateUniqueId(); // Generate unique ID for the peer.
	}

	/**
	 * Returns the name of the peer.
	 * 
	 * @return The name of the peer.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the ID of the peer.
	 * 
	 * @return The ID of the peer.
	 */
	public String getId() {
		return this.id;
	}

	/**
	 * Returns the endpoint of the peer.
	 * 
	 * @return The endpoint address of the peer.
	 */
	public String getEndPoint() {
		return endPoint;
	}

	/**
	 * Returns the public key of the peer.
	 * 
	 * @return The public key of the peer.
	 */
	public String getPublicKey() {
		return publicKey;
	}

	/**
	 * Returns the preshared key of the peer.
	 * 
	 * @return The preshared key of the peer.
	 */
	public String getPresharedKey() {
		return presharedKey;
	}

	/**
	 * Returns the allowed IP addresses for the peer.
	 * 
	 * @return The allowed IPs for the peer.
	 */
	public String getAllowedIps() {
		return allowedIPs;
	}

	/**
	 * Retrieves the private key of the peer.
	 * 
	 * @return The private key of the peer.
	 */
	public String getPrivateKey() {
		return privateKey;
	}

	/**
	 * Retrieves the address of the peer.
	 * 
	 * @return The address of the peer.
	 */
	public String getAddress() {
		return address;
	}

	/**
	 * Retrieves the DNS of the peer.
	 * 
	 * @return The DNS of the peer.
	 */
	public String getDNS() {
		return dns;
	}

	/**
	 * Retrieves the MTU (Maximum Transmission Unit) of the peer.
	 * 
	 * @return The MTU of the peer.
	 */
	public String getMTU() {
		return mtu;
	}

	/**
	 * Generates a unique identifier for the peer using UUID.
	 * 
	 * @return A unique identifier string for the peer.
	 * @see java.util.UUID#randomUUID()
	 */
	private static String generateUniqueId() {
		return UUID.randomUUID().toString();
	}

	/**
	 * Provides a string representation of the Peer object.
	 * 
	 * @return A string representation of the peer's configuration.
	 */
	@Override
	public String toString() {
		return String.format(
				"[INFO] ID: %s%n" + "[INFO] Name: %s%n" + "[INFO] Private Key: %s%n" + "[INFO] Address: %s%n"
						+ "[INFO] DNS: %s%n" + "[INFO] MTU: %s%n" + "[INFO] Public Key: %s%n"
						+ "[INFO] Preshared Key: %s%n" + "[INFO] Endpoint: %s%n" + "[INFO] Allowed IPs: %s",
				id, name, privateKey, address, dns, mtu, publicKey, presharedKey, endPoint, allowedIPs);
	}

}
