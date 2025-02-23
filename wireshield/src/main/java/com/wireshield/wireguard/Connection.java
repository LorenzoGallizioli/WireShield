package com.wireshield.wireguard;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.wireshield.av.FileManager;
import com.wireshield.enums.connectionStates;

/**
 * Represents a singleton instance for managing a WireGuard connection. Provides
 * methods to retrieve connection details, traffic statistics, and interface
 * status using WireGuard commands.
 */
public class Connection {
	private static final Logger logger = LogManager.getLogger(Connection.class);

	// Singleton instance
	private static Connection instance;

	// Connection state and statistics
	private connectionStates status;
	private long sentTraffic;
	private long receivedTraffic;
	private long lastHandshakeTime;

	// Active interface and path to WireGuard executable
	private String activeInterface;
	private String wgPath;

	/**
	 * Private constructor to ensure Singleton pattern. Initializes default values
	 * and determines the path to the WireGuard executable.
	 */
	private Connection() {
		wgPath = FileManager.getProjectFolder() + FileManager.getConfigValue("WGEXE_STD_PATH");
		status = connectionStates.DISCONNECTED;
		sentTraffic = 0;
		receivedTraffic = 0;
		lastHandshakeTime = 0;
		activeInterface = "";
	}

	/**
	 * Returns the Singleton instance of Connection. If no instance exists, creates
	 * one.
	 *
	 * @return Singleton instance of Connection.
	 */
	public static synchronized Connection getInstance() {
		if (instance == null) {
			instance = new Connection();
		}
		return instance;
	}
	
	/**
	 * Executes the `wg show` command to retrieve specific connection parameters.
	 *
	 * @param param [public-key | private-key | listen-port | fwmark | peers |
	 *              preshared-keys | endpoints | allowed-ips | latest-handshakes |
	 *              transfer | persistent-keepalive | dump]
	 * @return
	 */
	protected String wgShow(String param) {
		activeInterface = this.getActiveInterface();
		if (activeInterface == null || param == null)
			return null;

		try {
			ProcessBuilder processBuilder = new ProcessBuilder(wgPath, "show", activeInterface, param);
			Process process = processBuilder.start();

			// Read command output
			BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
			String line;
			while ((line = reader.readLine()) != null) {
				return line.split("=")[1].trim();
			}
			return null;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}


	/**
	 * Updates the sent and received traffic statistics using the WireGuard
	 * "transfer" parameter. Resets values to zero if no data is available.
	 */
	public void updateTraffic() {
		String trafficString = wgShow("transfer");

		if (trafficString != null) {
			this.sentTraffic = Long.parseLong(trafficString.trim().split("\\s+")[0]);
			this.receivedTraffic = Long.parseLong(trafficString.trim().split("\\s+")[1]);
		} else {
			this.sentTraffic = 0;
			this.receivedTraffic = 0;
		}
	}
	
	/**
	 * Retrieves the sent and received traffic statistics. Updates the values by
	 * invoking WireGuard commands.
	 *
	 * @return A Long array containing sent traffic (index 0) and received traffic
	 *         (index 1).
	 */
	public Long getSentTraffic() {
		return this.sentTraffic;

	}
	
	/**
	 * Retrieves the sent and received traffic statistics. Updates the values by
	 * invoking WireGuard commands.
	 *
	 * @return A Long array containing sent traffic (index 0) and received traffic
	 *         (index 1).
	 */
	public Long getReceivedTraffic() {
		return this.receivedTraffic;

	}

	/**
	 * Updates the name of the active WireGuard interface. If no interfaces are
	 * active, sets the value to null.
	 */
	protected void updateActiveInterface() {

		Process process = null;
		try {
			ProcessBuilder processBuilder = new ProcessBuilder(wgPath, "show", "interfaces");
			process = processBuilder.start();

			// Read output to find the first active interface
			try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
				String line;

				while ((line = reader.readLine()) != null) {
					if (!line.isEmpty()) {
						this.activeInterface = line; // Get only the first wg interface up and exit
						return;
					}
				}
				this.activeInterface = null; // No active interfaces found
			}
		} catch (IOException e) {
			logger.error("Error getting active interface: {}", e.getMessage());
			this.activeInterface = null;

		} finally {
			if (process != null) {
				process.destroy();
			}
		}
	}

	/**
	 * Retrieves the active WireGuard interface name.
	 * 
	 * @return The name of the active interface, or null if no interface is active.
	 */
	public String getActiveInterface() {
		this.updateActiveInterface();
		return this.activeInterface;
	}

	/**
	 * Retrieves the current connection status.
	 *
	 * @return The connection state.
	 */
	public connectionStates getStatus() {
		return this.status;
	}

	/**
	 * Updates the connection status.
	 *
	 * @param status The new connection state.
	 */
	public void setStatus(connectionStates status) {
		this.status = status;
	}

	/**
	 * Updates the last handshake time using the WireGuard "latest-handshakes"
	 * parameter.
	 */
	public void updateLastHandshakeTime() {
		String latestHandShake = wgShow("latest-handshakes");
		if (latestHandShake != null)
			this.lastHandshakeTime = Long.parseLong(latestHandShake);
	}

	/**
	 * Retrieves the last handshake time for the connection.
	 *
	 * @return The last handshake time in seconds.
	 */
	public Long getLastHandshakeTime() {
		this.updateLastHandshakeTime();
		return this.lastHandshakeTime;
	}
	

	/**
	 * Provides a string representation of the connection, including interface
	 * details, traffic statistics, and connection status.
	 */
	@Override
	public String toString() {
		String interfaceName = this.activeInterface == null ? "None" : this.activeInterface;

		return String.format(
				"Interface: %s%nStatus: %s%nLast handshake time: %s%nReceived traffic: %s byte %nSent traffic: %s byte",
				interfaceName, this.status, this.lastHandshakeTime, this.receivedTraffic, this.sentTraffic);
	}
	
	
	
	

	// Protected setters for internal testing
	protected void setSentTraffic(long sentTraffic) {
		this.sentTraffic = sentTraffic;
	}

	protected void setReceivedTraffic(long receivedTraffic) {
		this.receivedTraffic = receivedTraffic;
	}

	protected void setLastHandshakeTime(long lastHandshakeTime) {
		this.lastHandshakeTime = lastHandshakeTime;
	}

	protected void setActiveInterface(String activeInterface) {
		this.activeInterface = activeInterface;
	}

}
