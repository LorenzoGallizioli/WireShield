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
	private static String wgPath;
	private static String wireguardPath;
	private static String defaultPeerPath;

	private Thread wireGuardInterfaceSetDownThread;
	private Thread wireGuardInterfaceSetUpThread;

	private static final long BYTE = 1L;
    private static final long KILOBYTE = 1024L;
    private static final long MEGABYTE = KILOBYTE * 1024L;
    private static final long GIGABYTE = MEGABYTE * 1024L;
    private static final long TERABYTE = GIGABYTE * 1024L;

	/**
	 * Private constructor to ensure Singleton pattern. Initializes default values
	 * and determines the path to the WireGuard executable.
	 */
	private Connection() {
		this.wgPath = FileManager.getProjectFolder() + FileManager.getConfigValue("WGEXE_STD_PATH");
		this.wireguardPath = FileManager.getProjectFolder() + FileManager.getConfigValue("WIREGUARDEXE_STD_PATH");
		this.defaultPeerPath = FileManager.getProjectFolder() + FileManager.getConfigValue("PEER_STD_PATH");

		this.status = connectionStates.DISCONNECTED;
		this.sentTraffic = 0L;
		this.receivedTraffic = 0L;
		this.lastHandshakeTime = 0;
		this.activeInterface = "";
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

	public void setUp(String configFileName) {

		Runnable WireGuardInterfaceUpTask = () -> {
			int exitCode = -1;
		
			try {

				ProcessBuilder processBuilder = new ProcessBuilder(this.wireguardPath, "/installtunnelservice", this.defaultPeerPath + configFileName);
				Process process = processBuilder.start();
	
				BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
				String line;
				while ((line = reader.readLine()) != null) {
					logger.info(line);
				}
	
				exitCode = process.waitFor();
				
			} catch (IOException e) {
				e.printStackTrace();
				
			} catch (InterruptedException e) {
				logger.error("Thread was interrupted while starting the WireGuard interface.");

			}
			
			if (exitCode == 0) {

				while (this.getActiveInterface() == null && !Thread.currentThread().isInterrupted()) {
					try {
						Thread.sleep(200); // Wait for 1 second before checking again
					} catch (InterruptedException e) {
						logger.error("Error while waiting for WireGuard interface to starts: {}", e.getMessage());
					}
				}
				this.status = connectionStates.CONNECTED;

			} else {
				logger.error("Error starting WireGuard interface -> exit code: {}", exitCode);
			}
		
			logger.info("Thread stopped - [setUp()] set up wireguard connection thread terminated.");
		};

		this.wireGuardInterfaceSetUpThread = new Thread(WireGuardInterfaceUpTask);

		this.wireGuardInterfaceSetUpThread.setDaemon(true);
		this.wireGuardInterfaceSetUpThread.start();
	}

	public void setDown(String interfaceName){

		Runnable WireGuardInterfaceDownTask = () -> {
			int exitCode = -1;

			try {
				ProcessBuilder processBuilder = new ProcessBuilder(this.wireguardPath, "/uninstalltunnelservice", interfaceName);
				Process process = processBuilder.start();
	
				BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
				String line;
				while ((line = reader.readLine()) != null) {
					logger.info(line);
				}
				
				exitCode = process.waitFor();
				
			} catch (IOException e) {
				e.printStackTrace();		

			} catch (InterruptedException e) {
				logger.error("Thread was interrupted while stopping the WireGuard interface.");

			}
			
			if (exitCode == 0) {

				while (getActiveInterface() != null && !Thread.currentThread().isInterrupted()) {
					try {
						Thread.sleep(200); // Wait for 1 second before checking again
					} catch (InterruptedException e) {
						logger.error("Error while waiting for WireGuard interface to stpos: {}", e.getMessage());
					}
				}
				this.status = connectionStates.DISCONNECTED;

			} else {
				logger.error("Error stopping WireGuard interface -> exit code: {}", exitCode);	
			}

			logger.info("Thread stopped - [setDown()] interrupt wireguard connection thread terminated.");

		};

		this.wireGuardInterfaceSetDownThread = new Thread(WireGuardInterfaceDownTask);

		this.wireGuardInterfaceSetDownThread.setDaemon(true);
		this.wireGuardInterfaceSetDownThread.start();
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
		this.activeInterface = this.getActiveInterface();
		if (this.activeInterface == null || param == null) return null;

		try {

			ProcessBuilder processBuilder = new ProcessBuilder(this.wgPath, "show", this.activeInterface, param);
			Process process = processBuilder.start();

			// Read command output
			BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
			String line;
			while ((line = reader.readLine()) != null && !Thread.currentThread().isInterrupted()) {
				return line.split("=")[1].trim();
			}
			return null;

		} catch (IOException e) {
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
			ProcessBuilder processBuilder = new ProcessBuilder(this.wgPath, "show", "interfaces");
			process = processBuilder.start();

			// Read output to find the first active interface
			try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
				String line;

				while ((line = reader.readLine()) != null && !Thread.currentThread().isInterrupted()) {
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
	 * Sets the connection status.
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
		//this.updateLastHandshakeTime();
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
			"[INFO] Interface: %s%n[INFO] Status: %s%n[INFO] Last handshake time: %s%n[INFO] Received traffic: %s%n[INFO] Sent traffic: %s",
			interfaceName, this.status, this.lastHandshakeTime, this.receivedTraffic, this.sentTraffic
		);
	}
	
	
	/**
     * Formats a byte value to a human-readable string with appropriate unit
     * 
     * @param bytes The number of bytes to format
     * @return A formatted string with the appropriate unit (B, KB, MB, GB, TB)
     */
    public static String formatBytes(long bytes) {
        if (bytes < 0) {
            return "0 B";
        }
        
        if (bytes < KILOBYTE) {
            return bytes + " B";
        } else if (bytes < MEGABYTE) {
            double value = bytes / (double) KILOBYTE;
            return String.format("%.2f KB", value);
        } else if (bytes < GIGABYTE) {
            double value = bytes / (double) MEGABYTE;
            return String.format("%.2f MB", value);
        } else if (bytes < TERABYTE) {
            double value = bytes / (double) GIGABYTE;
            return String.format("%.2f GB", value);
        } else {
            double value = bytes / (double) TERABYTE;
            return String.format("%.2f TB", value);
        }
    }

	/**
	 * Interrupts all threads associated with the `wireGuardInterfaceSetUpThread` and `wireGuardInterfaceSetDownThread` services, if they are active.
	 * Checks if each thread is not null and is alive before attempting to interrupt it.
	 */
	public void interruptAllThreads() throws InterruptedException {
		if(this.wireGuardInterfaceSetUpThread != null && this.wireGuardInterfaceSetUpThread.isAlive()){
			this.wireGuardInterfaceSetUpThread.interrupt();
			this.wireGuardInterfaceSetUpThread.join();
		}
		if(this.wireGuardInterfaceSetDownThread != null && this.wireGuardInterfaceSetDownThread.isAlive()){
			this.wireGuardInterfaceSetDownThread.interrupt();
			this.wireGuardInterfaceSetDownThread.join();
		}
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
