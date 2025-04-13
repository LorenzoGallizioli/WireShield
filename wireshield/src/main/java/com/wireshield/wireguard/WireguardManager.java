package com.wireshield.wireguard;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.parser.ParseException;

import com.wireshield.av.FileManager;
import com.wireshield.enums.connectionStates;
import com.wireshield.windows.WFPManager;

/**
 * The WireguardManager class is responsible for managing the WireGuard VPN,
 * including starting and stopping the interface, updating connection
 * statistics, and managing logs.
 */
public class WireguardManager {
	private static final Logger logger = LogManager.getLogger(WireguardManager.class);

	private static WireguardManager instance;
	private static String wireguardPath;
	private static String defaultPeerPath;
	private static String logDumpPath;
	private Connection connection;
	private PeerManager peerManager;
	private String logs;
	private Process WFPprocess;

	private Thread setUpWFPRulesThread;
	private Thread updateWireguardLogsThread;
	private Thread startUpdateConnectionStatsThread;


	/**
	 * Private constructor for the WireguardManager class. Initializes paths and
	 * starts log update thread.
	 */
	private WireguardManager() {
		this.wireguardPath = FileManager.getProjectFolder() + FileManager.getConfigValue("WIREGUARDEXE_STD_PATH");
		this.defaultPeerPath = FileManager.getProjectFolder() + FileManager.getConfigValue("PEER_STD_PATH");
		this.logDumpPath = FileManager.getProjectFolder() + FileManager.getConfigValue("LOGDUMP_STD_PATH");

		File file = new File(wireguardPath);
		if (!file.exists() || !file.isFile()) {
			logger.error("WireGuard executable not found");
			return;
		}

		if (Connection.getInstance() != null) {
			this.connection = Connection.getInstance();
		} else {
			throw new IllegalStateException("Il costruttore di Connection ha restituito un oggetto null");
		} 
		
		if (PeerManager.getInstance() != null) {
			this.peerManager = PeerManager.getInstance();
		} else {
			throw new IllegalStateException("Il costruttore di PeerManager ha restituito un oggetto null");
		}
		
		this.startUpdateWireguardLogs(); // Start log update thread
	}

	/**
	 * Public static method to get the Singleton instance of WireguardManager. If
	 * the instance does not exist, it will be created with the provided wgPath.
	 *
	 * @param wgPath the path to the WireGuard executable.
	 * @return the single instance of WireguardManager.
	 * @throws ParseException If there is an error parsing configuration.
	 * @throws IOException    If an I/O error occurs.
	 */
	public static synchronized WireguardManager getInstance() {
		if (instance == null) {
			instance = new WireguardManager();
		}
		return instance;
	}

	/**
	 * Starts the WireGuard interface based on the given configuration file.
	 * 
	 * @param configFileName The name of the configuration file (including extension).
	 * @return True if the interface is successfully started, false otherwise.
	 */
	public void setInterfaceUp(String configFileName) {
		String activeInterface = connection.getActiveInterface();

		if (activeInterface != null) {
			logger.warn("WireGuard interface is already up.");
		}

		String peerNameWithoutExtension = configFileName.contains(".") ? configFileName.substring(0, configFileName.lastIndexOf(".")) : configFileName;
		this.setUpWFPRules(WFPManager.makeCommand(WFPManager.getAllCIDR_permit(this.defaultPeerPath, peerNameWithoutExtension)));
		
		this.connection.setUp(configFileName); // Set the connection with the given config file name
	}

	/**
	 * Stops the active WireGuard interface.
	 * 
	 * @return True if the interface was stopped successfully, false otherwise.
	 */
	public void setInterfaceDown() {
		String interfaceName = this.connection.getActiveInterface();

		if (interfaceName == null) {
			logger.info("No active WireGuard interface.");
			return;
		}
		
		this.setDownWFPRules();

		this.connection.setDown(interfaceName);
	}

	/**
	 * Updates connection statistics in a synchronized manner. This method waits
	 * until the active interface of the connection is available, then updates the
	 * active interface, traffic, and last handshake time.
	 */
	private synchronized void updateConnectionStats() {

		// Wait until the interface is active
		if (connection.getActiveInterface() != null) {
			
			// Update active interface
			connection.updateActiveInterface();

			// Update traffic
			connection.updateTraffic();

			// Update last handshake time
			connection.updateLastHandshakeTime();
			
		}else {
			
			logger.error("connection.getActiveInterface() returns NULL object");
			// Interface not active, check again shortly
		}		

	}

	/**
	 * Starts a thread to continuously update connection statistics. The method runs
	 * a background task that calls {@link #updateConnectionStats()} as long as the
	 * connection status is {@code CONNECTED}. After each update, it logs the
	 * current state of the connection and sleeps for 1 second before the next
	 * iteration.
	 */
	public void startUpdateConnectionStats() {
		this.startUpdateConnectionStatsThread = new Thread(() -> {
			while (this.connection.getStatus() == connectionStates.CONNECTED && !Thread.currentThread().isInterrupted()) { // Check interface is up
				try {
					
					// Update connection stats
					this.updateConnectionStats();
					Thread.sleep(350); // wait
					
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();	
				}
			}
			
			this.connection.setLastHandshakeTime(0);
			this.connection.setReceivedTraffic(0);
			this.connection.setSentTraffic(0);

			logger.info("Thread stopped - [startUpdateConnectionStats()] query connection stats thread terminated.");

		});

		this.startUpdateConnectionStatsThread.setDaemon(true);
		this.startUpdateConnectionStatsThread.start();
	}
	
	/**
	 * Updates the WireGuard logs by executing the given command and reading the log file.
	 * If the log file does not exist, it attempts to create it.
	 *
	 * @param command an array of strings representing the command to execute for updating logs
	 * @throws InterruptedException if the process is interrupted while waiting for completion
	 * @throws IOException if an I/O error occurs while reading or creating the log file
	 */
	private void updateWireguardLogs(String[] command) throws InterruptedException, IOException {
		File logFile = new File(this.logDumpPath);
	    if (logFile.exists() && logFile.isFile()) {
	        
			//logger.debug(command[0] + " " + command[1] + " " + command[2]);
	        ProcessBuilder processBuilder = new ProcessBuilder(command);
			processBuilder.redirectErrorStream(true);

		    Process process = processBuilder.start();
			process.waitFor();
	        	
	        String logDump = FileManager.readFile(logDumpPath);
	        this.logs = logDump;

	    } else {
	        logger.error(this.logDumpPath + " not exits - Creating... ");
	        if(FileManager.createFile(this.logDumpPath)) {
	        	logger.info(this.logDumpPath + " created.");
	        } else {
	        	logger.error("Error occured during " + this.logDumpPath + " creation.");	        		
	        }
	    }    
	}

	/**
	 * Starts a thread to continuously update WireGuard logs. This method executes a
	 * background task that periodically dumps WireGuard logs into a specified file
	 * using a {@link ProcessBuilder}. The logs are read into memory and stored. The
	 * task runs indefinitely, with a 1-second sleep between iterations. If the
	 * thread is interrupted, it stops and logs an error.
	 */
	public void startUpdateWireguardLogs() {

		String[] command = {"cmd.exe", "/c", this.wireguardPath + " /dumplog > " + this.logDumpPath};

		this.updateWireguardLogsThread = new Thread(() -> {
			while (!Thread.currentThread().isInterrupted() && connection.getStatus() == connectionStates.CONNECTED) {
				
				try {
					
					this.updateWireguardLogs(command);
					Thread.sleep(500);
					
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();	
					
				} catch (IOException e) {
					Thread.currentThread().interrupt();	
				}
			}
			logger.info("Thread stopped - [startUpdateWireguardLogs()] retrive wireguard logs thread terminated.");
		});

		// Set the thread as not a Deamon to ensure log file remains in a consistent state
		this.updateWireguardLogsThread.setDaemon(false);
		this.updateWireguardLogsThread.start();
	}

	/**
 	 * Starts a background thread to apply custom Windows Filtering Platform (WFP) rules
 	 * by executing a specified command. The method continuously monitors the process
 	 * and ensures that the rules are removed when the connection is no longer active.
 	 *
     * @param command The command to execute for setting up WFP rules.
 	 */
	public void setUpWFPRules(String command) {

		this.setUpWFPRulesThread = new Thread(() -> {
			try {
				// Start process
				this.WFPprocess = new ProcessBuilder(command.split(" ")).start();
				System.out.println("WFP custom rules applied: " + command);
	
				while (!Thread.currentThread().isInterrupted()) {
					// Check if process is still running
					this.WFPprocess.waitFor();

					if (!WFPprocess.isAlive()) {
						System.out.println("WFP process terminated");
						Thread.currentThread().interrupt();
						break;
					}
				}
				this.setDownWFPRules();
				System.out.println("WFP custom rules removed");
					
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();	
			} catch (IOException e) {
				Thread.currentThread().interrupt();	
			}
			logger.info("Thread stopped - [setUpWFPRules()] WFP rules thread interrupted.");
		});
		
		this.setUpWFPRulesThread.setDaemon(true);
		this.setUpWFPRulesThread.start();
	}

	
	/**
 	 * Terminates the WFP process if it is still running.
 	 * This method is called when the connection is closed or the process has finished.
 	 */
	public void setDownWFPRules() {
        if (this.WFPprocess != null && this.WFPprocess.isAlive()) {
            this.WFPprocess.destroy(); 
        }
    }
	
	/**
	 * Returns the current connection logs.
	 * 
	 * @return A string containing the connection logs.
	 */
    public String getConnectionLogs(){
        this.connection.updateActiveInterface();
        this.connection.updateTraffic();
        this.connection.updateLastHandshakeTime();
        return this.connection.toString();
    }

	/**
	 * Returns the current connection status.
	 * 
	 * @return The current connection status.
	 */
	public connectionStates getConnectionStatus() {
		return this.connection.getStatus();
	}

	/**
	 * Returns the PeerManager instance.
	 * 
	 * @return The PeerManager instance.
	 */
	public PeerManager getPeerManager() {
		return this.peerManager;
	}

	/**
	 * Returns the current connection object.
	 * 
	 * @return The current Connection object.
	 */
	public Connection getConnection() {
		return this.connection;
	}

	/**
	 * Returns reversed WireGuard logs.
	 * 
	 * @return The WireGuard logs.
	 */
	public String getLog() {
    	String[] lines = this.logs.split("\n");
    	Collections.reverse(Arrays.asList(lines));
    	this.logs = String.join("\n", lines);
		return this.logs;
	}


	/**
	 * Interrupts all threads associated with the `clamdServiceStart` and `clamdServiceStop` services, if they are active.
	 * Checks if each thread is not null and is alive before attempting to interrupt it.
	 */
	public void interruptAllThreads() throws InterruptedException {
		if(this.setUpWFPRulesThread != null && this.setUpWFPRulesThread.isAlive()){
			this.setUpWFPRulesThread.interrupt();
			this.setUpWFPRulesThread.join();
		}
		if(this.updateWireguardLogsThread != null && this.updateWireguardLogsThread.isAlive()){
			this.updateWireguardLogsThread.interrupt();
			this.updateWireguardLogsThread.join();
		}
		if(this.startUpdateConnectionStatsThread != null && this.startUpdateConnectionStatsThread.isAlive()){
			this.startUpdateConnectionStatsThread.interrupt();
			this.startUpdateConnectionStatsThread.join();
		}
	}
}
