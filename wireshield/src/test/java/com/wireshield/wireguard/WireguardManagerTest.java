package com.wireshield.wireguard;

import static org.junit.Assert.assertNotEquals;
import org.junit.Before;
import org.junit.Test;

import com.wireshield.av.FileManager;

/**
 * Unit tests for the WireguardManager class in the WireGuard module. These
 * tests verify the functionality of managing the interface status (up/down)
 * using the WireguardManager.
 */
public class WireguardManagerTest {

	// Configuration name for testing purposes
	String confName = "testPeer";

	String logDumpPath = FileManager.getProjectFolder() + FileManager.getConfigValue("LOGDUMP_STD_PATH");

	// WireguardManager instance for performing operations
	WireguardManager wireguardManager;

	/**
	 * Setup method that initializes the WireguardManager instance before each test.
	 * This method is run before each test method is executed.
	 */
	@Before
	public void setUp() {
		wireguardManager = WireguardManager.getInstance();
	}
    
    @Test
    public void updateWireguardLogs() throws InterruptedException {
    	
    	FileManager.deleteFile(logDumpPath);
    	FileManager.createFile(logDumpPath);
    	
    	String log_0 = FileManager.readFile(logDumpPath);
    	//System.out.println("log_0: " + log_0);
    	
    	wireguardManager.startUpdateWireguardLogs();
    	
    	Thread.sleep(1000);
    	
    	//System.out.println(wireguardManager.getLog());
    	assertNotEquals(log_0, wireguardManager.getLog());
    }
}
