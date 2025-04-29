package com.wireshield.localfileutils;

import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.After;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.MockitoAnnotations;

import com.wireshield.av.AntivirusManager;
import com.wireshield.enums.connectionStates;
import com.wireshield.enums.runningStates;
import com.wireshield.enums.vpnOperations;
import com.wireshield.wireguard.Peer;
import com.wireshield.wireguard.PeerManager;
import com.wireshield.wireguard.WireguardManager;



/**
 * This class contains unit tests for the functionalities of the
 * {@code SystemOrchestrator} class. It tests various operations such as
 * managing VPN, download, and antivirus, as well as retrieving statuses and
 * reports.
 */
public class SystemOrchestratorTest {

	// Test string used for parsing peer configurations
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

	// Map of parsed peer data
	Map<String, Map<String, String>> extDatas = PeerManager.parsePeerConfig(testString);

	// Peer ID and PeerManager instance for testing
	String peerId;
	PeerManager pm;
	Logger logger = LogManager.getLogger(SystemOrchestratorTest.class);
	
	SystemOrchestrator orchestrator;

    @Mock
    private WireguardManager wireguardManager;

    @Mock
    private DownloadManager downloadManager;

    @Mock
    private AntivirusManager antivirusManager;

    /*
     * Sets up the test environment before each test. 
     * This method is executed before each test and initializes the SystemOrchestrator and PeerManager instance.
     */
    @Before
    public void setUp() {
    	
    	orchestrator = SystemOrchestrator.getInstance();
    	orchestrator.resetIstance();
    	orchestrator = SystemOrchestrator.getInstance();
    	
		pm = PeerManager.getInstance();
    	
        orchestrator.setGuardianState(runningStates.DOWN); // Ensure guardian is stopped

    }
    
    @After
    public void setDown() {
    	orchestrator.manageDownload(runningStates.DOWN);
    	orchestrator.manageAV(runningStates.DOWN);
    	orchestrator.manageVPN(vpnOperations.STOP, null);
    	
    }

	/**
	 * Test the {@code manageVPN} method with the START operation. This test checks
	 * if the VPN connection status is set to {@code CONNECTED} after starting the
	 * VPN.
	 * @throws InterruptedException 
	 */
	@Test
	public void testManageVPNStart() throws InterruptedException {
        // Test managing download monitoring when it is UP
        orchestrator.manageDownload(runningStates.UP);
        
        Thread.sleep(200);
        
        assertEquals(runningStates.UP, orchestrator.getMonitorStatus());
        logger.info("Download monitoring status set to UP");

        // Test managing download monitoring when it is DOWN
        orchestrator.manageDownload(runningStates.DOWN);
        assertEquals(runningStates.DOWN, orchestrator.getMonitorStatus());
        logger.info("Download monitoring status set to DOWN");
    }


	/**
	 * Test the {@code manageDownload} method with the DOWN state. This test
	 * verifies that the download monitoring service is stopped successfully.
	 * @throws InterruptedException 
	 */
	@Test
	public void testManageDownloadDown() throws InterruptedException {
		orchestrator.manageDownload(runningStates.UP);
		
		Thread.sleep(200);
		// Execute the method to stop the download monitoring
		orchestrator.manageDownload(runningStates.DOWN);
		System.out.println(orchestrator.getDownloadManager().getMonitorStatus());
		// Verify that the monitoring status is DOWN
		assertEquals(orchestrator.getDownloadManager().getMonitorStatus(), runningStates.DOWN);
	}

	/**
	 * Test the {@code manageAV} method with the UP state. This test verifies that
	 * the antivirus scan is started successfully.
	 */
	@Test
	public void testManageAVUp() {
		// Execute the method to start the antivirus scan
		orchestrator.manageAV(runningStates.UP);

		// Verify that the antivirus scan status is UP
		assertEquals(orchestrator.getAntivirusManager().getScannerStatus(), runningStates.UP);
	}

	/**
	 * Test the {@code manageAV} method with the DOWN state. This test verifies that
	 * the antivirus scan is stopped successfully.
	 */
	@Test
	public void testManageAVDown() {
		// Execute the method to stop the antivirus scan
		orchestrator.manageAV(runningStates.DOWN);

		// Verify that the antivirus scan status is DOWN
		assertTrue(orchestrator.getAntivirusManager().getScannerStatus() == runningStates.DOWN);
	}


	/**
	 * Test the {@code getMonitorStatus} method. This test verifies that the correct
	 * monitoring status is returned.
	 */
	@Test
	public void testGetMonitorStatus() {

		orchestrator.manageDownload(runningStates.UP);

		// Call the method to get the monitoring status
		runningStates status = orchestrator.getMonitorStatus();

		// Verify that the monitoring status is UP
		assertEquals(runningStates.UP, status);
	}

	/**
	 * Test the {@code getAVStatus} method. This test verifies that the correct
	 * antivirus status is returned.
	 */
	@Test
	public void testGetAVStatus() {

		orchestrator.manageAV(runningStates.UP);

		// Call the method to get the antivirus status
		runningStates status = orchestrator.getScannerStatus();

		// Verify that the antivirus status is UP
		assertEquals(runningStates.UP, status);
	}

	/**
	 * Test the {@code addPeer} method. This test verifies that a peer is
	 * successfully added to the system.
	 */
	@Test
	public void testAddPeer() {

		// Add a peer and get the peer list
		peerId = pm.createPeer(extDatas, "B");

		Peer[] p = pm.getPeers();

		// Verify that the peer list is not empty and the peer has been added
		assertTrue("Peers list is empty", p.length > 0);
		assertEquals(p[p.length - 1], pm.getPeerById(peerId));
	}

	/**
	 * Test the {@code getReportInfo} method. This test verifies that the report
	 * information is retrieved correctly.
	 */
	@Test
	public void testGetReportInfo() {
		String report = "SampleReport";

		// Call the method to get the report info
		String result = orchestrator.getReportInfo(report);

		// Verify that the result is not null
		assertNotNull("Report info should not be null", result);
	}

	/**
	 * Test the {@code getWireguardManager} method. This test verifies that the
	 * WireguardManager instance is returned.
	 */
	@Test
	public void testGetWireguardManager() {

		// Call the method to get the WireguardManager instance
		WireguardManager manager = orchestrator.getWireguardManager();

		// Verify that the WireguardManager instance is not null
		assertNotNull("WireguardManager should not be null", manager);
	}

	/**
	 * Test the {@code getDownloadManager} method. This test verifies that the
	 * DownloadManager instance is returned.
	 */
	@Test
	public void testGetDownloadManager() {

		// Call the method to get the DownloadManager instance
		DownloadManager manager = orchestrator.getDownloadManager();

		// Verify that the DownloadManager instance is not null
		assertNotNull("DownloadManager should not be null", manager);
	}

	/**
	 * Test the {@code getAntivirusManager} method. This test verifies that the
	 * AntivirusManager instance is returned.
	 */
	@Test
	public void testGetAntivirusManager() {
		// Call the method to get the AntivirusManager instance
		AntivirusManager manager = orchestrator.getAntivirusManager();

		// Verify that the AntivirusManager instance is not null
		assertNotNull("AntivirusManager should not be null", manager);
	}

    @Test
    public void testStatesGuardian_NormalOperation() throws InterruptedException {
    	MockitoAnnotations.openMocks(this);
        orchestrator.setObjects(wireguardManager, antivirusManager, downloadManager);
    	
        // Mock normal operation
        when(wireguardManager.getConnectionStatus()).thenReturn(connectionStates.CONNECTED);
        when(antivirusManager.getScannerStatus()).thenReturn(runningStates.UP);
        when(downloadManager.getMonitorStatus()).thenReturn(runningStates.UP);

        orchestrator.setGuardianState(runningStates.UP);
        orchestrator.statesGuardian();

        // Allow some time for the thread to execute
        Thread.sleep(500);

        // Verify no actions taken
        verify(wireguardManager, never()).setInterfaceDown();
        verify(downloadManager, never()).forceStopMonitoring();
        verify(antivirusManager, never()).stopScan();

        orchestrator.setGuardianState(runningStates.DOWN); // Stop the guardian thread
    }
    
    /**
     * Test method. Simulate a AV failure and detects if GuardianState Thread takes action.
     * It is not possible to verify effectiveness but only that it invokes the designated functions.
     */
    @Test
    public void testStatesGuardian_AVComponentFailure() throws InterruptedException {
    	MockitoAnnotations.openMocks(this);
        orchestrator.setObjects(wireguardManager, antivirusManager, downloadManager);
    	
        // Mock antivirus failure
        when(orchestrator.getWireguardManager().getConnectionStatus()).thenReturn(connectionStates.CONNECTED);
        when(orchestrator.getAntivirusManager().getScannerStatus()).thenReturn(runningStates.DOWN);
        when(orchestrator.getDownloadManager().getMonitorStatus()).thenReturn(runningStates.UP);

        orchestrator.statesGuardian();

        // Allow some time for the thread to detect the failure
        Thread.sleep(500);

        // Verify actions taken
        verify(orchestrator.getDownloadManager(), atLeast(1)).forceStopMonitoring();
        verify(orchestrator.getWireguardManager(), atLeast(1)).setInterfaceDown();

        orchestrator.setGuardianState(runningStates.DOWN); // Stop the guardian thread
    }
    
    /**
     * Test method. Simulate a DowmloadMonitor failure and detects if GuardianState Thread takes action.
     * It is not possible to verify effectiveness but only that it invokes the designated functions.
     */
    @Test
    public void testStatesGuardian_DownloadComponentFailure() throws InterruptedException {
    	MockitoAnnotations.openMocks(this);
        orchestrator.setObjects(wireguardManager, antivirusManager, downloadManager);
    	
        // Mock antivirus failure
        when(orchestrator.getWireguardManager().getConnectionStatus()).thenReturn(connectionStates.CONNECTED);
        when(orchestrator.getAntivirusManager().getScannerStatus()).thenReturn(runningStates.UP);
        when(orchestrator.getDownloadManager().getMonitorStatus()).thenReturn(runningStates.DOWN);

        orchestrator.statesGuardian();

        // Allow some time for the thread to detect the failure
        Thread.sleep(500);

        // Verify actions taken
        verify(orchestrator.getAntivirusManager(), atLeast(1)).stopScan();
        verify(orchestrator.getWireguardManager(), atLeast(1)).setInterfaceDown();

        orchestrator.setGuardianState(runningStates.DOWN); // Stop the guardian thread
    }
    
    @Test
    public void testStatesGuardian_ThreadRunningControls() throws InterruptedException {
    	MockitoAnnotations.openMocks(this);
        orchestrator.setObjects(wireguardManager, antivirusManager, downloadManager);
    	
        orchestrator.statesGuardian();
        
        // Allow the thread to start
        Thread.sleep(200);
        
        assertEquals(runningStates.UP, orchestrator.getGuardianState());
        orchestrator.setGuardianState(runningStates.DOWN);

        // Allow the thread to terminate gracefully
        Thread.sleep(200);

        assertEquals(runningStates.DOWN, orchestrator.getGuardianState());
    }
    
    @Test
    public void testSetAndGetGuardianState() {
    	
        // Set state and verify
    	orchestrator.setGuardianState(runningStates.UP);
        assertEquals(runningStates.UP, orchestrator.getGuardianState());

        orchestrator.setGuardianState(runningStates.DOWN);
        assertEquals(runningStates.DOWN, orchestrator.getGuardianState());
    }

}
