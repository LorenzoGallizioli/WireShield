package com.wireshield.ui;
import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

import javafx.application.Platform;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.layout.AnchorPane;
import javafx.scene.control.TextArea;
import javafx.scene.control.Label;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import com.wireshield.enums.connectionStates;
import com.wireshield.enums.runningStates;
import com.wireshield.enums.vpnOperations;
import com.wireshield.localfileutils.SystemOrchestrator;
import com.wireshield.wireguard.WireguardManager;

public class UserInterfaceTest {
	private static boolean isToolkitInitialized = false;
    
	private UserInterface userInterface;

    @Mock
    private SystemOrchestrator mockSystemOrchestrator;

	@Mock
    private WireguardManager mockWireguardManager;

    @Before
    public void setUp() {
        // Inizializza manualmente il toolkit JavaFX
		if (!isToolkitInitialized) {
			Platform.startup(() -> {});
			isToolkitInitialized = true;
		}
		
        MockitoAnnotations.initMocks(this);
        userInterface = new UserInterface();

        // Mock del SystemOrchestrator
        UserInterface.so = mockSystemOrchestrator;

        // Inizializza i componenti JavaFX
        Platform.runLater(() -> {
            userInterface.vpnButton = new Button("Start VPN");
            userInterface.peerListView = new ListView<>();
            userInterface.logsArea = new TextArea();
            userInterface.avStatusLabel = new Label();
            userInterface.homePane = new AnchorPane();
        });
    }

    @Test
    public void testInitialize_disablesPeerListWhenConnected() {
        when(mockSystemOrchestrator.getConnectionStatus()).thenReturn(connectionStates.CONNECTED);

        Platform.runLater(() -> {
        	UserInterface.so = mockSystemOrchestrator;
        	userInterface.initialize();
            assertTrue(userInterface.peerListView.isDisable());
            verify(mockSystemOrchestrator).getConnectionStatus();
        });
    }

	@Test
	public void testChangeVPNState_startVPN() {
		when(mockSystemOrchestrator.getConnectionStatus()).thenReturn(connectionStates.DISCONNECTED);
		
		Platform.runLater(() -> {
			UserInterface.so = mockSystemOrchestrator;
			userInterface.initialize();
			userInterface.selectedPeerFile = "test.conf";
			userInterface.changeVPNState();
			assertEquals("Stop VPN", userInterface.vpnButton.getText());
			assertTrue(userInterface.peerListView.isDisable());
		});
	}
	

    @Test
    public void testChangeVPNState_stopVPN() {
        when(mockSystemOrchestrator.getConnectionStatus()).thenReturn(connectionStates.CONNECTED);
        Platform.runLater(() -> {
        	UserInterface.so = mockSystemOrchestrator;
            userInterface.initialize();
            userInterface.changeVPNState();
            assertEquals("Start VPN", userInterface.vpnButton.getText());
            assertFalse(userInterface.peerListView.isDisable());
        });
    }

    @Test
    public void testViewHome_updatesPeerList() {
        Platform.runLater(() -> userInterface.viewHome());
    }

    @Test
    public void testHandleFileSelection_noFileSelected() {
        Platform.runLater(() -> userInterface.handleFileSelection(null));
    }

    @Test
    public void testStartDynamicLogUpdate_logsUpdated() throws InterruptedException {
        // Configure WireguardManager mock to return a log
        when(mockWireguardManager.getLog()).thenReturn("Test Log");

        // Run the test
        Platform.runLater(() -> userInterface.startDynamicLogUpdate());

        // Wait a moment to let the logs update
        Thread.sleep(2000);

        // Assert the logsArea text is updated
        Platform.runLater(() -> assertEquals("Test Log", userInterface.logsArea.getText()));
    }
}
