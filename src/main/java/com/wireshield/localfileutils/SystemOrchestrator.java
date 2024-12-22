package com.wireshield.localfileutils;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.wireshield.av.AntivirusManager;
import com.wireshield.av.ClamAV;
import com.wireshield.av.ScanReport;
import com.wireshield.av.VirusTotal;
import com.wireshield.wireguard.PeerManager;
import com.wireshield.wireguard.WireguardManager;
import com.wireshield.enums.runningStates;
import com.wireshield.enums.connectionStates;
import com.wireshield.enums.vpnOperations;

/*
 * Orchestrates various system components, including antivirus, download monitoring, and VPN connections.
 */
public class SystemOrchestrator {

    private static final Logger logger = LogManager.getLogger(SystemOrchestrator.class);

    private WireguardManager wireguardManager; // Manages VPN connections
    private DownloadManager downloadManager;   // Manages download monitoring
    private AntivirusManager antivirusManager; // Manages antivirus operations
    private ClamAV clamAV;
    private VirusTotal virusTotal;

    private runningStates avStatus;            // Antivirus service status
    private runningStates monitorStatus;       // Download monitoring service status
    private connectionStates connectionStatus; // VPN connection status

    /*
     * Initializes the SystemOrchestrator instance with necessary components.
     */
    public SystemOrchestrator() {
        this.antivirusManager = new AntivirusManager();
        this.clamAV = new ClamAV(); // Initialize ClamAV
        this.virusTotal = new VirusTotal(); // Initialize VirusTotal

        this.setDownloadManager(new DownloadManager(antivirusManager));
        antivirusManager.setClamAV(clamAV);
        antivirusManager.setVirusTotal(virusTotal);

        logger.info("SystemOrchestrator initialized.");
    }

    /**
     * Manages the VPN connection.
     * 
     * @param operation The operation to be performed (START or STOP).
     */
    public void manageVPN(vpnOperations operation) {
        String wgPath = "C:\\Program Files\\WireGuard\\wireguard.exe";
        String configPath = "C:\\Users\\loren\\Downloads\\peer5_galliz.conf";

        wireguardManager = new WireguardManager(wgPath);

        switch (operation) {
            case START:
                if (wireguardManager.setInterfaceUp(configPath)) {
                    logger.info("Interface successfully started.");
                } else {
                    logger.error("Error starting the interface.");
                }
                break;

            case STOP:
                if (wireguardManager.setInterfaceDown()) {
                    logger.info("Interface successfully stopped.");
                } else {
                    logger.error("Error stopping the interface.");
                }
                break;

            default:
                logger.error("Unsupported operation: {}", operation);
                break;
        }
    }

    /**
     * Manages the download monitoring service.
     * 
     * @param status The desired state of the download monitoring service (UP or DOWN).
     */
    public void manageDownload(runningStates status) {
        this.monitorStatus = status; // Update download monitoring status
        logger.info("Managing download monitoring service. Desired state: {}", status);

        if (monitorStatus == runningStates.UP) {
            if (downloadManager.getMonitorStatus() != runningStates.UP) {
                logger.info("Starting download monitoring service...");
                try {
                    downloadManager.startMonitoring(); // Start monitoring downloads
                    logger.info("Download monitoring service started successfully.");
                } catch (IOException e) {
                    logger.error("Error starting the download monitoring service: {}", e.getMessage(), e);
                }
            } else {
                logger.info("Download monitoring service is already running.");
            }
        } else {
            if (downloadManager.getMonitorStatus() != runningStates.DOWN) {
                logger.info("Stopping download monitoring service...");
                downloadManager.stopMonitoring(); // Stop monitoring downloads
				logger.info("Download monitoring service stopped successfully.");
            } else {
                logger.info("Download monitoring service is already stopped.");
            }
        }
    }

    /**
     * Manages the antivirus service.
     * 
     * @param status The desired state of the antivirus service (UP or DOWN).
     */
    public void manageAV(runningStates status) {
        this.avStatus = status; // Update antivirus status
        logger.info("Managing antivirus service. Desired state: {}", status);

        if (avStatus == runningStates.UP) {
            if (antivirusManager.getScannerStatus() != runningStates.UP) {
                logger.info("Starting antivirus service...");

                // Starting antivirus scan and providing progress
                try {
                    antivirusManager.startPerformScan(); // Start antivirus scan
                    logger.info("Antivirus service started successfully.");
                } catch (Exception e) {
                    logger.error("Error while starting antivirus service: {}", e.getMessage(), e);
                }
            } else {
                logger.info("Antivirus service is already running.");
            }
        } else {
            if (antivirusManager.getScannerStatus() != runningStates.DOWN) {
                logger.info("Stopping antivirus service...");
                
                // Stopping the scan
                try {
                    antivirusManager.stopPerformScan(); // Stop antivirus scan
                    logger.info("Antivirus service stopped successfully.");
                } catch (Exception e) {
                    logger.error("Error while stopping antivirus service: {}", e.getMessage(), e);
                }
            } else {
                logger.info("Antivirus service is already stopped.");
            }
        }

        // Print final scan reports using printReport() method
        List<ScanReport> finalReports = antivirusManager.getFinalReports();
        if (finalReports.isEmpty()) {
            logger.info("No scan reports available.");
        } else {
            logger.info("Printing final scan reports:");
            for (ScanReport report : finalReports) {
                report.printReport();  // Use printReport method to print the report
            }
        }
    }

    /**
     * Retrieves the current VPN connection status.
     * 
     * @return The current VPN connection status.
     */
    public connectionStates getConnectionStatus() {
        logger.debug("Retrieving connection status: {}", connectionStatus);
        return connectionStatus;
    }

    /**
     * Retrieves the current download monitoring status.
     * 
     * @return The current download monitoring status.
     */
    public runningStates getMonitorStatus() {
        logger.debug("Retrieving monitoring status: {}", monitorStatus);
        return monitorStatus;
    }

    /**
     * Retrieves the current antivirus status.
     * 
     * @return The current antivirus status.
     */
    public runningStates getAVStatus() {
        logger.debug("Retrieving antivirus status: {}", avStatus);
        return avStatus;
    }

    /**
     * Adds a new peer to the VPN configuration.
     * 
     * @param peerData The peer configuration data.
     * @param peerName The name of the peer to be added.
     */
    public void addPeer(String peerData, String peerName) {
        logger.info("Adding new peer with name: {}", peerName);
        Map<String, Map<String, String>> peer = PeerManager.parsePeerConfig(peerName);
        wireguardManager.getPeerManager().createPeer(peer, peerName);
        logger.info("Peer added successfully: {}", peerName);
    }

    /**
     * Retrieves the WireguardManager instance.
     * 
     * @return The WireguardManager instance.
     */
    public WireguardManager getWireguardManager() {
        return wireguardManager;
    }

    /**
     * Retrieves report information based on the report name.
     * 
     * @param report The name or identifier of the report to retrieve.
     * @return The report information.
     */
    public String getReportInfo(String report) {
        logger.info("Retrieving report info for report: {}", report);
        return ""; // Dummy implementation for now
    }

    /**
     * Retrieves the DownloadManager instance.
     * 
     * @return The DownloadManager instance.
     */
    public DownloadManager getDownloadManager() {
        logger.debug("Retrieving DownloadManager instance.");
        return downloadManager;
    }

    /**
     * Sets the DownloadManager instance.
     * 
     * @param downloadManager The DownloadManager instance to set.
     */
    public void setDownloadManager(DownloadManager downloadManager) {
        logger.debug("Setting DownloadManager instance.");
        this.downloadManager = downloadManager;
    }
}
