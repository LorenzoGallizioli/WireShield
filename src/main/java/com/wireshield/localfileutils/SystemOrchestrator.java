package com.wireshield.localfileutils;

import com.wireshield.av.AntivirusManager;
import com.wireshield.wireguard.WireguardManager;
import com.wireshield.enums.runningStates;
import com.wireshield.enums.connectionStates;
import com.wireshield.enums.vpnOperations;

/**
 * The SystemOrchestrator class is responsible for orchestrating the system.
 */
public class SystemOrchestrator {
    private WireguardManager wireguardManager;
    private DownloadManager downloadManager;
    private AntivirusManager antivirusManager;
    private runningStates avStatus;
    private runningStates monitorStatus;
    private connectionStates connectionStatus;

    /**
     * The constructor for the SystemOrchestrator class.
     */
    public SystemOrchestrator() {}

    /**
     * Method to manage the VPN connection.
     * 
     * @param operation
     *   The operation to be performed.
     */
    public void manageVPN(vpnOperations operation) {
        String wgPath = "C:\\Program Files\\WireGuard\\wireguard.exe";
        String configPath = "C:\\Program Files\\WireGuard\\Data\\Configurations\\peer5_galliz.conf.dpapi";
        wireguardManager = new WireguardManager(wgPath);
        switch (operation) {
            case START:
                if (wireguardManager.setInterfaceUp(configPath)) {
                    System.out.println("[INFO] Interfaccia avviata con successo.");
                } else {
                    System.err.println("[ERR] Errore nell'avvio dell'interfaccia.");
                }
            break;
        
            case STOP:
                if (wireguardManager.setInterfaceDown()) {
                    System.out.println("[INFO] Interfaccia arrestata con successo.");
                } else {
                    System.err.println("[ERR] Errore nell'arresto dell'interfaccia.");
                }
                break;
            
            default:
                System.err.println("[WARN] Operazione non supportata: " + operation);
            break;
        }
    
    }

    
    /**
     * Method to manage the antivirus.
     * 
     * @param status
     *   The antivirus status.
     */
    public void manageAV(runningStates status) {}

    /**
     * Returns the connection status.
     * 
     * @return connectionStates
     *   The connection status.
     */
    public connectionStates getConnectionStatus() {
        return connectionStatus;
    }

    /**
     * Returns the monitor status.
     * 
     * @return runningStates
     *   The monitor status. 
     */
    public runningStates getMonitorStatus() {
        return monitorStatus;
    }

    /**
     * Returns the antivirus status.
     * 
     * @return runningStates
     *   The antivirus status.
     */
    public runningStates getAVStatus() {
        return avStatus;
    }

    /**
     * Creates a peer.
     * 
     * @param peer
     *   The peer to be created.
     */
    public void createPeer(String peer){}

    /**
     * Gets the report info.
     * 
     * @param report
     *   The report to be retrieved.
     * @return String
     *   The report info.
     */
    public String getReportInfo (String report){
        return "";
    }
}
