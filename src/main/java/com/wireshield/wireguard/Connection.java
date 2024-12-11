package com.wireshield.wireguard;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import com.wireshield.enums.connectionStates;

public class Connection {
    private connectionStates status;
    private long sentTraffic;
    private long receivedTraffic;

    public Connection() {}

    public void updateTraffic(long sentTraffic, long receivedTraffic) {}

    /**
     * Execute the wg show command for retrieving informations about the connection.
     * 
     * @param param
     *   [public-key | private-key | listen-port | fwmark | peers | preshared-keys | endpoints | allowed-ips | latest-handshakes | transfer | persistent-keepalive | dump]
     * @return
     */
    private String wgShow(String param) {
        String activeInterface = this.getActiveInterface();
        try {
        ProcessBuilder processBuilder = new ProcessBuilder("wg", "show", activeInterface, param);
        Process process = processBuilder.start();

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
     * Sets the connection status.
     * 
     * @param status
     *   The status.
     */
    public void setStatus(connectionStates status) {
        this.status = status;
    }

    /**
     * Retrieves the active interface.
     * 
     * @return String|null
     *   The name of the interface or null if not found.
     */
    protected String getActiveInterface() {
        try {
            ProcessBuilder processBuilder = new ProcessBuilder("wg", "show", "interfaces");
            Process process = processBuilder.start();

            // Read the output of the command
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.isEmpty()) {
                    return line; // Interface is up
                }
            }
            return null; // Interface is down
        } catch (IOException e) {
            System.err.println("[ERR] Error getting active interface: " + e.getMessage());  
            return null;
        }

    }

    /**
     * Retrieves the status of the connection.
     * 
     * @return connectionStates
     *   The status.
     */
    public connectionStates getStatus() {
        return status;
    }

    /**
     * Retrieves the traffic sent.
     * 
     * @return Long
     *   The traffic sent in bytes.
     */
    public Long getSentTraffic() {
        String trafficString = wgShow("transfer");
        sentTraffic = Long.parseLong(trafficString.trim().split("\\s+")[0]);
        return sentTraffic;
    }

    /**
     * Retrieves the traffic received.
     * 
     * @return Long
     *   The traffic received in bytes.
     */
    public Long getReceivedTraffic() {
        String trafficString = wgShow("transfer");
        receivedTraffic = Long.parseLong(trafficString.trim().split("\\s+")[1]);
        return receivedTraffic;
    }

    /**
     * Retrieves the last handshake time.
     * 
     * @return Long
     *   The last handshake time.
     */
    public Long getLastHandshakeTime() {
        String latestHandShake = wgShow("latest-handshakes"); 
        return Long.parseLong(latestHandShake);
    }


    /**
     * Describes the connection.
     */
    @Override
    public String toString() {
        return String.format(
            "[INFO] Interface: %s\n[INFO] Status: %s\n[INFO] Last handshake time: %s\n[INFO] Received traffic: %s\n[INFO] Sent traffic: %s",
            this.getActiveInterface(),
            this.getStatus(),
            this.getLastHandshakeTime(),
            this.getReceivedTraffic(),
            this.getSentTraffic());
    }

}
