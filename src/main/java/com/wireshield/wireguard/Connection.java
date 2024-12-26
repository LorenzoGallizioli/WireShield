package com.wireshield.wireguard;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.parser.ParseException;

import com.wireshield.av.FileManager;
import com.wireshield.enums.connectionStates;

/**
 * The Connection class represents a WireGuard connection.
 */
public class Connection {
    private static final Logger logger = LogManager.getLogger(Connection.class);

    private static Connection instance;
    private connectionStates status;
    private long sentTraffic;
    private long receivedTraffic;
    private long lastHandshakeTime;
    private String wgPath;

    private Connection() throws IOException, ParseException {
    	this.wgPath = FileManager.getProjectFolder() + FileManager.getConfigValue("WGEXE_STD_PATH");
    }
    
    /**
     * Public method to get the Singleton instance.
     * 
     * @return the single instance of Connection.
     * @throws ParseException 
     * @throws IOException 
     */
    public static synchronized Connection getInstance() throws IOException, ParseException {
        if (instance == null) {
            instance = new Connection();
        }
        return instance;
    }

    /**
     * Updates the traffic of the connection.
     * 
     * @param sentTraffic
     *   The traffic sent in bytes.
     * @param receivedTraffic
     *   The traffic received in bytes.
     */
    public void updateTraffic(long sentTraffic, long receivedTraffic) {
        while (true) {
            sentTraffic = this.getSentTraffic();
            receivedTraffic = this.getReceivedTraffic();
        }
    }

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
        ProcessBuilder processBuilder = new ProcessBuilder(wgPath, "show", activeInterface, param);
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
            ProcessBuilder processBuilder = new ProcessBuilder(wgPath, "show", "interfaces");
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
            logger.error("Error getting active interface: " + e.getMessage());  
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
        lastHandshakeTime = Long.parseLong(latestHandShake);
        return lastHandshakeTime;
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
