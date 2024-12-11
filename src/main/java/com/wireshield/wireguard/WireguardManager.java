package com.wireshield.wireguard;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.IOException;
import com.wireshield.enums.connectionStates;

public class WireguardManager {
    private String wgPath;
    private Connection connection;

    public WireguardManager(String wgPath) {
        connection = new Connection();
        File file = new File(wgPath);
        if (!file.exists() || !file.isFile()) {
            throw new IllegalArgumentException("[ERR] WireGuard executable not found.");
        }
        this.wgPath = wgPath;
    }

    /**
     * Starts the wireguard inteface based on the configuration path.
     * 
     * @param configPath
     *   The configuration file path.
     * 
     * @return True if the interface is correctly up, false overwise.
     */
    public Boolean setInterfaceUp(String configPath) {
        String activeInterface = connection.getActiveInterface();
        if(activeInterface != null) {
            System.err.println("[ERR] WireGuard interface is already up.");
            return false; // Interface is up
        }

        try {
            // Command for wireguard interface start.
            ProcessBuilder processBuilder = new ProcessBuilder(
                wgPath, 
                "/installtunnelservice", 
                configPath
            );
            Process process = processBuilder.start();

            // Reads the output.
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }

            // Checks the exit code of the process.
            int exitCode = process.waitFor();
            if (exitCode == 0) {
                System.out.println("[INFO] WireGuard interface started.");
                connection.setStatus(connectionStates.CONNECTED);
                return true;
            } else {
                System.err.println("[ERR] Error starting WireGuard interface.");
                return false;
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Stops the active wireguard interface.
     * 
     * @return True if the interface has been stopped correctly, false overwise.
     */
    public Boolean setInterfaceDown() {
        String interfaceName = connection.getActiveInterface();
        if(interfaceName == null) {
            System.err.println("[ERR] No active WireGuard interface.");
            return false;
        }

        try {
            // Command for wireguard interface stop.
            ProcessBuilder processBuilder = new ProcessBuilder(
                wgPath, 
                "/uninstalltunnelservice", 
                interfaceName
            );
            Process process = processBuilder.start();

            // Reads the output.
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }

            // Checks the exit code of the process.
            int exitCode = process.waitFor();
            if (exitCode == 0) {
                System.out.println("[INFO] WireGuard interface stopped.");
                connection.setStatus(connectionStates.DISCONNECTED);
                return true;
            } else {
                System.err.println("[ERR] Error stopping WireGuard interface.");
                return false;
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            return false;
        }
    }

    public Connection getConnection() {
        return connection;
    }
}
