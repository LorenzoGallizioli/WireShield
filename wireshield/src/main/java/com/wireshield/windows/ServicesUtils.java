package com.wireshield.windows;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;

public class ServicesUtils {

    static Logger logger = Logger.getLogger(ServicesUtils.class.getName());

    /**
     * Checks whether a Windows service with the specified name exists.
     *
     * @param serviceName The name of the service to check.
     * @return true if the service exists, false otherwise.
     * @throws Exception if the check process fails.
     */
    public static boolean serviceExists(String serviceName) {
        try {
            ProcessBuilder pb = new ProcessBuilder("sc", "query", serviceName);
            Process process = pb.start();
            process.waitFor();

            String output = new String(process.getInputStream().readAllBytes());
            return output.contains("WIN32_OWN_PROCESS");
        } catch (Exception e) {
            return false;
        }
    }

	/**
     * Attempts to start a Windows service with the specified name.
     *
     * @param serviceName The name of the service to start.
     * @return true if the service was started successfully, false otherwise.
     * @throws Exception if the start process fails.
     */
    public static boolean startService(String serviceName) throws Exception {
        try {
            ProcessBuilder pb = new ProcessBuilder("net", "start", serviceName);
            Process process = pb.start();
            int exitCode = process.waitFor();

            if (exitCode == 0) {
                return true;
            } else {
			    return false;
            }
        } catch (Exception e) {
            return false;
        }
    }

	/**
     * Checks whether a Windows service with the specified name is currently running.
     *
     * @param serviceName The name of the service to check.
     * @return true if the service is running, false otherwise.
     * @throws Exception if the check process fails.
     */
    public static boolean isServiceRunning(String serviceName) {
        try {
            ProcessBuilder pb = new ProcessBuilder("sc", "query", serviceName);
            Process process = pb.start();

            int exitCode = process.waitFor();

            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            String errorOutput = new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);

            if (exitCode != 0 || !errorOutput.trim().isEmpty()) {
                System.err.println("Errore durante l'esecuzione di 'sc query " + serviceName + "':");
                System.err.println("Exit Code: " + exitCode);
                System.err.println("Output Errore: " + errorOutput);
            }

            logger.info("Output di 'sc query " + serviceName + "': " + output);
            return output.contains("RUNNING");
            
        } catch (IOException e) {

            System.err.println("IOException durante l'esecuzione di 'sc query " + serviceName + "': " + e.getMessage());
            return false;

        } catch (InterruptedException e) {

            System.err.println("Interruzione durante l'esecuzione di 'sc query " + serviceName + "': " + e.getMessage());
            Thread.currentThread().interrupt();
            return false;
        }
    }
 
	/**
     * Attempts to stop a Windows service with the specified name.
     *
     * @param serviceName The name of the service to stop.
     * @return true if the service was stopped successfully, false otherwise.
     * @throws Exception if the stop process fails.
     */
    public static boolean stopService(String serviceName) {
        try {
            ProcessBuilder pb = new ProcessBuilder("net", "stop", serviceName);
            Process process = pb.start();
            int exitCode = process.waitFor();

            if (exitCode == 0) {
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
            return false;
        }
    }
}
