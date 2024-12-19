package com.wireshield;

import com.wireshield.enums.runningStates;
import com.wireshield.localfileutils.SystemOrchestrator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/*
 * Entry point for the WireShield application.
 */
public class Main {
    /**
     * Main method to launch the WireShield application.
     * 
     * @param args Command line arguments (not used).
     */
    public static void main(String[] args) {
        SystemOrchestrator so = new SystemOrchestrator();
        so.manageDownload(runningStates.UP);
        so.manageAV(runningStates.UP);
    }
}
