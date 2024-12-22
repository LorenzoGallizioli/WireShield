package com.wireshield;
import com.wireshield.enums.runningStates;
import com.wireshield.localfileutils.SystemOrchestrator;
import com.wireshield.ui.UserInterface;

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
        UserInterface.main(args);
        so.manageDownload(runningStates.UP);
        so.manageAV(runningStates.UP);
    }
}
