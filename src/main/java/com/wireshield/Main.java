package com.wireshield;

import com.wireshield.enums.vpnOperations;
import com.wireshield.localfileutils.SystemOrchestrator;

/**
 * Entry point dell'applicazione.
 */
public class Main 
{
    public static void main( String[] args )
    {
        SystemOrchestrator so = new SystemOrchestrator();
        so.manageVPN(vpnOperations.START);
    }
}
