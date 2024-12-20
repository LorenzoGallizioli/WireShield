package com.wireshield;

import com.wireshield.ui.UserInterface;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
/**
 * Entry point dell'applicazione.
 */
public class Main 
{
    private static final Logger logger = LogManager.getLogger(Main.class);
    
    public static void main( String[] args )
    {
    	UserInterface.main(args);
        logger.info("Hello World!");
    }
}
