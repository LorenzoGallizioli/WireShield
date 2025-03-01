package com.wireshield.ui;

import java.time.Duration;

/**
 * Utility class for formatting time values
 */
public class TimeUtil {

	/**
     * Calculates and formats the time elapsed since the last handshake
     * 
     * @param lastHandshakeTimestamp The timestamp of the last handshake in milliseconds
     * @return A formatted string representing time elapsed since last handshake
     */
    public static String getTimeSinceHandshake(long lastHandshakeTimestamp) {
        if (lastHandshakeTimestamp <= 0) {
            return "--";
        }
        
        lastHandshakeTimestamp = lastHandshakeTimestamp * 1000;
        
        // Calculate time elapsed since the handshake in seconds
        long currentTime = System.currentTimeMillis();
        long elapsedTotalSeconds = (currentTime - lastHandshakeTimestamp) / 1000;
        
        // Handle case if the time is negative (could happen if system clock changed)
        if (elapsedTotalSeconds < 0) {
            return "Time error";
        }
        
        // Calculate each time component
        long days = elapsedTotalSeconds / (24 * 3600);
        elapsedTotalSeconds %= (24 * 3600);
        
        long hours = elapsedTotalSeconds / 3600;
        elapsedTotalSeconds %= 3600;
        
        long minutes = elapsedTotalSeconds / 60;
        long seconds = elapsedTotalSeconds % 60;
        
        // Format the output based on the elapsed time
        if (days > 0) {
            return String.format("%d days %02d:%02d:%02d ago", days, hours, minutes, seconds);
        } else if (hours > 0) {
            return String.format("%02d:%02d:%02d ago", hours, minutes, seconds);
        } else if (minutes > 0) {
            return String.format("%02d:%02d ago", minutes, seconds);
        } else {
            return String.format("%d seconds ago", seconds);
        }
    }
}
