package com.wireshield.av;

import java.io.File;

/*
 * The AVInterface interface is responsible for scanning files using antivirus software.
 */
public interface AVInterface {

    /**
     * Performs a scan of a file using antivirus software.
     * 
     * @param file
     *   The file to scan.
     * @param report
     *   The scan report.
     */
    public abstract void analyze(File file, ScanReport report);
}
