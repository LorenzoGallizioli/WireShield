## General Information

| Field     | Value                                                    |
|-----------|----------------------------------------------------------|
| Project   | WireShield – VPN Client with Integrated Antivirus        |
| Version   | 1.0                                                      |
| Author    | Davide Bonsembiante                                      |
| Date      | 15-04-2025                                               |

&nbsp;

## Test Case ID: [WS-TC-004]  
### Title: Performance and Scan Timing with ClamAV

**Test Category:**  
Performance and Timing

**Priority:**  
High

&nbsp;

## Objective  
Measure the time required to scan various files of different sizes and complexities using ClamAV, and verify that the system's performance remains adequate under load.

&nbsp;

## Pre-conditions

- WireShield is correctly installed and configured  
- ClamAV is installed and active  
- The antivirus service (`AntivirusManager`) and file monitoring service (`DownloadManager`) are running  
- System with sufficient resources (CPU and memory) to test performance

&nbsp;

## Test Environment

- Operating System: Windows 10  
- Java Version: OpenJDK 23  
- ClamAV Version: 1.4.2  
- Dependencies: JavaFX, ClamAV CLI, active local logger

&nbsp;

## Test Data

- Mixed dataset of files:
  - Small files (10 MB)
  - Medium files (50 MB)
  - Large files (200 MB)

&nbsp;

## Execution Steps

1. **Prepare the test files**:
    - Small file (e.g., `10MB-TESTFILE.ORG.pdf` of 10 MB)
    - Medium file (e.g., `50MB-TESTFILE.ORG.pdf` of 50 MB)
    - Large file (e.g., `200MB-TESTFILE.ORG.pdf` of 200 MB)
  
2. **Start the scanning process**:
    - Scan the **small file** and record the scan time.
    - Scan the **medium file** and record the scan time.
    - Scan the **large file** and record the scan time.

3. **Repeat the scan** for each of the files listed above to verify consistency in results.

4. **Monitor system resources**:
    - Check CPU and memory usage during scans.
    - Ensure the system does not crash or slow down significantly during scans of large files.

5. **Evaluate performance**:
    - Monitor resource usage for each scan and verify that the system maintains adequate performance even during scans of large files.

&nbsp;

## Expected Results

- Scan times should be acceptable and consistent, based on file size (e.g., larger files should take more time, but without excessive slowdowns).
- There should be no system crashes during scans.
- The system should not consume excessive CPU/memory resources, causing issues with parallel work.

&nbsp;

## Actual Results

During the test execution, various key aspects of the system and behavior during file scans were monitored, as highlighted in the attached video. The results obtained are as follows:

1. **File Quarantine**:
    - The infected file was detected and correctly moved to the `.QUARANTINE` folder, regardless of file size.
    - The movement of files, including large ones (up to 200 MB), was completed quickly and without noticeable slowdowns, ensuring a smooth user experience.
    - The system retained the `.blocked` extension as expected to indicate the file was quarantined.

2. **File Scanning**:
    - The antivirus scan completed the analysis of each file without slowdowns or interruptions, even for large files.
    - Large files, such as the 200 MB file, were analyzed quickly, with no loss of system performance. The scan was completed in acceptable times, with the system maintaining optimal performance throughout the process.
    - During the scanning process, the system demonstrated excellent resource management, with no PC slowdowns or crashes, even under the load of large files.

3. **Clean File Restoration**:
    - The clean file was successfully restored from quarantine, removing the `.blocked` extension and returning the file to its original path without any issues.
    - Even large files were restored quickly and without errors, confirming that the system can handle files of various sizes without compromising performance.
    - The clean file was verified and found to be fully executable, without damage, confirming proper file handling throughout the process.

4. **Resource Usage**:
    - CPU and memory usage during the scan was monitored, and no usage spikes were detected that could compromise system stability.
    - The system correctly handled small and large files without evident impacts on overall performance.

5. **General Behavior**:
    - No system crashes were detected during the test execution.
    - The infected file's handling, its movement to quarantine, and analysis were quick and error-free.
    - No issues were encountered during file analysis or clean file restoration.

&nbsp;

## Status

[Passed]

&nbsp;

## Attachments and Collected Metrics

- **Video recording of the test session**, including:
  - Test execution
  - Antivirus status and WireShield behavior
  - Real-time metrics display:
    - CPU usage
    - Memory usage
    - Disk I/O


https://github.com/user-attachments/assets/fa185560-66d4-4225-9055-00d7c2c2caed


&nbsp;

## Notes

- It is noted that the connection used during the test is a **Wi-Fi** connection, which is more unstable compared to a wired **Ethernet** connection. Additionally, the connection is **VDSL**, and the cabinet is located at a distance of **1190 meters**, which may contribute to some slowness in network operations and scan times.
