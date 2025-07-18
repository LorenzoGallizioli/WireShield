## General Information

| Field     | Value                                                    |
|-----------|----------------------------------------------------------|
| Project   | WireShield – VPN Client with Integrated Antivirus        |
| Version   | 1.0                                                      |
| Author    | Davide Bonsembiante                                      |
| Date      | 15-04-2025                                               |

&nbsp;

## Test Case ID: [WS-TC-002] 
### Title: Heuristic Detection of Modified Malware

**Test Category:**  
Heuristic Analysis

**Priority:**  
High

&nbsp;

## Objective  
Verify that WireShield can detect modified malware variants through heuristic analysis, even when the exact signature is not present in the ClamAV database.

&nbsp;

## Pre-conditions

- WireShield is correctly installed and configured  
- ClamAV is installed and active  
- The antivirus service (`AntivirusManager`) and file monitoring service (`DownloadManager`) are running  
- The file `eicar.txt` is available  

&nbsp;

## Test Environment

- Operating System: Windows 10  
- Java Version: OpenJDK 23  
- ClamAV Version: 1.4.2  
- Dependencies: JavaFX, ClamAV CLI, active local logger  

&nbsp;

## Test Data

- File: `eicar.com.txt` (original sample)  
- File: `eicar_modified.txt` (modified version)  
- Modifications made:  
  - Alteration of the standard EICAR string:  
    ```
    X5O!Q%@AP[5\PZX54(P^)7CC)7}$EICAR-TEST-STANDARD-ANTIMALWARE-FILE!$H+H*
    ```

&nbsp;

## Execution Steps

1. Download the file `eicar.txt` (official antivirus test file).  
2. Start WireShield.  
3. Scan the modified file (`eicar.txt`).  
4. Observe the system behavior.  
5. Check if the file is detected as suspicious or malicious.  
6. Create a copy of the file and modify it:  
   - Alter some characters of the standard string without changing the general structure.  
7. Scan the modified file (`eicar.txt`).  
8. Observe the system behavior.  
9. Check if the file is detected as suspicious or malicious.  

&nbsp;

## Expected Results

- The file `eicar_modified.txt` should be detected as potentially malicious through heuristic analysis.  
- The file should be moved to quarantine.  
- The interface should prompt the user to delete or restore the file.  

&nbsp;

## Actual Results

- The file `eicar_modified.txt` was detected as **clean** by ClamAV.  
- No virus detection notification appeared in the user interface.  
- Logs do not contain malware reports for the modified file.  

&nbsp;

## Status

**Failed**

&nbsp;

## Attachments and Collected Metrics

- **Video recording of the test session**, including:  
  - Test execution  
  - Antivirus status and WireShield behavior  
  - Real-time metrics display:  
    - CPU usage  
    - Memory usage  
    - Disk I/O

https://github.com/user-attachments/assets/a3d9f28d-0c1f-485f-b5c6-24ae48fa2b50


&nbsp;

## Note  
To achieve effective heuristic analysis, it may be necessary to:  
- Use more sophisticated samples or deeper alterations.  
- Configure ClamAV to enable a more advanced heuristic scanning level.  
