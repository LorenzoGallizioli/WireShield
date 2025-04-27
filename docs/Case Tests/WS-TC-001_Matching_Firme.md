## General Information

| Field     | Value                                                     |
|-----------|-----------------------------------------------------------|
| Project   | WireShield – VPN Client with Integrated Antivirus         |
| Version   | 1.0                                                       |
| Author    | Davide Bonsembiante                                       |
| Date      | 15-04-2025                                                |

&nbsp;

## Test Case ID: [WS-TC-001]  
### Title: Detection of a File Containing a Known Viral Signature

**Test Category:**  
Signature-based Detection

**Priority:**  
High

&nbsp;

## Objective  
Verify that ClamAV correctly detects a file with a known viral signature (e.g., EICAR) and that WireShield moves the file to quarantine, generates logs, and notifies the user.

&nbsp;

## Pre-conditions

- WireShield is correctly installed and configured  
- ClamAV is installed and active  
- The antivirus service (`AntivirusManager`) and file monitoring service (`DownloadManager`) are running  
- Test file `eicar.com` is available

&nbsp;

## Test Environment

- Operating System: Windows 10  
- Java Version: OpenJDK 23  
- ClamAV Version: 1.4.2  
- Dependencies: JavaFX, ClamAV CLI, active local logger  

&nbsp;

## Test Data

- File: `eicar.com`  
- Source: [https://www.eicar.org/](https://www.eicar.org/)  
- Content: standard antivirus test string  
- Notes: the file **is not dangerous**, but is only used to test antivirus engines  

&nbsp;

## Execution Steps

1. Start WireShield.  
2. Download a test PDF file.  
3. Wait for WireShield to automatically scan the file.  
4. Verify that the file is moved to the `quarantine/` folder (if detected as infected).  
5. Check the scan result in the **Antivirus** section of the GUI.  
6. Download the test file `eicar.com`.  
7. Wait for the automatic scan.  
8. Verify that the file `eicar.com` is also moved to the `quarantine/` folder.  
9. Check in the GUI that ClamAV detected the file as malicious and prompts the user to delete or restore it.  

&nbsp;

## Expected Results

- The test PDF file is detected as **clean** by ClamAV.  
- The file `eicar.com` is detected as **infected** by ClamAV.  
- The infected file is automatically moved to `quarantine/`.  
- Logs display a message similar to `"Virus detected..."`.  
- The graphical interface prompts the user to either **delete** the file or **restore** it.  

&nbsp;

## Actual Results

- No false positives were detected during the scan of the clean PDF file.  
- The file `eicar.com` was correctly identified as infected by ClamAV.  
- WireShield automatically moved `eicar.com` to the `quarantine/` folder.  
- The **Antivirus** section of the GUI correctly displayed the detection of the threat and prompted the user to choose whether to delete or restore the file.  
- A notification was displayed in the GUI, prompting the user to take action:  
  - **Permanently delete**.  
  - **Restore to the Downloads folder**.  

&nbsp;

## Status

**Passed**

&nbsp;

## Attachments and Collected Metrics

- **Video recording of the test session**, including:  
  - Test execution  
  - Antivirus status and WireShield behavior  
  - Real-time metrics display:  
    - CPU usage  
    - Memory usage  
    - Disk I/O


https://github.com/user-attachments/assets/8948e82d-f18d-461b-b8cb-3e30f1a2177c

