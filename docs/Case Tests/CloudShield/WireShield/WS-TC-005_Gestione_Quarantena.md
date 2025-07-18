## General Information

| Field     | Value                                                    |
|-----------|----------------------------------------------------------|
| Project   | WireShield – VPN Client with Integrated Antivirus        |
| Version   | 1.0                                                      |
| Author    | Davide Bonsembiante                                      |
| Date      | 15-04-2025                                               |

&nbsp;

## Test Case ID: [WS-TC-005]  
### Title: Quarantine Management for Infected and Clean Files

**Test Category:**  
Quarantine and Suspicious File Management

**Priority:**  
High

&nbsp;

## Objective  
Verify that infected files are correctly moved to quarantine and cannot be executed, while clean files are restored from quarantine and can be executed.

&nbsp;

## Pre-conditions

- WireShield is correctly installed and configured  
- ClamAV is installed and active  
- The antivirus service (`AntivirusManager`) and file monitoring service (`DownloadManager`) are running  
- The test files are:
  1. **Infected file:** `eicar.com` (EICAR antivirus test file)
  2. **Clean file:** `file-example_PDF_1MB.pdf` (simulated safe PDF file)

&nbsp;

## Test Environment

- Operating System: Windows 10  
- Java Version: OpenJDK 23  
- ClamAV Version: 1.4.2  
- Dependencies: JavaFX, ClamAV CLI, active local logger

&nbsp;

## Test Data

- **Infected file:** `eicar.com` (an EICAR file, used to test antivirus)
- **Clean file:** `file-example_PDF_1MB.pdf` (a simulated safe PDF file)
- Source: A download folder (e.g., `C:\Users\<username>\Downloads\`)
- Quarantine folder: `.QUARANTINE`

&nbsp;

## Execution Steps

1. Start WireShield and activate the VPN with the provided peer.

2. Simulate the download of the infected file (`eicar.com`).

3. Verify that the infected file (`eicar.com`) is detected.

4. Automatically move the infected file to the quarantine folder `.QUARANTINE`.
    - The infected file should be named something like `eicar.com.<timestamp>.blocked`.

5. Simulate the download of the clean file (`file-example_PDF_1MB.pdf`).

6. Verify that the clean file (`file-example_PDF_1MB.pdf`) is detected.

7. Automatically move the clean file to the quarantine folder `.QUARANTINE`.
    - The clean file should be named something like `file-example_PDF_1MB.pdf.<timestamp>.blocked`.

9. During the scan:
    - The infected file (`eicar.com`) should remain in quarantine, and the GUI should display the options:
        1. Restore
        2. Delete
    - The clean file (`file-example_PDF_1MB.pdf`) should be restored from quarantine and returned to its original path, removing the `.blocked` extension.

&nbsp;

## Expected Results

- The **infected file** (`eicar.com`) is detected and moved to quarantine with its original name and the `.blocked` extension.
- The **clean file** (`file-example_PDF_1MB.pdf`) is also moved to quarantine with its original name and the `.blocked` extension.
- During the scan:
    - The **infected file** remains in quarantine, and the GUI should display the options:
        1. Restore
        2. Delete
    - The **clean file** is restored to its original path, removing the `.blocked` extension.

&nbsp;

## Actual Results

During the test execution, the following steps were successfully performed:

1. **Clean File (file-example_PDF_1MB.pdf):**
   - The **clean file** was correctly downloaded and moved to the `.QUARANTINE` folder.
   - When the file was moved to quarantine, it retained the `.blocked` extension to indicate it had been quarantined.
   - Metadata associated with the file was created to track important information such as the file's status (clean, infected, quarantine) and the original file path.
   - After antivirus analysis, being detected as a safe file, the file was immediately restored to its original path without the `.blocked` extension.

2. **Infected File (eicar.com):**
   - The **eicar.com file** was downloaded and immediately detected as infected by the antivirus system.
   - When the file was quarantined, it retained the `.blocked` extension, and associated metadata was generated to track its status (infected) and the original file path.
   - In the **GUI**, options to restore or delete appeared.
   - Initially, I chose to restore the file, and the file was restored to its original path without the `.blocked` extension.
   - Subsequently, after downloading the same file `eicar.com` again, the system once again detected it as an infected file.
   - The file was again moved to quarantine, retaining the `.blocked` extension, and the associated metadata updated the file's status as **infected**.
   - In this case, the file was finally **deleted** from quarantine, as it was no longer necessary to restore it.

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

https://github.com/user-attachments/assets/8cf9795b-a93f-4457-a1a2-f32f2e659a15

