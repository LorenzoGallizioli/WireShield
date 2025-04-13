import os
import shutil
import subprocess
import zipfile
import sys
import ctypes
import requests
import re
from packaging import version
from bs4 import BeautifulSoup
import requests
import sys
import win32com.client
from datetime import datetime, timedelta

CLAMAV_DOWNLOAD_PAGE = "https://www.clamav.net/downloads"
CONF_BASE_URL = "https://raw.githubusercontent.com/LorenzoGallizioli/WireShield/110-gestione-automatica-degli-aggiornamenti-del-database-clamav-allavvio/wireshield/bin/clamAV/conf"
CONFIG_FILES = ["clamd.conf", "freshclam.conf"]

def get_latest_clamav_url():
    """
    Fetches the URL of the latest ClamAV for Windows x64 available on the official website.

    Returns:
        str: The URL of the latest ClamAV version.
    """
    print("Fetching latest ClamAV download URL...")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }
    response = requests.get(CLAMAV_DOWNLOAD_PAGE, headers=headers)
    if response.status_code != 200:
        print(f"Failed to access ClamAV downloads page. Status code: {response.status_code}")
        sys.exit(1)

    soup = BeautifulSoup(response.text, "html.parser")
    links = soup.find_all("a", href=True)

    # Find all the links that point to a ClamAV version for Windows x64
    candidates = []

    for link in links:
        href = link["href"]
        match = re.search(r"clamav-(\d+\.\d+\.\d+)\.win\.x64\.zip$", href)
        if match and "production" in href:
            # Extract the version string from the URL
            ver = match.group(1)
            full_url = href if href.startswith("http") else f"https://www.clamav.net{href}"
            candidates.append((version.parse(ver), full_url))

    if not candidates:
        print("Could not find any valid ClamAV Windows x64 version.")
        sys.exit(1)

    # Sort the candidates by version, from the most recent
    candidates.sort(reverse=True)
    latest_version, latest_url = candidates[0]
    print(f"Latest version found: {latest_version}")
    return latest_url

def download_clamav_zip(output_path):
    """
    Downloads the latest ClamAV for Windows x64 from the official website.

    Args:
        output_path (str): The path where the downloaded file will be saved.

    Returns:
        None
    """
    latest_url = get_latest_clamav_url()
    print(f"Downloading ClamAV from: {latest_url}")
    # Use requests to download the file with streaming
    response = requests.get(latest_url, stream=True)
    if response.status_code == 200:
        # Save the file to the specified path
        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"Download completed: {output_path}")
    else:
        print("Error downloading ClamAV.")
        sys.exit(1)


def download_config_files(destination_folder):
    """
    Downloads the configuration files for ClamAV from the remote repository.

    Args:
        destination_folder (str): The folder where the files will be saved.
    """
    if not os.path.exists(destination_folder):
        os.makedirs(destination_folder)

    print("Downloading configuration files...")
    for config_file in CONFIG_FILES:
        # Construct the URL of the file to download
        url = f"{CONF_BASE_URL}/{config_file}"
        # Construct the path of the file where it will be saved
        dest_path = os.path.join(destination_folder, config_file)
        # Download the file
        response = requests.get(url)
        if response.status_code == 200:
            # Save the file to the specified path
            with open(dest_path, "wb") as f:
                f.write(response.content)
            print(f"{config_file} downloaded.")
        else:
            print(f"Error downloading {config_file}.")
            sys.exit(1)

def extract_clamav(zip_path, extract_to):
    """
    Extracts the ClamAV files from the downloaded archive to the specified folder.

    Args:
        zip_path (str): The path of the downloaded ClamAV archive.
        extract_to (str): The folder where the files will be extracted.
    """
    if not os.path.exists(extract_to):
        os.makedirs(extract_to)

    # Extract the files from the archive
    print("Extracting files...")
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)
    print("Extraction completed.")

def find_clamav_extracted_folder(extract_to):
    """
    Searches for the ClamAV extracted folder within the specified directory.

    Args:
        extract_to (str): The directory path where ClamAV was extracted.

    Returns:
        str: The path to the extracted ClamAV folder if found, otherwise None.
    """
    # Iterate over items in the specified directory
    for item in os.listdir(extract_to):
        item_path = os.path.join(extract_to, item)
        # Check if the item is a directory and starts with "clamav"
        if os.path.isdir(item_path) and item.startswith("clamav"):
            return item_path
    # Return None if no suitable folder is found
    return None

def move_clamav_folder(source_folder, destination_folder):
    """
    Moves the ClamAV folder from the extracted location to the specified installation folder.

    Args:
        source_folder (str): The path of the ClamAV folder after extraction.
        destination_folder (str): The path of the installation folder.
    """
    print("Moving ClamAV to the installation folder...")

    # Check if the source folder exists
    if not os.path.exists(source_folder):
        print("Error: ClamAV folder not found after extraction!")
        sys.exit(1)

    # If the destination folder already exists, remove it
    if os.path.exists(destination_folder):
        print("The destination folder already exists. It will be removed.")
        shutil.rmtree(destination_folder)

    # Move the ClamAV folder to the installation folder
    shutil.move(source_folder, destination_folder)
    print("Move completed.")

def remove_conf_examples_folder(install_folder):
    """
    Removes the "conf_examples" folder from the ClamAV installation folder.

    The "conf_examples" folder is not needed for the ClamAV installation, so it can be removed to save space.

    :param install_folder: The path of the ClamAV installation folder.
    :type install_folder: str
    """
    # Construct the path of the "conf_examples" folder
    conf_examples_folder = os.path.join(install_folder, "conf_examples")
    
    # If the "conf_examples" folder exists, remove it
    if os.path.exists(conf_examples_folder):
        try:
            # Remove the folder and all its contents
            shutil.rmtree(conf_examples_folder)
            print("The 'conf_examples' folder has been removed.")
        except Exception as e:
            # Print an error message if something goes wrong
            print(f"Error removing the 'conf_examples' folder: {e}")
    else:
        print("The 'conf_examples' folder does not exist.")

def copy_config_files_to_installation(source_folder, destination_folder):
    """
    Copies the configuration files from the source folder to the installation folder.

    Args:
        source_folder (str): The path of the folder containing the configuration files.
        destination_folder (str): The path of the folder where the files will be copied.
    """

    print("Copying configuration files to the installation folder...")

    # Iterate over the configuration files
    for config_file in CONFIG_FILES:
        # Construct the source and destination paths of the file
        src = os.path.join(source_folder, config_file)
        dst = os.path.join(destination_folder, config_file)

        try:
            # Copy the file from the source to the destination
            shutil.copy2(src, dst)
            print(f"{config_file} copied to {destination_folder}")
        except Exception as e:
            # Print an error message if something goes wrong
            print(f"Error copying {config_file}: {e}")
            sys.exit(1)

def install_clamav_service():
    """
    Installs ClamAV as a Windows service.

    This function attempts to install ClamAV's clamd.exe as a Windows service.
    If the installation fails, the script will terminate with an error message.
    """
    print("Installing ClamAV as a Windows service...")
    # Path to ClamAV executable
    clamav_exe = r"C:\Program Files\ClamAV\clamd.exe"
    
    try:
        # Run the installation command for ClamAV service
        subprocess.run([clamav_exe, "--install"], shell=True, check=True)
        print("ClamAV has been installed as a service.")
    except subprocess.CalledProcessError:
        # Handle errors during service installation
        print("Error installing ClamAV as a service.")
        sys.exit(1)

def update_freshclam():
    """
    Updates ClamAV's virus database using `freshclam`.

    This function attempts to update ClamAV's virus database using `freshclam`.
    If the update fails, the script will terminate with an error message.
    """
    print("Updating ClamAV database...")
    try:
        # Run the update command for ClamAV database
        subprocess.run([r"C:\\Program Files\\ClamAV\\freshclam"], shell=True, check=True)
        print("Update completed.")
    except subprocess.CalledProcessError:
        # Handle errors during database update
        print("Error updating the database.")
        sys.exit(1)

def is_admin():
    """
    Checks if the current user is an administrator.

    Returns:
        bool: True if the user is an administrator, False otherwise.
    """
    try:
        # Call the IsUserAnAdmin function from the shell32 library
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        # If something goes wrong, return False
        return False

def restart_as_admin():
    """
    Checks if the current user is an administrator and restarts the script with elevation if needed.
    """
    if not is_admin():
        # If the user is not an administrator, restart the script with elevation
        print("The script needs to be run as administrator! Restarting...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        # Exit the script after restarting it
        sys.exit(0)

def main():
    """
    Main script flow for installing and configuring ClamAV.
    
    This script performs the following steps:
    1. Checks for administrative privileges and restarts with elevation if necessary.
    2. Downloads the latest ClamAV archive.
    3. Extracts the downloaded archive.
    4. Moves the extracted folder to the installation directory.
    5. Removes unnecessary example configuration files.
    6. Downloads and copies necessary configuration files.
    7. Installs ClamAV as a Windows service.
    8. Updates the ClamAV virus database.
    9. Cleans up temporary files.
    """
    restart_as_admin()

    # Define paths for download, extraction, and installation
    download_folder = os.path.join(os.path.expanduser("~"), "Downloads")
    download_path = os.path.join(download_folder, "ClamAV.zip")
    extract_to = os.path.join(download_folder, "ClamAV_Temp")
    config_folder = os.path.join(download_folder, "ClamAV_Config")
    install_path = r"C:\Program Files\ClamAV"

    # Step 2: Download ClamAV archive
    download_clamav_zip(download_path)

    # Step 3: Extract the downloaded archive
    extract_clamav(download_path, extract_to)

    # Step 4: Find and move the extracted ClamAV folder
    clamav_extracted_dir = find_clamav_extracted_folder(extract_to)
    if clamav_extracted_dir is None:
        print("ClamAV folder not found!")
        sys.exit(1)
    move_clamav_folder(clamav_extracted_dir, install_path)

    # Step 5: Remove 'conf_examples' folder
    remove_conf_examples_folder(install_path)

    # Step 6: Download and copy configuration files
    download_config_files(config_folder)
    copy_config_files_to_installation(config_folder, install_path)

    # Step 7: Install ClamAV as a Windows service
    install_clamav_service()

    # Step 8: Update the ClamAV database
    update_freshclam()

    print("Installation completed successfully!")

    # Step 9: Clean up temporary files
    print("Cleaning up temporary files...")
    try:
        if os.path.exists(download_path):
            os.remove(download_path)
            print(f"Removed {download_path}")
        if os.path.exists(extract_to) and "ClamAV_Temp" in extract_to:
            shutil.rmtree(extract_to)
            print(f"Removed {extract_to}")
        if os.path.exists(config_folder) and "ClamAV_Config" in config_folder:
            shutil.rmtree(config_folder)
            print(f"Removed {config_folder}")
    except Exception as e:
        print(f"Error during cleanup: {e}")

if __name__ == "__main__":
    main()
