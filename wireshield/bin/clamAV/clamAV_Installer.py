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

    candidates = []

    for link in links:
        href = link["href"]
        match = re.search(r"clamav-(\d+\.\d+\.\d+)\.win\.x64\.zip$", href)
        if match and "production" in href:
            ver = match.group(1)
            full_url = href if href.startswith("http") else f"https://www.clamav.net{href}"
            candidates.append((version.parse(ver), full_url))

    if not candidates:
        print("Could not find any valid ClamAV Windows x64 version.")
        sys.exit(1)

    # Ordina per versione, dalla più recente
    candidates.sort(reverse=True)
    latest_version, latest_url = candidates[0]
    print(f"Latest version found: {latest_version}")
    return latest_url

def download_clamav_zip(output_path):
    latest_url = get_latest_clamav_url()
    print(f"Downloading ClamAV from: {latest_url}")
    response = requests.get(latest_url, stream=True)
    if response.status_code == 200:
        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"Download completed: {output_path}")
    else:
        print("Error downloading ClamAV.")
        sys.exit(1)


def download_config_files(destination_folder):
    if not os.path.exists(destination_folder):
        os.makedirs(destination_folder)

    print("Downloading configuration files...")
    for config_file in CONFIG_FILES:
        url = f"{CONF_BASE_URL}/{config_file}"
        dest_path = os.path.join(destination_folder, config_file)
        response = requests.get(url)
        if response.status_code == 200:
            with open(dest_path, "wb") as f:
                f.write(response.content)
            print(f"{config_file} downloaded.")
        else:
            print(f"Error downloading {config_file}.")
            sys.exit(1)

def extract_clamav(zip_path, extract_to):
    if not os.path.exists(extract_to):
        os.makedirs(extract_to)

    print("Extracting files...")
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)
    print("Extraction completed.")

def find_clamav_extracted_folder(extract_to):
    """Find the extracted ClamAV folder dynamically"""
    for item in os.listdir(extract_to):
        item_path = os.path.join(extract_to, item)
        if os.path.isdir(item_path) and item.startswith("clamav"):
            return item_path
    return None

def move_clamav_folder(source_folder, destination_folder):
    print("Moving ClamAV to the installation folder...")

    if not os.path.exists(source_folder):
        print("Error: ClamAV folder not found after extraction!")
        sys.exit(1)

    if os.path.exists(destination_folder):
        print("The destination folder already exists. It will be removed.")
        shutil.rmtree(destination_folder)

    shutil.move(source_folder, destination_folder)
    print("Move completed.")

def remove_conf_examples_folder(install_folder):
    conf_examples_folder = os.path.join(install_folder, "conf_examples")
    
    if os.path.exists(conf_examples_folder):
        try:
            shutil.rmtree(conf_examples_folder)
            print("The 'conf_examples' folder has been removed.")
        except Exception as e:
            print(f"Error removing the 'conf_examples' folder: {e}")
    else:
        print("The 'conf_examples' folder does not exist.")

def copy_config_files_to_installation(source_folder, destination_folder):
    print("Copying configuration files to the installation folder...")
    for config_file in CONFIG_FILES:
        src = os.path.join(source_folder, config_file)
        dst = os.path.join(destination_folder, config_file)
        try:
            shutil.copy2(src, dst)
            print(f"{config_file} copied to {destination_folder}")
        except Exception as e:
            print(f"Error copying {config_file}: {e}")
            sys.exit(1)

def install_clamav_service():
    """Installs ClamAV as a Windows service"""
    print("Installing ClamAV as a Windows service...")
    clamav_exe = r"C:\Program Files\ClamAV\clamd.exe"
    try:
        subprocess.run([clamav_exe, "--install"], shell=True, check=True)
        print("ClamAV has been installed as a service.")
    except subprocess.CalledProcessError:
        print("Error installing ClamAV as a service.")
        sys.exit(1)

def update_freshclam():
    print("Updating ClamAV database...")
    try:
        subprocess.run([r"C:\\Program Files\\ClamAV\\freshclam"], shell=True, check=True)
        print("Update completed.")
    except subprocess.CalledProcessError:
        print("Error updating the database.")
        sys.exit(1)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def restart_as_admin():
    if not is_admin():
        print("The script needs to be run as administrator! Restarting...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)

def main():
    """Main script flow"""
    restart_as_admin()

    # Paths for download, extraction, and installation
    download_folder = os.path.join(os.path.expanduser("~"), "Downloads")
    download_path = os.path.join(download_folder, "ClamAV.zip")
    extract_to = os.path.join(download_folder, "ClamAV_Temp")
    config_folder = os.path.join(download_folder, "ClamAV_Config")
    install_path = r"C:\Program Files\ClamAV"

    # Download and extract ClamAV
    download_clamav_zip(download_path)
    extract_clamav(download_path, extract_to)

    # Find the extracted ClamAV folder (search for a folder starting with "clamav")
    clamav_extracted_dir = find_clamav_extracted_folder(extract_to)
    if clamav_extracted_dir is None:
        print("ClamAV folder not found!")
        sys.exit(1)

    move_clamav_folder(clamav_extracted_dir, install_path)

    # Remove the 'conf_examples' folder
    remove_conf_examples_folder(install_path)

    # Download and copy configuration files
    download_config_files(config_folder)
    copy_config_files_to_installation(config_folder, install_path)

    # Install ClamAV as a Windows service
    install_clamav_service()

    # Update the ClamAV database
    update_freshclam()

    print("Installation completed successfully!")

    # Clean up temporary files created by the script
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
