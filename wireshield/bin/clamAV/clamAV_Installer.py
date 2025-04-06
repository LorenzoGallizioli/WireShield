import os
import shutil
import subprocess
import zipfile
import sys
import ctypes
import requests
import win32com.client
from datetime import datetime, timedelta

CLAMAV_URL = "https://www.clamav.net/downloads/production/clamav-1.4.2.win.x64.zip"
CONF_BASE_URL = "https://raw.githubusercontent.com/LorenzoGallizioli/WireShield/110-gestione-automatica-degli-aggiornamenti-del-database-clamav-allavvio/wireshield/bin/clamAV/conf"
CONFIG_FILES = ["clamd.conf", "freshclam.conf"]

def download_clamav_zip(output_path):
    print("🔽 Scaricando ClamAV dal sito ufficiale...")
    response = requests.get(CLAMAV_URL, stream=True)
    if response.status_code == 200:
        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"✅ Download completato: {output_path}")
    else:
        print("❌ Errore durante il download di ClamAV.")
        sys.exit(1)

def download_config_files(destination_folder):
    if not os.path.exists(destination_folder):
        os.makedirs(destination_folder)

    print("⚙️ Scaricamento dei file di configurazione...")
    for config_file in CONFIG_FILES:
        url = f"{CONF_BASE_URL}/{config_file}"
        dest_path = os.path.join(destination_folder, config_file)
        response = requests.get(url)
        if response.status_code == 200:
            with open(dest_path, "wb") as f:
                f.write(response.content)
            print(f"✅ {config_file} scaricato.")
        else:
            print(f"❌ Errore durante il download di {config_file}.")
            sys.exit(1)

def extract_clamav(zip_path, extract_to):
    if not os.path.exists(extract_to):
        os.makedirs(extract_to)

    print("📂 Estrazione in corso...")
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)
    print("✅ Estrazione completata.")

def find_clamav_extracted_folder(extract_to):
    """Trova la cartella clamav estratta dinamicamente"""
    for item in os.listdir(extract_to):
        item_path = os.path.join(extract_to, item)
        if os.path.isdir(item_path) and item.startswith("clamav"):
            return item_path
    return None

def move_clamav_folder(source_folder, destination_folder):
    print("🚀 Spostando ClamAV nella cartella di installazione...")

    if not os.path.exists(source_folder):
        print("❌ Errore: la cartella ClamAV non è stata trovata dopo l'estrazione!")
        sys.exit(1)

    if os.path.exists(destination_folder):
        print("⚠️ La cartella di destinazione esiste già. Verrà rimossa.")
        shutil.rmtree(destination_folder)

    shutil.move(source_folder, destination_folder)
    print("✅ Spostamento completato.")

def remove_conf_examples_folder(install_folder):
    conf_examples_folder = os.path.join(install_folder, "conf_examples")
    
    if os.path.exists(conf_examples_folder):
        try:
            shutil.rmtree(conf_examples_folder)
            print("✅ Cartella 'conf_examples' rimossa.")
        except Exception as e:
            print(f"❌ Errore durante la rimozione della cartella 'conf_examples': {e}")
    else:
        print("⚠️ La cartella 'conf_examples' non esiste.")

def copy_config_files_to_installation(source_folder, destination_folder):
    print("📝 Copia dei file di configurazione nella cartella di installazione...")
    for config_file in CONFIG_FILES:
        src = os.path.join(source_folder, config_file)
        dst = os.path.join(destination_folder, config_file)
        try:
            shutil.copy2(src, dst)
            print(f"✅ {config_file} copiato in {destination_folder}")
        except Exception as e:
            print(f"❌ Errore durante la copia di {config_file}: {e}")
            sys.exit(1)

def install_clamav_service():
    """Installa ClamAV come servizio Windows"""
    print("🔧 Installazione di ClamAV come servizio Windows...")
    clamav_exe = r"C:\Program Files\ClamAV\clamd.exe"
    try:
        subprocess.run([clamav_exe, "--install"], shell=True, check=True)
        print("✅ ClamAV è stato installato come servizio.")
    except subprocess.CalledProcessError:
        print("❌ Errore durante l'installazione di ClamAV come servizio.")
        sys.exit(1)

def update_freshclam():
    print("🔄 Aggiornamento database ClamAV in corso...")
    try:
        subprocess.run([r"C:\\Program Files\\ClamAV\\freshclam"], shell=True, check=True)
        print("✅ Aggiornamento completato.")
    except subprocess.CalledProcessError:
        print("❌ Errore durante l'aggiornamento del database.")
        sys.exit(1)

def schedule_update():
    print("📅 Creazione attività pianificata per aggiornamento giornaliero...")
    task_name = "ClamAV_Update"
    command = r"C:\\Program Files\\ClamAV\\freshclam"
    
    try:
        scheduler = win32com.client.Dispatch('Schedule.Service')
        scheduler.Connect()
        rootFolder = scheduler.GetFolder("\\")

        try:
            rootFolder.DeleteTask(task_name, 0)
        except:
            pass

        task_def = scheduler.NewTask(0)
        task_def.RegistrationInfo.Description = "Aggiornamento ClamAV giornaliero"
        task_def.Principal.LogonType = 3

        trigger = task_def.Triggers.Create(2)
        trigger.StartBoundary = (datetime.now() + timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S")
        trigger.DaysInterval = 1

        action = task_def.Actions.Create(0)
        action.Path = command

        rootFolder.RegisterTaskDefinition(
            task_name,
            task_def,
            6,
            None,
            None,
            3
        )
        print("✅ Attività pianificata creata con successo!")
    except Exception as e:
        print(f"❌ Errore nella creazione della task: {e}")
        sys.exit(1)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def restart_as_admin():
    if not is_admin():
        print("⚠️ Lo script deve essere eseguito come amministratore! Riavvio...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)

def main():
    """Flusso principale dello script"""
    restart_as_admin()

    # Percorsi per il download, estrazione e installazione
    download_folder = os.path.join(os.path.expanduser("~"), "Downloads")
    download_path = os.path.join(download_folder, "ClamAV.zip")
    extract_to = os.path.join(download_folder, "ClamAV_Temp")
    config_folder = os.path.join(download_folder, "ClamAV_Config")
    install_path = r"C:\Program Files\ClamAV"

    # Scarica ed estrai ClamAV
    download_clamav_zip(download_path)
    extract_clamav(download_path, extract_to)

    # Trova la cartella ClamAV estratta (cerca una cartella che inizia con "clamav")
    clamav_extracted_dir = find_clamav_extracted_folder(extract_to)
    if clamav_extracted_dir is None:
        print("❌ Cartella ClamAV non trovata!")
        sys.exit(1)

    move_clamav_folder(clamav_extracted_dir, install_path)

    # Rimuove la cartella 'conf_examples'
    remove_conf_examples_folder(install_path)

    # Scarica e copia i file di configurazione
    download_config_files(config_folder)
    copy_config_files_to_installation(config_folder, install_path)

    # Installa ClamAV come servizio Windows
    install_clamav_service()

    # Aggiorna il database di ClamAV
    update_freshclam()

    # Pianifica l’aggiornamento giornaliero
    schedule_update()

    print("🎉 Installazione completata con successo!")

    # Pulizia sicura dei file creati dallo script
    print("🧹 Pulizia dei file temporanei...")
    try:
        if os.path.exists(download_path):
            os.remove(download_path)
            print(f"🗑️ Rimosso {download_path}")
        if os.path.exists(extract_to) and "ClamAV_Temp" in extract_to:
            shutil.rmtree(extract_to)
            print(f"🗑️ Rimossa {extract_to}")
        if os.path.exists(config_folder) and "ClamAV_Config" in config_folder:
            shutil.rmtree(config_folder)
            print(f"🗑️ Rimossa {config_folder}")
    except Exception as e:
        print(f"⚠️ Errore durante la pulizia: {e}")

if __name__ == "__main__":
    main()