import os
import shutil
import subprocess
import zipfile
import sys
import ctypes
import requests
import win32com.client
import gdown
from datetime import datetime, timedelta

def download_from_drive(output_path):
    """Scarica il file ZIP di ClamAV da Google Drive usando gdown"""
    file_id = "1dQHnsNEV7Z2y-UovmTyufPlzlHiGq9yq"
    url = f"https://drive.google.com/uc?export=download&id={file_id}"
    
    print("🔽 Scaricando ClamAV da Google Drive...")
    gdown.download(url, output_path, quiet=False)
    print(f"✅ Download completato: {output_path}")

def extract_clamav(zip_path, extract_to):
    """Estrae il file ZIP"""
    if not os.path.exists(extract_to):
        os.makedirs(extract_to)

    print("📂 Estrazione in corso...")
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)
    print("✅ Estrazione completata.")

def move_clamav_folder(source_folder, destination_folder):
    """Sposta ClamAV in C:\\Program Files"""
    print("🚀 Spostando ClamAV nella cartella di installazione...")

    if not os.path.exists(source_folder):
        print("❌ Errore: la cartella ClamAV non è stata trovata dopo l'estrazione!")
        sys.exit(1)

    if os.path.exists(destination_folder):
        print("⚠️ La cartella di destinazione esiste già. Verrà rimossa prima di spostare ClamAV.")
        shutil.rmtree(destination_folder)

    shutil.move(source_folder, destination_folder)
    print("✅ Spostamento completato.")

def update_freshclam():
    """Aggiorna il database ClamAV"""
    print("🔄 Aggiornamento database ClamAV in corso...")
    try:
        subprocess.run([r"C:\\Program Files\\ClamAV\\freshclam"], shell=True, check=True)
        print("✅ Aggiornamento completato.")
    except subprocess.CalledProcessError:
        print("❌ Errore durante l'aggiornamento del database.")
        sys.exit(1)

def schedule_update():
    """Crea un'attività pianificata per eseguire freshclam ogni giorno"""
    print("📅 Creazione attività pianificata per aggiornamento giornaliero...")
    task_name = "ClamAV_Update"
    command = r"C:\\Program Files\\ClamAV\\freshclam"
    
    try:
        scheduler = win32com.client.Dispatch('Schedule.Service')
        scheduler.Connect()
        rootFolder = scheduler.GetFolder("\\")

        # Se esiste già, rimuoverla
        try:
            rootFolder.DeleteTask(task_name, 0)
        except:
            pass

        task_def = scheduler.NewTask(0)
        task_def.RegistrationInfo.Description = "Aggiornamento ClamAV giornaliero"
        task_def.Principal.LogonType = 3  # Esegui solo se l'utente è loggato

        # Creazione del trigger giornaliero
        trigger = task_def.Triggers.Create(2)  # 2 = Trigger giornaliero
        trigger.StartBoundary = (datetime.now() + timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S")
        trigger.DaysInterval = 1  # Esegui ogni giorno

        action = task_def.Actions.Create(0)  # Crea l'azione per il task
        action.Path = command

        # Registra il task
        rootFolder.RegisterTaskDefinition(
            task_name,
            task_def,
            6,  # Se il task esiste, verrà sovrascritto
            None,
            None,
            3   # Esegui il task solo se l'utente è loggato
        )
        print("✅ Attività pianificata creata con successo!")
    except Exception as e:
        print(f"❌ Errore nella creazione della task: {e}")
        sys.exit(1)

def is_admin():
    """Controlla se lo script è eseguito con privilegi di amministratore"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def restart_as_admin():
    """Riavvia lo script con privilegi di amministratore"""
    if not is_admin():
        print("⚠️ Lo script deve essere eseguito come amministratore! Riavvio con privilegi elevati...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)

def main():
    """Flusso principale dello script"""
    restart_as_admin()

    # Percorsi per il download, estrazione e installazione
    download_folder = os.path.join(os.path.expanduser("~"), "Downloads")
    download_path = os.path.join(download_folder, "ClamAV.zip")
    extract_to = os.path.join(download_folder, "ClamAV_Temp")
    install_path = r"C:\Program Files\ClamAV"

    # Scarica e estrai ClamAV
    download_from_drive(download_path)
    extract_clamav(download_path, extract_to)

    # Trova la cartella ClamAV
    source_folder = os.path.join(extract_to, "ClamAV")
    move_clamav_folder(source_folder, install_path)

    # Aggiorna il database di ClamAV
    update_freshclam()

    # Pianifica l'aggiornamento automatico
    schedule_update()

    print("🎉 Installazione completata con successo!")

    # Pulizia dei file temporanei
    os.remove(download_path)
    shutil.rmtree(extract_to)

if __name__ == "__main__":
    main()
