import os
import shutil
import subprocess
import zipfile
import sys
import ctypes
import requests
import win32com.client

def download_from_drive(file_id, output_path):
    """Scarica il file ZIP di ClamAV da Google Drive"""
    url = f"https://drive.google.com/uc?export=download&id={file_id}"
    session = requests.Session()
    
    print("🔽 Scaricando ClamAV da Google Drive...")
    
    response = session.get(url, stream=True)
    with open(output_path, "wb") as file:
        for chunk in response.iter_content(1024):
            file.write(chunk)
    
    print("✅ Download completato.")

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
    
    if os.path.exists(destination_folder):
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
    """Crea un'attività pianificata per eseguire freshclam ogni 6 giorni"""
    print("📅 Creazione attività pianificata per aggiornamento...")
    task_name = "ClamAV_Update"
    command = r"C:\Program Files\ClamAV\freshclam"
    
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
        task_def.RegistrationInfo.Description = "Aggiornamento ClamAV ogni 6 giorni"
        task_def.Principal.LogonType = 3
        
        # Creazione del trigger ogni 6 giorni
        trigger = task_def.Triggers.Create(1)
        trigger.StartBoundary = "2024-03-24T12:00:00"
        trigger.DaysInterval = 6
        
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
    """Controlla se lo script è eseguito con privilegi di amministratore"""
    try:
        return os.getuid() == 0
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

def main():
    """Flusso principale dello script"""
    if not is_admin():
        print("⚠️ Lo script deve essere eseguito come amministratore!")
        sys.exit(1)

    file_id = "INSERISCI_ID_FILE_DRIVE"  # Sostituisci con l'ID del file Google Drive
    download_path = "ClamAV.zip"
    extract_to = "ClamAV_Temp"
    install_path = r"C:\Program Files\ClamAV"
    
    download_from_drive(file_id, download_path)
    extract_clamav(download_path, extract_to)
    move_clamav_folder(os.path.join(extract_to, "ClamAV"), install_path)
    update_freshclam()
    schedule_update()
    
    print("🎉 Installazione completata con successo!")
    os.remove(download_path)
    shutil.rmtree(extract_to)

if __name__ == "__main__":
    main()
