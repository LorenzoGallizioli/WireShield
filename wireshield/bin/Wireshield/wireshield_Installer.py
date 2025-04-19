import os
import subprocess
import shutil
import winreg
from pathlib import Path
from git import Repo

# CONFIGURA QUI
GITHUB_REPO_URL = "https://github.com/LorenzoGallizioli/WireShield.git"
REPO_NAME = "wireshield"
MAIN_CLASS_PATH = "wireshield/src/main/java/main.java"  # Percorso relativo
JAVA_EXEC = "java"

def get_desktop_path():
    return os.path.join(Path.home(), "Desktop")

def clone_repo():
    dest_path = os.path.join(get_desktop_path(), REPO_NAME)
    if os.path.exists(dest_path):
        print("[!] La cartella esiste già, la cancello.")
        shutil.rmtree(dest_path)
    print("[*] Clonazione del repository...")
    Repo.clone_from(GITHUB_REPO_URL, dest_path)
    return dest_path

def run_java_as_admin(repo_path):
    main_path = os.path.join(repo_path, MAIN_CLASS_PATH)
    
    # Compila se necessario
    print("[*] Compilazione di main.java...")
    subprocess.run(["javac", main_path], shell=True)

    # Lancia come amministratore (via script .bat con runas)
    run_bat_path = os.path.join(repo_path, "run_admin.bat")
    with open(run_bat_path, "w") as f:
        f.write(f'@echo off\n')
        f.write(f'cd /d "{os.path.dirname(main_path)}"\n')
        f.write(f'start "" java main\n')

    print("[*] Esecuzione come amministratore...")
    subprocess.run(['powershell', '-Command', f'Start-Process "{run_bat_path}" -Verb runAs'])

def add_to_startup(repo_path):
    java_command = f'{JAVA_EXEC} -cp "{repo_path}\\src" main'
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "WireshieldBoot", 0, winreg.REG_SZ, java_command)
    print("[+] Aggiunto alle app di avvio.")

def main():
    repo_path = clone_repo()
    run_java_as_admin(repo_path)
    add_to_startup(repo_path)
    print("[✔] Completato tutto!")

if __name__ == "__main__":
    main()
