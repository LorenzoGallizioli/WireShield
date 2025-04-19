import os
import sys
import urllib.request
import zipfile
import subprocess
import shutil
import ctypes
import time

# Funzione per verificare i privilegi di amministratore
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Funzione per scaricare e estrarre lo ZIP del repository
def download_and_extract_zip():
    print("📥 Scaricamento del progetto...")
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    zip_url = "https://github.com/LorenzoGallizioli/WireShield/archive/refs/heads/main.zip"
    zip_path = os.path.join(desktop_path, "WireShield.zip")
    extract_to = os.path.join(desktop_path, "WireShield")

    # Crea la directory se non esiste
    if not os.path.exists(extract_to):
        os.makedirs(extract_to)

    # Scarica il repository come ZIP
    urllib.request.urlretrieve(zip_url, zip_path)

    print("📦 Estrazione del progetto...")
    # Estrai il contenuto dello ZIP
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)

    # Rimuovi il file ZIP dopo l'estrazione
    os.remove(zip_path)

    return extract_to

# Funzione per scaricare JDK e JavaFX
def download_jdk_and_javafx():
    print("📥 Scaricamento JDK e JavaFX...")

    # Percorso di salvataggio di JDK e JavaFX
    jdk_url = "https://download.oracle.com/java/24/latest/jdk-24_windows-x64_bin.msi"
    javafx_url = "https://download2.gluonhq.com/openjfx/24.0.1/openjfx-24.0.1_windows-x64_bin-sdk.zip"
    log4j_url = "https://downloads.apache.org/logging/log4j/2.24.3/apache-log4j-2.24.3-bin.zip"
    json_simple_url = "https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/json-simple/json-simple-1.1.1.jar"
    
    download_folder = os.path.join(extract_to, "JavaSetup")

    if not os.path.exists(download_folder):
        os.makedirs(download_folder)
        
    lib_folder = os.path.join(download_folder, "lib")
    if not os.path.exists(lib_folder):
        os.makedirs(lib_folder)

    # Scarica JDK
    jdk_msi_path = os.path.join(download_folder, "jdk.msi")
    print("📥 Scaricamento JDK...")
    urllib.request.urlretrieve(jdk_url, jdk_msi_path)

    # Scarica JavaFX
    javafx_zip_path = os.path.join(download_folder, "javafx.zip")
    print("📥 Scaricamento JavaFX...")
    urllib.request.urlretrieve(javafx_url, javafx_zip_path)
    
    # Scarica Log4j
    log4j_zip_path = os.path.join(download_folder, "log4j.zip")
    print("📥 Scaricamento Log4j...")
    urllib.request.urlretrieve(log4j_url, log4j_zip_path)
    
    # Scarica JSON Simple
    json_simple_jar_path = os.path.join(lib_folder, "json-simple-1.1.1.jar")
    print("📥 Scaricamento JSON Simple...")
    urllib.request.urlretrieve(json_simple_url, json_simple_jar_path)

    # Installazione di JDK utilizzando il file MSI (installazione silenziosa)
    print("📦 Installazione JDK...")
    subprocess.run(["msiexec", "/i", jdk_msi_path, "/quiet", "/norestart"])
    
    # Attendi che l'installazione sia completata
    print("⏳ Attesa completamento installazione JDK...")
    time.sleep(60)  # Attendi 60 secondi per l'installazione del JDK

    # Estrai JavaFX
    print("📦 Estrazione JavaFX...")
    with zipfile.ZipFile(javafx_zip_path, 'r') as zip_ref:
        zip_ref.extractall(download_folder)
    
    # Estrai Log4j
    print("📦 Estrazione Log4j...")
    with zipfile.ZipFile(log4j_zip_path, 'r') as zip_ref:
        zip_ref.extractall(download_folder)

    # Trova percorsi effettivi di JDK, JavaFX e Log4j
    jdk_path = find_jdk_path()
    javafx_path = find_path_by_prefix(download_folder, "javafx-sdk")
    log4j_path = find_path_by_prefix(download_folder, "apache-log4j")
    
    # Copiamo i JAR necessari nella cartella lib
    if log4j_path:
        # Copia i JAR di Log4j nella cartella lib
        log4j_jars = [os.path.join(log4j_path, f) for f in os.listdir(log4j_path) 
                      if f.endswith(".jar") and not f.startswith("log4j-core-") and not f.startswith("log4j-api-")]
        log4j_api_jar = next((os.path.join(log4j_path, f) for f in os.listdir(log4j_path) 
                              if f.startswith("log4j-api-")), None)
        log4j_core_jar = next((os.path.join(log4j_path, f) for f in os.listdir(log4j_path) 
                               if f.startswith("log4j-core-")), None)
        
        if log4j_api_jar:
            shutil.copy(log4j_api_jar, os.path.join(lib_folder, "log4j-api.jar"))
        if log4j_core_jar:
            shutil.copy(log4j_core_jar, os.path.join(lib_folder, "log4j-core.jar"))
    
    # Salva i percorsi in un file di configurazione
    config_path = os.path.join(download_folder, "java_config.txt")
    with open(config_path, 'w') as f:
        f.write(f"JDK_PATH={jdk_path}\n")
        f.write(f"JAVAFX_PATH={javafx_path}\n")
        f.write(f"LOG4J_PATH={log4j_path}\n")
        f.write(f"LIB_PATH={lib_folder}\n")

    return jdk_path, javafx_path, lib_folder

def find_jdk_path():
    # Percorsi probabili per JDK 24
    possible_paths = [
        "C:\\Program Files\\Java\\jdk-24",
        "C:\\Program Files\\Java\\jdk-24.0.1",
        "C:\\Program Files\\Java\\jdk-24.0.2"
    ]
    
    # Verifica i percorsi più probabili
    for path in possible_paths:
        if os.path.exists(path):
            return path
    
    # Se non trovato, cerca in Program Files\Java
    java_dir = "C:\\Program Files\\Java"
    if os.path.exists(java_dir):
        jdk_folders = [os.path.join(java_dir, d) for d in os.listdir(java_dir) if d.startswith("jdk")]
        if jdk_folders:
            # Ordina per nome in ordine decrescente per prendere la versione più recente
            jdk_folders.sort(reverse=True)
            return jdk_folders[0]
    
    return None

def find_path_by_prefix(folder, prefix):
    for item in os.listdir(folder):
        if item.startswith(prefix):
            return os.path.join(folder, item)
    return None

# Funzione per compilare ed eseguire il programma Java
def compile_and_run_java(extract_to, jdk_path, javafx_path, lib_folder):
    print("🔧 Compilazione ed esecuzione del programma Java...")

    # Percorso della cartella contenente Main.java e delle classi compilate
    src_dir = os.path.join(extract_to, "WireShield-main", "wireshield", "src", "main", "java")
    bin_dir = os.path.join(extract_to, "WireShield-main", "wireshield", "bin")
    
    # Crea la directory bin se non esiste
    if not os.path.exists(bin_dir):
        os.makedirs(bin_dir)

    # Verifica che la cartella src esista
    if not os.path.exists(src_dir):
        print(f"❌ La cartella src non esiste in {src_dir}")
        return False

    # Trova il percorso dei moduli jar di JavaFX
    javafx_lib = os.path.join(javafx_path, "lib")
    
    if not os.path.exists(javafx_lib):
        print(f"❌ Il percorso JavaFX non è valido: {javafx_lib}")
        return False
    
    # Ottieni tutti i file JAR in javafx/lib
    javafx_jars = [os.path.join(javafx_lib, f) for f in os.listdir(javafx_lib) if f.endswith(".jar")]
    
    # Ottieni tutti i file JAR nella cartella lib
    lib_jars = [os.path.join(lib_folder, f) for f in os.listdir(lib_folder) if f.endswith(".jar")]
    
    # Unisci i percorsi JAR per il classpath
    all_jars = javafx_jars + lib_jars
    classpath = os.pathsep.join(all_jars)
    
    # Imposta JAVA_HOME e aggiungi JDK al PATH
    os.environ["JAVA_HOME"] = jdk_path
    os.environ["PATH"] = os.path.join(jdk_path, "bin") + os.pathsep + os.environ["PATH"]
    
    # Trova tutti i file .java nel src_dir
    java_files = []
    for root, dirs, files in os.walk(src_dir):
        for file in files:
            if file.endswith(".java"):
                java_files.append(os.path.join(root, file))
    
    if not java_files:
        print("❌ Nessun file Java trovato nella directory src.")
        return False
    
    # Costruisci il comando di compilazione
    javac_cmd = [
        os.path.join(jdk_path, "bin", "javac"),
        "-d", bin_dir,
        "-cp", classpath + os.pathsep + src_dir,  # Aggiungi src_dir al classpath
        "-encoding", "UTF-8",
        "-Xlint:deprecation"  # Aggiunto per maggiori dettagli sugli errori
    ]
    javac_cmd.extend(java_files)
    
    print("🔨 Compilazione dei file Java...")
    print(f"Classpath: {classpath}")
    try:
        # Mostriamo il comando completo per debugging
        print(f"Esecuzione comando: {' '.join(javac_cmd)}")
        subprocess.run(javac_cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Errore durante la compilazione: {e}")
        return False
    
    # Verifica che ci siano file .class nella cartella bin
    class_found = False
    for root, dirs, files in os.walk(bin_dir):
        if any(f.endswith(".class") for f in files):
            class_found = True
            break
    
    if not class_found:
        print("❌ Nessun file .class generato. La compilazione non ha avuto successo.")
        return False
    
    # Trova il percorso completo della classe Main
    main_class = find_main_class(bin_dir)
    
    if not main_class:
        print("❌ Impossibile trovare la classe Main.")
        print("💡 Controlla manualmente quale sia la classe principale nel progetto.")
        return False
    
    # Costruisci il comando per eseguire Java
    module_path = javafx_lib
    modules = "javafx.controls,javafx.fxml,javafx.graphics"
    
    java_cmd = [
        os.path.join(jdk_path, "bin", "java"),
        "-cp", classpath + os.pathsep + bin_dir,
        "--module-path", module_path,
        "--add-modules", modules,
        main_class
    ]
    
    print(f"🚀 Esecuzione di {main_class}...")
    try:
        print(f"Esecuzione comando: {' '.join(java_cmd)}")
        subprocess.run(java_cmd)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Errore durante l'esecuzione: {e}")
        return False

def find_main_class(bin_dir):
    # Cerca prima esplicitamente com.wireshield.Main
    expected_main_path = os.path.join(bin_dir, "com", "wireshield", "Main.class")
    if os.path.exists(expected_main_path):
        return "com.wireshield.Main"
    
    # Altrimenti, cerca ricorsivamente una classe Main
    for root, dirs, files in os.walk(bin_dir):
        for file in files:
            if file == "Main.class":
                rel_path = os.path.relpath(root, bin_dir)
                if rel_path == ".":
                    return "Main"
                else:
                    return rel_path.replace(os.sep, ".") + ".Main"
    
    # Se non troviamo Main.class, cerchiamo file che contengono "main" nel nome o classi con metodo main
    for root, dirs, files in os.walk(bin_dir):
        for file in files:
            if file.endswith(".class") and ("main" in file.lower() or "launcher" in file.lower() or "app" in file.lower() or "start" in file.lower()):
                rel_path = os.path.relpath(root, bin_dir)
                main_class = file[:-6]  # Rimuovi '.class'
                if rel_path == ".":
                    return main_class
                else:
                    return rel_path.replace(os.sep, ".") + "." + main_class
    
    return None

# Funzione per aggiungere l'app all'avvio automatico di Windows
def add_to_startup(extract_to, jdk_path, javafx_path, lib_folder, main_class):
    print("📌 Aggiunta dell'app all'avvio automatico...")

    startup_folder = os.path.join(os.getenv('APPDATA'), r'Microsoft\Windows\Start Menu\Programs\Startup')
    bin_dir = os.path.join(extract_to, "WireShield-main", "wireshield", "bin")
    
    if not main_class:
        main_class = find_main_class(bin_dir)
    
    if not main_class:
        print("❌ Impossibile trovare la classe Main per l'avvio automatico.")
        return False
        
    # Crea un file batch per l'avvio automatico
    batch_file_path = os.path.join(startup_folder, "WireShield.bat")
    javafx_lib = os.path.join(javafx_path, "lib")
    
    # Crea il classpath con tutti i jar necessari
    javafx_jars = [os.path.join(javafx_lib, f) for f in os.listdir(javafx_lib) if f.endswith(".jar")]
    lib_jars = [os.path.join(lib_folder, f) for f in os.listdir(lib_folder) if f.endswith(".jar")]
    all_jars = javafx_jars + lib_jars + [bin_dir]
    classpath = os.pathsep.join(all_jars)
    
    with open(batch_file_path, 'w') as f:
        f.write('@echo off\n')
        f.write(f'set "JAVA_HOME={jdk_path}"\n')
        f.write(f'set "PATH=%JAVA_HOME%\\bin;%PATH%"\n')
        f.write(f'cd "{os.path.dirname(bin_dir)}"\n')
        f.write(f'"{jdk_path}\\bin\\java" -cp "{classpath}" --module-path "{javafx_lib}" --add-modules javafx.controls,javafx.fxml,javafx.graphics {main_class}\n')

    print("✅ Aggiunto all'avvio automatico.")
    return True

# MAIN
if __name__ == "__main__":
    if not is_admin():
        print("🔒 Richiesto esecuzione come amministratore. Riavvio in corso...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)

    try:
        # Scarica ed estrae il progetto
        extracted_folder = download_and_extract_zip()

        # Configura Java e JavaFX all'interno della cartella WireShield
        jdk_path, javafx_path, lib_folder = download_jdk_and_javafx(extracted_folder)
        
        print(f"✅ JDK installato in: {jdk_path}")
        print(f"✅ JavaFX installato in: {javafx_path}")
        print(f"✅ Librerie aggiuntive installate in: {lib_folder}")

        # Compila ed esegui il programma Java
        main_class = None
        compile_success = compile_and_run_java(extracted_folder, jdk_path, javafx_path, lib_folder)
        
        if compile_success:
            # Trova il nome della classe principale
            bin_dir = os.path.join(extracted_folder, "WireShield-main", "wireshield", "bin")
            main_class = find_main_class(bin_dir)
            
            # Aggiungi l'app all'avvio automatico solo se la compilazione ha avuto successo
            add_to_startup(extracted_folder, jdk_path, javafx_path, lib_folder, main_class)
            print("\n✅ Installazione completata con successo!")
            print("L'app si avvierà automaticamente al prossimo riavvio.")
        else:
            print("\n❌ L'installazione non è stata completata a causa di errori.")
            print("Controlla eventuali problemi nel codice sorgente o nelle dipendenze mancanti.")

    except Exception as e:
        print(f"❌ Errore: {e}")
        import traceback
        traceback.print_exc()

    input("\nPremi INVIO per chiudere...")