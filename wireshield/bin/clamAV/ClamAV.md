# Scarica e Installa ClamAV per WireShield

Benvenuto! Questa guida ti permette di scaricare rapidamente, configurare e automatizzare l'uso di ClamAV per il corretto funzionamento di WireShield su Windows.

---

## 📂 Download del File Eseguibile

Clicca sul link qui sotto per scaricare il file eseguibile ClamAV pronto per l'uso:

👉 [Scarica ClamAV per WireShield](https://github.com/LorenzoGallizioli/WireShield/blob/main/wireshield/bin/clamAV/clamAV_Installer.exe)

---

## 🛠️ Istruzioni per l'Installazione

1. **Scarica il file**  
   Scarica il file `.exe` direttamente sul tuo computer.

2. **Esegui il file**  
   Fai doppio clic sul file `.exe` per avviare l’installazione.  
   Il programma:
   - Scarica automaticamente l'ultima versione stabile di ClamAV dal sito ufficiale.
   - Estrae i file e li installa in `C:\Program Files\ClamAV`.
   - Scarica e applica la configurazione predefinita di WireShield.
   - Installa ClamAV come servizio Windows.
   - Aggiorna subito il database antivirus.

3. **Permessi di amministratore**  
   Verrà richiesto di eseguire il programma con privilegi amministrativi. È fondamentale per completare correttamente l’installazione.

---

## 🔄 Aggiornamento Automatico delle Firme Antivirus

WireShield è progettato per avviarsi automaticamente all'accensione del computer. Durante l'avvio, **WireShield esegue automaticamente il comando `freshclam`**, che aggiorna il database delle firme antivirus.

🛡️ **In sintesi:**
- Nessuna pianificazione manuale necessaria.
- Il database si aggiorna **automaticamente ad ogni avvio del sistema operativo**.
- ClamAV sarà sempre aggiornato per proteggerti dalle minacce più recenti.

---

## ✅ Configurazione Completa

Dopo aver eseguito il file `.exe`, ClamAV sarà correttamente installato, aggiornato e pronto per funzionare con WireShield. Non serve alcuna configurazione aggiuntiva.

---

## 🧹 Pulizia Automatica

Al termine dell’installazione, il programma elimina automaticamente tutti i file temporanei utilizzati durante il processo.

---

## ⚠️ Requisiti di Amministratore

Ricorda che il programma richiede **privilegi di amministratore** per completare l'installazione correttamente. Assicurati di eseguire il file `.exe` come amministratore se richiesto.

## 💬 Assistenza

Se hai bisogno di ulteriore assistenza o se qualcosa non funziona come previsto, non esitare a contattarci. Saremo felici di aiutarti! 😊

---

**🛡️ Team WireShield**
