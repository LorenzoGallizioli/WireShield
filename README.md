# 🌐 WireShield

**Titolo del Progetto:** Client VPN in Java per connessioni WireGuard con scansione antivirus integrata per una navigazione sicura


# 📖 Indice

1. [🌐 WireShield - Introduzione](#-wireshield---introduzione)  
2. [🧑‍💻 Chi Siamo](#-chi-siamo)  
3. [📝 Descrizione del Progetto](#-descrizione-del-progetto)  
4. [🔑 Funzionalità Principali](#-funzionalità-principali)  
   - [4.1 Connessione VPN con WireGuard](#1-connessione-vpn-con-wireguard)  
   - [4.2 Scansione Antivirus Integrata](#2-scansione-antivirus-integrata)
   - [4.3 Sistema di Quarantena](#3-sistema-di-quarantena)
   - [4.4 Interfaccia Utente (UI)](#4-interfaccia-utente-ui)  
   - [4.5 Logging e Notifiche](#5-logging-e-notifiche)
5. [🚀 Guida all'Installazione](#-guida-allinstallazione)  
   - [5.1 Prerequisiti](#prerequisiti)  
6. [🛠️ Come Usare l'Applicazione](#%EF%B8%8F-come-usare-lapplicazione)  
7. [📚 Riferimenti e Approfondimenti](#-riferimenti-e-approfondimenti)  
8. [📞 Contatti](#-contatti)

&nbsp;
## 📝 Descrizione del Progetto

Il progetto consiste in un'applicazione **client Java** progettata per connettersi a una VPN tramite il protocollo **WireGuard** e integrare un sistema di **scansione antivirus** che analizzi i file scaricati attraverso la rete. 

Con questo strumento, vogliamo offrire una soluzione che combini:

- **Privacy**: Una connessione sicura tramite **WireGuard**, un protocollo di VPN moderno e sicuro.
- **Sicurezza**: Un sistema di scansione antivirus per analizzare i file da malware che possono infettare i sistemi informatici utilizzando **ClamAV**.
- **Open Source**: Una soluzione completamente open-source, liberamente utilizzabile da chiunque.

&nbsp;
## 🔑 Funzionalità Principali

### 1. Connessione VPN con WireGuard
L’applicazione permette la configurazione e la gestione di una connessione VPN attraverso WireGuard. Le funzionalità principali sono:
 <!--  - **Configurazione con chiavi**: l'utente può configurare la connessione tramite chiavi pubbliche e private. -->
   - **Caricamento file di configurazione**: supporto per file `.conf` di WireGuard, che semplifica il setup della connessione.

### 2. Scansione Antivirus Integrata
Per proteggere i file scaricati durante l’utilizzo della VPN, il client offre una scansione antivirus:
   - **Integrazione con ClamAV**: scansione antivirus open-source con ClamAV.
   - **Aggiornamento automatico delle firme virus**: ogni volta che WireShield viene avviato, l'applicazione aggiorna automaticamente le firme virali per garantire la massima protezione.

### 3. Sistema di Quarantena
Per gestire in sicurezza i file potenzialmente pericolosi:
- **Directory di quarantena protetta**: i file sospetti vengono spostati in una directory nascosta `.QUARANTINE` con controlli di accesso restrittivi.
- **Gestione metadati**: ogni file in quarantena mantiene informazioni sul percorso originale, data di quarantena e risultati della scansione.
- **Ripristino sicuro**: possibilità di ripristinare i file nella loro posizione originale quando necessario.
- **Blocco esecuzione file**: i file sospetti vengono automaticamente bloccati aggiungendo l'estensione ".blocked" per impedirne l'esecuzione accidentale.

### 4. Interfaccia Utente (UI)
L’applicazione presenta un’interfaccia **JavaFX** che consente all’utente di:
   - **Configurare la connessione VPN**: l'utente può facilmente configurare e gestire la connessione VPN direttamente dall'interfaccia grafica.
   - **Monitorare la connessione**: visualizzazione di informazioni in tempo reale sulla VPN, come la latenza, la velocità di connessione e i dettagli del traffico.
   - **Visualizzare i risultati delle scansioni antivirus**: l'interfaccia fornisce feedback chiari e immediati riguardo ai risultati delle scansioni antivirus, indicando se i file sono sicuri o contengono malware.
   - **Gestire i file in quarantena**, ripristinare o eliminare definitivamente i file posti in quarantena.

### 5. Logging e Notifiche
L’applicazione tiene traccia di tutte le operazioni e fornisce notifiche in tempo reale:
   - **Logging completo**: tutti gli eventi, comprese le scansioni antivirus e i risultati delle analisi, vengono registrati in un file di log per una tracciabilità completa delle operazioni.
   - **Notifiche di sicurezza**: notifiche automatiche vengono inviate all'utente se viene rilevato malware durante le scansioni antivirus.

&nbsp;
## 🚀 Guida all'Installazione

### Prerequisiti

> ⚠️ **Permessi Amministrativi**: Poiché l’applicazione interagisce con WireGuard, è necessario eseguire il programma con privilegi elevati (root/sudo) per gestire le connessioni di rete.

1. **ClamAV**: Necessario per la scansione antivirus. Lo script di installazione automatizzato per Windows ora offre:
   - **Download dinamico dell'ultima versione**: Lo script scarica automaticamente l'ultima versione stabile di ClamAV direttamente dal sito ufficiale.
   - **Configurazione automatica**: I file di configurazione necessari vengono scaricati e installati automaticamente.
   - **Pulizia automatica**: I file temporanei vengono rimossi al termine dell'installazione.
   - **Aggiornamento automatico delle firme**: Le firme virali vengono automaticamente aggiornate all'avvio di WireShield, garantendo che l'antivirus sia sempre aggiornato con le ultime definizioni disponibili.

👉 [Scarica ClamAV per WireShield](https://github.com/LorenzoGallizioli/WireShield/blob/main/wireshield/bin/clamAV/clamAV_Installer.exe)

2. **Java 11** o versione successiva: L’applicazione è sviluppata in Java e utilizza funzionalità correlate come JavaFX.


&nbsp;
## 🛠️ Come Usare l'Applicazione

### 1. Clona WireShield
`git clone https://github.com/LorenzoGallizioli/WireShield.git`

### 2. Verifica di aver seguito tutti i passaggi indicati nei [prerequisiti](#prerequisiti).

### 3. Avvia l'applicazione
> ⚠️ **Permessi Amministrativi**: Poiché l’applicazione interagisce con WireGuard, è necessario eseguire il programma con privilegi elevati (root/sudo) per gestire le connessioni di rete.
Al primo avvio non sarà presente nessun peer.

### 4. Carica un peer
Il peer deve essere caricato cliccando sul bottone '+' nella **Home** di WireShield e deve essere un file di configurazione wireguard (.conf).

### 5. Avvia la connessione VPN
Puoi avviare o interrompere la connessione VPN direttamente dalla scheda **Home** dell'interfaccia utente e controllare i log nella scheda **Logs**.

### 6. Esegui una scansione antivirus
Una volta stabilita la connessione VPN, puoi scansionare i file scaricati tramite **ClamAV** semplicemente scaricando un file dal web e attendendo che WireShield effettui la scansione. Il sistema ti notificherà immediatamente in caso di rilevamento di malware e troverai il risultato della scansione, al termine della stessa, nella sezione **Antivirus**.

### 7. Gestione della quarantena
I file identificati come sospetti vengono automaticamente spostati in quarantena. Puoi **visualizzare** i file in quarantena, **ripristinarli** o **eliminarli** definitivamente attraverso l'interfaccia dedicata.

&nbsp;
## 📚 Riferimenti e Approfondimenti

- **WireGuard**: [Sito Ufficiale](https://www.wireguard.com/)
- **ClamAV**: [Sito Ufficiale](https://www.clamav.net/)

&nbsp;
## 📞 Contatti

Per ulteriori informazioni o domande sul progetto, potete contattarci via email:

- **Davide Bonsembiante** - [d.bonsembiante@studenti.unibg.it](mailto:d.bonsembiante@studenti.unibg.it])
- **Lorenzo Gallizioli** - [l.gallizioli@studenti.unibg.it](mailto:l.gallizioli@studenti.unibg.it)
- **Thomas Paganelli** - [t.paganelli@studenti.unibg.it](mailto:t.paganelli@studenti.unibg.it)
