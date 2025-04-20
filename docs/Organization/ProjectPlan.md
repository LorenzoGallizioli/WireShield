# **Project Plan**
In questo documento illustriamo il **Project Plan** che guiderà lo sviluppo del progetto. Le linee guida fornite serviranno a chiarire il nostro approccio metodologico e le strategie di implementazione, garantendo coerenza e organizzazione durante tutte le fasi del lavoro.

# Indice 

[**1. Introduzione**](#1-introduzione)

[**2. Modello di Processo**](#2-modello-di-processo)
  - [2.1 Modello SCRUM](#21-modello-scrum)
  - [2.2 Programmazione a coppie](#22-programmazione-a-coppie)

[**3. Organizzazione del progetto**](#3-organizzazione-del-progetto)
  - [3.1 Ruoli e Responsabilità](#ruoli-e-responsabilità)

[**4. Standard, linee guida, procedure**](#4-standard-linee-guida-procedure)

[**5. Attività di gestione**](#5-attività-di-gestione)

[**6. Rischi**](#6-rischi)

[**7. Personale**](#7-personale)
    - [Gestione dei Task](#gestione-dei-task)

[**8. Metodi e Tecniche**](#8-metodi-e-tecniche)
  - [8.1 Controllo della Versione e Configurazione](#81-controllo-della-versione-e-configurazione)
  - [8.2 Ambiente di Test e Apparecchiature di Test](#82-ambiente-di-test-e-apparecchiature-di-test)
  - [8.3 Fasi di test principali](#83-fasi-di-test-principali)

[**9. Garanzia di Qualità**](#9-garanzia-di-qualità)
  - [9.1 Obiettivi della Garanzia di Qualità](#91-obiettivi-della-garanzia-di-qualità)
  - [9.2 McCall's Quality Model: Attributi di Qualità](#92-mccalls-quality-model-attributi-di-qualità)

[**10. Pacchetti di Lavoro**](#10-pacchetti-di-lavoro)

[**11. Risorse**](#11-risorse)

[**12. Budget**](#12-budget)

[**13. Cambiamenti**](#13-cambiamenti)

[**14. Consegna**](#14-consegna)
    
&nbsp;
## 1. Introduzione

Il progetto **"WireShield"** si propone di sviluppare una soluzione per l’accesso remoto sicuro, combinando un client VPN basato sul protocollo **WireGuard** con funzionalità avanzate di scansione antivirus e analisi automatica tramite **VirusTotal** e **ClamAV**. L’obiettivo principale è offrire un client VPN che non solo assicuri la riservatezza dei dati e la gestione efficiente delle connessioni, ma che integri anche strumenti per la protezione attiva contro minacce come malware e virus.

L’integrazione di **ClamAV** permetterà di eseguire scansioni antivirus a livello locale, mentre l’API di **VirusTotal** offrirà un ulteriore livello di analisi per i file sospetti, riducendo il rischio di falsi positivi e garantendo un ambiente di lavoro remoto più sicuro e resiliente.

L’applicazione fornirà agli utenti un’interfaccia grafica (UI) intuitiva per gestire la connessione VPN, visualizzare statistiche in tempo reale e accedere a report dettagliati sull’analisi dei file. Saranno incluse notifiche tempestive per avvisare l’utente in caso di rilevamento di minacce informatiche.

Prima di avviare la pianificazione, è stata condotta un’analisi di fattibilità per valutare l’integrazione delle componenti VPN, ClamAV e VirusTotal, verificando la compatibilità tecnica con l’uso del linguaggio **Java**. Questa analisi ha confermato la realizzabilità del progetto, evidenziando i principali rischi e proponendo soluzioni pratiche.

- [Analisi di fattibilità](https://github.com/LorenzoGallizioli/WireShield/blob/main/docs/AnalisiFattibilit%C3%A0.md)

&nbsp;
## 2. Modello di Processo

Per lo sviluppo del progetto, abbiamo adottato un approccio **AGILE** basato sul framework **SCRUM**, opportunamente adattato per soddisfare le esigenze specifiche del team. Questo modello iterativo e incrementale ci consente di mantenere flessibilità durante il processo di sviluppo, rilasciando progressivamente nuove funzionalità e incorporando feedback in tempo reale.

### 2.1 **Modello SCRUM**

- **Durata degli sprint**:  
Gli sprint avranno una durata di **2 settimane**, un compromesso ideale per bilanciare la produttività con gli impegni accademici del team. Questo intervallo di tempo permette di completare obiettivi significativi senza compromettere la qualità del lavoro.

- **Riunioni settimanali**:  
  È prevista una **riunione settimanale di sincronizzazione** della durata di circa un’ora. Questi incontri saranno dedicati a:
  - *Monitorare l’avanzamento del lavoro.*
  - *Identificare e risolvere eventuali impedimenti.* 
  - *Pianificare e riorganizzare i task in base alle priorità emergenti.*

### 2.2 **Programmazione a coppie**

La **programmazione a coppie** (Pair Programming) sarà integrata nel processo di sviluppo come parte integrante del framework SCRUM. La programmazione a coppie sarà applicata principalmente nelle attività legate alla riscrittura del codice, in corrispondenza di bug o funzioni complesse.

&nbsp;
## 3. Organizzazione del progetto

La struttura del team SCRUM è stata pensata per promuovere la collaborazione e l'efficienza, consentendo a ciascun membro di acquisire competenze in diverse aree del processo di sviluppo.

### Ruoli e Responsabilità

- **Scrum Master a rotazione**: Il ruolo di Scrum Master sarà ricoperto a rotazione da ciascun membro del team. Questo approccio consente a tutti i membri di sviluppare competenze nella gestione e facilitazione del processo SCRUM, oltre a garantire che tutti abbiano una comprensione completa delle dinamiche del team.

- **Product Owner condiviso**: Il ruolo di Product Owner non sarà assegnato a una sola persona, ma sarà condiviso tra tutti i membri del team. Ogni membro avrà l'opportunità di partecipare attivamente alla definizione delle funzionalità da sviluppare e alla prioritizzazione degli obiettivi, in modo da favorire un approccio collettivo nella gestione del backlog e delle decisioni strategiche.

- **Team di sviluppo**: Ogni membro del team avrà un ruolo attivo nello sviluppo del codice. Non ci sono divisioni rigide nei ruoli di sviluppo, favorendo così un approccio collaborativo e dinamico.

- **Tester**: I membri del team svolgeranno anche il ruolo di tester, eseguendo test funzionali per garantire la qualità del software. Saranno previsti test sia manuali che automatizzati, con particolare attenzione alla scansione antivirus e all’analisi dei file.

Poiché il progetto non prevede la presenza di clienti esterni, i membri del team assumeranno il ruolo di 'clienti', testando il prodotto e valutando le funzionalità come se fossero utenti finali. In questo modo, si garantirà un feedback continuo e un miglioramento costante delle funzionalità, assicurando che il prodotto risponda alle aspettative e alle necessità degli utenti.

&nbsp;
## 4. Standard, linee guida, procedure

Ispirandoci alla norma **ISO/IEC 9126** per la qualità del software, abbiamo elaborato le seguenti qualità utili per il successo del nostro progetto:

- **Affidabilità**: Garantire la stabilità dell'applicazione, minimizzando il rischio di crash o comportamenti imprevisti. Un software affidabile è essenziale per assicurare la continuità del servizio e la soddisfazione dell'utente.
  
- **Usabilità**: Creare un'interfaccia utente chiara, intuitiva e facilmente navigabile, in modo da offrire un'esperienza utente fluida. La qualità dell'usabilità è cruciale per assicurare che gli utenti possano utilizzare il sistema in modo semplice e immediato.

- **Performance**: Ottimizzare l'efficienza del sistema per garantire che l'applicazione funzioni in modo rapido e senza rallentamenti significativi. Il nostro obiettivo è realizzare un sistema leggero e performante, in linea con la filosofia del protocollo WireGuard.

- **Manutenibilità**: Strutturare il codice in modo chiaro e modulare, facilitando interventi di modifica o correzione nel tempo. Una buona manutenibilità permette di evolvere il software in modo agile e senza complicazioni.

La documentazione dei requisiti segue lo standard **IEEE 830**, che fornisce una guida dettagliata per la specifica e la documentazione dei requisiti di sistema. Questo standard aiuta a definire in modo chiaro e strutturato sia i requisiti funzionali, che descrivono le azioni e le operazioni che il sistema deve eseguire, sia i requisiti non funzionali, che stabiliscono le caratteristiche di qualità del sistema, come le prestazioni, la sicurezza e la manutenibilità. Adottando IEEE 830, il nostro obiettivo è garantire che i requisiti siano ben definiti, comprensibili e misurabili, fornendo così una base solida per tutte le fasi del ciclo di vita del software, dallo sviluppo al testing.

&nbsp;
## 5. Attività di gestione

Per garantire un lavoro completo e dettagliato, il team si impegna costantemente nella creazione di nuova documentazione per le funzionalità aggiunte nelle diverse fasi di sviluppo, senza trascurare l'aggiornamento continuo della documentazione già esistente. Questo approccio assicura che ogni aspetto del progetto sia ben documentato e facilmente comprensibile, facilitando sia lo sviluppo che la manutenzione a lungo termine del software.

&nbsp;
## 6. Rischi

Sono stati individuati alcuni rischi, principalmente di natura tecnica, che potrebbero influenzare lo sviluppo del progetto. Questi rischi sono stati analizzati in dettaglio nella seguente [analisi di fattibilità](https://github.com/LorenzoGallizioli/WireShield/blob/main/docs/AnalisiFattibilit%C3%A0.md), che fornisce una panoramica completa delle possibili problematiche e delle relative soluzioni proposte per mitigare tali rischi.

&nbsp;
## 7. Personale

Il progetto **WireShield** sarà gestito da un team di tre membri, che si occuperanno dell'intero ciclo di vita del progetto, dalle fasi di sviluppo alla gestione dei test e della documentazione. I membri del team collaboreranno in modo sinergico per garantire il successo del progetto. Di seguito sono riportati i dettagli dei membri del team:

- **Davide Bonsembiante** – [GitHub](https://github.com/bnsdavide03)
- **Lorenzo Gallizioli** – [GitHub](https://github.com/LorenzoGallizioli)
- **Thomas Paganelli** – [GitHub](https://github.com/paganello)

### Gestione dei Task

Tutti i task relativi al progetto saranno suddivisi equamente tra i membri del team. Ogni attività, dalla definizione dei requisiti alla progettazione e sviluppo, sarà affrontata in modo collaborativo. I membri del team garantiranno che tutti gli aspetti del progetto siano trattati in modo bilanciato, favorendo un flusso di lavoro coeso e una gestione ottimale del tempo e delle risorse. Inoltre, la continua interazione tra i membri durante le **riunioni settimanali** e gli **sprint** permetterà di monitorare costantemente l'avanzamento e di adattare le priorità in base all’evoluzione del progetto.

&nbsp;
## 8. Metodi e Tecniche

### 8.1 Controllo della Versione e Configurazione

Il controllo della versione del progetto sarà gestito tramite **Git**, utilizzando **GitHub** come piattaforma di repository. Ogni componente software e configurazione associata sarà tracciato e gestito per garantire coerenza e gestione efficiente delle modifiche. Le procedure operative per il controllo della versione saranno le seguenti:

- **Branching**:  
  Saranno utilizzati **branch** per ogni nuova funzionalità o correzione di bug. Il branch principale (**main**) rappresenterà la versione stabile del progetto, mentre le funzionalità in sviluppo saranno contenute in branch separati. In questo modo, si garantisce che lo sviluppo non interferisca con la stabilità del progetto principale.

- **Issue**:  
  Le **issue** saranno utilizzate per tracciare e gestire i bug, le richieste di funzionalità e le attività del progetto. Ogni issue sarà associata a un membro del team, con una priorità definita e una descrizione chiara dell'attività da svolgere. In questo modo, si favorisce la trasparenza nella gestione del lavoro e si permette di monitorare lo stato di avanzamento delle attività.

- **Pull Requests e Code Review**:  
  Le modifiche al codice saranno sottoposte a **pull request**. Ogni modifica verrà revisionata da almeno un altro membro del team per garantirne la qualità e il rispetto degli **standard di codifica**.

- **Kanban Board**:  
 Per la gestione delle attività e il monitoraggio dello stato del progetto, verrà utilizzato un **Kanban Board**. Ogni task, rappresentato da un'issue, sarà spostato tra le colonne del board in base al suo stato di avanzamento (ad esempio: **To Do**, **In Progress**, **Code Review**, **Done**). Questo strumento permetterà al team di avere sempre una visione chiara e aggiornata dello stato del progetto, facilitando la collaborazione e l'assegnazione dei task.

In parallelo, tutte le configurazioni del sistema saranno versionate per garantire coerenza nell'ambiente di sviluppo e di produzione.

### 8.2 Ambiente di Test e Apparecchiature di Test

L’ambiente di test sarà progettato per simulare l’uso reale della soluzione **WireShield** con l’integrazione di scansione antivirus, garantendo che tutti i componenti software, inclusi **WireGuard**, **ClamAV**, e **VirusTotal**, funzionino correttamente in un ambiente di produzione simulato.

1. **Sistemi Operativi**

    L’ambiente di test sarà configurato su **Windows 10** e **Windows 11** , in quanto il protocollo **WireGuard** è compatibile con sistemi Windows e le tecnologie di scansione antivirus **ClamAV** e l’integrazione con **VirusTotal** sono anch'esse supportate su piattaforme Windows. Saranno inclusi anche altri sistemi operativi compatibili con la tecnologia utilizzata, come **Linux** per specifici test di rete e sicurezza.
  

2. **Strumenti di Test**
   - **JUnit**: Per test unitari delle singole componenti del codice, come la gestione delle connessioni VPN e la scansione dei file.
   - **TestFX** o **JaCoCo**: Per test funzionali sull'interfaccia utente (UI), garantendo che il design e le funzionalità siano intuitive e facili da usare.

3. **Apparecchiature**
   L’ambiente di test richiederà:
   - **Server** per ospitare le configurazioni VPN e dispositivi client (PC, laptop, dispositivi mobili) per simulare l’accesso remoto da diverse postazioni.
   - **Personal Computer e Mobile Phone**
   - **Macchine virtuali** per eseguire test in ambienti isolati, garantendo che il sistema funzioni correttamente senza interferire con altre configurazioni o applicazioni.

4. **Ordine e Procedure di Test**

Le fasi di test seguiranno un ordine logico, progettato per garantire che tutte le funzionalità del sistema siano verificate in modo completo e accurato, minimizzando il rischio di errori in fase di produzione.


### 8.3 Fasi di test principali

1. **Preparazione dell’Ambiente di Test**
   - Configurazione dei **server VPN** e dei **client** per testare la connessione e la gestione della rete.
   - Installazione e configurazione di **ClamAV** e l’integrazione con **VirusTotal API**.
   - Verifica della configurazione di rete per simulare correttamente l’accesso remoto sicuro tramite la VPN.

2. **Test Funzionali**
   - **Connessione VPN**: Test della stabilità e affidabilità della connessione VPN tra client e server, per garantire che non ci siano interruzioni durante l’utilizzo del sistema.
   - **Scansione Antivirus**: Verifica della funzionalità di **ClamAV** nel rilevare malware, e test dell’analisi avanzata tramite **VirusTotal** per assicurarsi che i file sospetti vengano identificati correttamente.
   - **Interfaccia Utente**: Test dell’usabilità dell’interfaccia grafica (UI), garantendo che l’esperienza dell’utente sia fluida e che tutte le funzionalità siano facilmente accessibili.

3. **Test di Prestazioni**
   - **Verifica** delle **prestazioni** della connessione VPN, inclusi i tempi di latenza e la velocità sotto carico, per garantire che il sistema non rallenti in condizioni di traffico intenso.
   - **Monitoraggio** delle **risorse** di sistema (CPU, RAM, larghezza di banda) durante l’utilizzo della VPN per verificare l’efficienza e l’impatto sulle risorse del sistema.
   - **Stress test** per simulare scenari di carico elevato, testando la stabilità del sistema sotto condizioni estreme.

4. **Test di Sicurezza**
   - Verifica che **ClamAV** e l'integrazione con **VirusTotal** rilevino correttamente i malware, anche in presenza di file criptati o compressi.

5. **Test di Regressione**
   - Dopo ogni aggiornamento del codice, verranno eseguiti **test di regressione** per garantire che le funzionalità esistenti non siano compromesse dalle nuove modifiche.
   - Verifica che le modifiche o le nuove funzionalità introdotte non causino il verificarsi di nuovi bug o problemi nelle parti già testate.

6. **Test di Usabilità**
   - Test sull’interfaccia utente con focus sull’esperienza dell’utente finale, per raccogliere **feedback utili** a migliorare la navigabilità e l’intuitività.
   - Analisi dell’efficacia delle **notifiche di sicurezza** e dei report generati dall’applicazione, per assicurarsi che gli utenti siano ben informati sui rischi rilevati.

&nbsp;

## 9. Garanzia di Qualità

La **Garanzia di Qualità** del progetto rappresenta un aspetto fondamentale per assicurare che il software sviluppato risponda pienamente ai requisiti funzionali, prestazionali e di sicurezza richiesti. Per raggiungere questo obiettivo, abbiamo adottato un approccio strutturato basato sul **McCall's Quality Model**, che ci consente di analizzare, monitorare e migliorare costantemente le caratteristiche qualitative del sistema durante tutte le fasi di sviluppo, garantendo la consegna di un prodotto affidabile, efficiente e altamente utilizzabile.

### **9.1 Obiettivi della Garanzia di Qualità**

- **Soddisfare i requisiti specificati**: Garantire che il software sia conforme alle necessità operative e alle aspettative degli utenti finali.
- **Migliorare l'affidabilità e la sicurezza**: Ridurre al minimo gli errori, i malfunzionamenti e i rischi associati all'uso del sistema.
- **Ottimizzare le prestazioni**: Assicurare un utilizzo efficiente delle risorse hardware e software.
- **Facilitare l'evoluzione e la manutenzione**: Rendere il sistema facilmente aggiornabile e adattabile a nuovi contesti.

### **9.2 McCall's Quality Model: Attributi di Qualità**
Il modello McCall ci ha guidato nell'identificazione di specifici attributi di qualità, suddivisi in tre categorie principali:

1. **Qualità del Prodotto (Product Operation)**

   Riguarda l’esperienza dell’utente finale e include:
   - **Correttezza**: Verifica che il software soddisfi i requisiti e fornisca risultati accurati.
   - **Affidabilità**: Garantisce che il sistema funzioni in modo stabile e tollerante agli errori.
   - **Efficienza**: Ottimizzazione dell’uso delle risorse per garantire prestazioni elevate.
   - **Integrità**: Protezione dei dati e delle operazioni contro accessi non autorizzati.
   - **Usabilità**: Creazione di un’interfaccia intuitiva e accessibile per migliorare l’esperienza dell’utente.

2. **Qualità del Comportamento durante i Cambiamenti (Product Revision)**
 
   Si focalizza sulla capacità del sistema di adattarsi a modifiche e miglioramenti:
   - **Manutenibilità**: Assicura che le modifiche al codice o al design siano semplici e veloci da implementare.
   - **Testabilità**: Facilita l'identificazione e la risoluzione di problemi.
   - **Flessibilità**: Permette di adattare il software a nuovi requisiti o ambienti operativi.

3. **Qualità di Transizione (Product Transition)**
   Si occupa della capacità del software di operare in nuovi contesti:
   - **Portabilità**: Garantisce che il software possa essere eseguito su diverse piattaforme.
   - **Riutilizzabilità**: Consente il riutilizzo di componenti software in progetti futuri.
   - **Interoperabilità**: Assicura che il sistema interagisca efficacemente con altri software o sistemi.

4. **Valutazione continua e miglioramento**

   Durante tutto il ciclo di sviluppo, verranno condotte valutazioni periodiche per identificare eventuali aree di miglioramento. Gli aggiornamenti e le modifiche verranno gestiti seguendo un processo di test regressivo, per la convalida delle nuove implementazioni e per garantire che le funzionalità esistenti non vengano compromesse.

&nbsp;
## 10. Pacchetti di Lavoro

Il progetto sarà **suddiviso in diversi macro-argomenti**, corrispondenti a pacchetti di lavoro ben definiti, che rappresentano le principali aree di sviluppo. Ogni macro-argomento sarà ulteriormente suddiviso in attività specifiche, che potranno essere allocate ai singoli membri del team Scrum in base alle competenze e alla disponibilità.

Per garantire una gestione efficace e una suddivisione equa del lavoro, **ogni membro** del team avrà un **set di attività assegnate** da completare nel corso della sprint.

Prima di ogni **Scrum Week** (incontro settimanale), il **codice** prodotto da ogni sviluppatore dovrà essere **pushato** su un proprio branch e successivamente integrato **nel branch principale** previa revisione da parte di tutti i membri del team. Questa **revisione collettiva**, che include l'assegnazione di una valutazione qualitativa, permetterà di identificare eventuali problemi e di risolverli tempestivamente, garantendo un'integrazione continua e incrementale delle parti di codice.

&nbsp;
## 11. Risorse

Il progetto prevede l'utilizzo delle seguenti risorse hardware e software:

- **Server di Test**: sarà necessario un server per testare il funzionamento del tunnel WireGuard in un ambiente controllato. Questa macchina verrà utilizzata per verificare l'affidabilità e le prestazioni del servizio.
- **Workstation per il Testing**: poiché il software sarà inizialmente sviluppato solo per Windows, i membri del team utilizzeranno workstation Windows per testare l’applicazione e garantirne la compatibilità.
- **Ottimizzazione delle Risorse**: uno degli obiettivi del progetto è garantire che il software sia il più leggero possibile in termini di consumo di CPU e memoria. Grazie al protocollo WireGuard, noto per la sua efficienza, prevediamo che l’applicazione avrà un impatto minimo sulle risorse di sistema.

&nbsp;
## 12. Budget

Il budget per il progetto sarà contenuto grazie all’adozione di software open source e a strumenti gratuiti. Tuttavia, saranno previsti costi per l'hosting del servizio WireGuard:

- **Utilizzo di Codice Open Source**: gran parte del codice e degli strumenti utilizzati saranno open source, riducendo significativamente i costi di licenza.
- **Costi di Hosting**: l'unico costo previsto sarà quello per l’hosting del servizio WireGuard, che verrà installato su una macchina cloud per garantire alta disponibilità e prestazioni.

&nbsp;
## 13. Cambiamenti

Le modifiche al progetto verranno gestite mediante una breve **analisi di gruppo**, durante la quale si valuteranno le implicazioni tecniche e le tempistiche necessarie. Tutte le decisioni prese verranno documentate accuratamente nello **storico del progetto**, garantendo tracciabilità e trasparenza.

- **Analisi di Gruppo**: Ogni richiesta di modifica sarà esaminata dal team per identificare eventuali impatti sul progetto.
- **Documentazione delle Scelte**: Ogni cambiamento approvato sarà registrato nello storico del progetto, includendo motivazioni e valutazioni tecniche.
- **Tracciabilità e Adattabilità**: La gestione ordinata delle modifiche ci permetterà di mantenere una traccia chiara e di adattarci in modo flessibile alle nuove esigenze.

&nbsp;
## 14. Consegna
La consegna del progetto seguirà una serie di procedure definite per garantire il corretto funzionamento e la soddisfazione del cliente. Di seguito i principali passaggi:

1. **Verifica Finale**: Tutte le funzionalità saranno testate e validate internamente dal team, assicurando che il software risponda ai requisiti iniziali.

2. **README per Installazione e Testing**: Un file `README` dettagliato verrà fornito al cliente per descrivere:
   - *Le istruzioni per l'installazione del software sulla sua macchina.*
   - *Le modalità per eseguire i test del software, garantendo che tutte le funzionalità siano correttamente configurate.*
3. **Supporto durante l'Installazione**: In caso di difficoltà durante l'installazione o i test, sarà fornito un supporto remoto per assistere il cliente in tempo reale.
4. **Documentazione di Consegna**: Il cliente riceverà anche:
   - *Una panoramica delle funzionalità principali del software.*
   - *Eventuali configurazioni avanzate necessarie per l'ottimizzazione delle prestazioni.*
5. **Supporto Post-Consegna**: Sarà garantito un periodo di supporto per risolvere eventuali problemi o richieste di assistenza dopo la consegna.


