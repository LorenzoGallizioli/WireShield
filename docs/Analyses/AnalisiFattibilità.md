# Analisi di Fattibilità - Software di Gestione WireGuard in Java

# Indice

1. [**Introduzione**](#introduzione)  
2. [**Obiettivi del Progetto**](#obiettivi-del-progetto)  
3. [**Requisiti Funzionali**](#requisiti-funzionali)
   - Gestione della Connessione WireGuard
   - Monitoraggio e Analisi dei File Scaricati
4. [**Aspetti Tecnici e Implementazione**](#aspetti-tecnici-e-implementazione)
   - Interazione con WireGuard 
   - Monitoraggio e Analisi Antivirus
5. [**Rischi e Sfide**](#rischi-e-sfide)
   - Interazione con WireGuard
   - Monitoraggio dei File e Scansione Antivirus]
   - Soluzioni e Mitigazioni
6. [**Conclusioni**](#conclusioni)



&nbsp;
## Introduzione

Questo progetto nasce con l’idea di realizzare un software in Java che permetta di gestire e monitorare le connessioni VPN utilizzando WireGuard. WireGuard è noto per essere un protocollo VPN molto efficiente e sicuro, ma manca di un’interfaccia utente completa e intuitiva, soprattutto su sistemi desktop. L’obiettivo principale è quindi quello di creare una dashboard grafica che consenta di visualizzare lo stato della connessione e tutte le informazioni rilevanti per l’utente.

Inoltre, per migliorare la sicurezza, il software sarà in grado di monitorare i file scaricati durante l’uso della VPN e di analizzarli automaticamente alla ricerca di minacce, utilizzando strumenti antivirus come ClamAV o servizi di analisi online come VirusTotal.

&nbsp;
## Obiettivi del Progetto

L’idea alla base di questo software è offrire un’esperienza semplice e intuitiva per chi utilizza WireGuard, fornendo un controllo completo sulla connessione e migliorando la sicurezza. Gli obiettivi principali includono:
1. *Creare un’interfaccia grafica per la gestione della connessione WireGuard, visualizzando informazioni come lo stato del tunnel, i peer connessi e le statistiche di traffico.*
2. *Integrare un sistema di monitoraggio dei file scaricati mentre la VPN è attiva, in modo da identificare eventuali minacce in tempo reale.*
3. *Offrire agli utenti un’ulteriore protezione, analizzando i file con ClamAV o, se necessario, inviandoli a VirusTotal per una scansione più approfondita.*

&nbsp;
## Requisiti Funzionali

Il progetto si concentra su due funzionalità principali:

1. **Gestione della connessione WireGuard:** L'utente potrà avviare e fermare la connessione VPN direttamente dal software. La dashboard mostrerà in tempo reale lo stato del tunnel (attivo o inattivo), la quantità di traffico inviato e ricevuto, e informazioni dettagliate sui peer connessi.

2. **Monitoraggio e analisi dei file scaricati:** Quando la connessione VPN è attiva, il software monitorerà la cartella di download predefinita dell’utente. Ogni file scaricato sarà automaticamente analizzato per individuare possibili minacce. Verrà effettuata una scansione con ClamAV o, per una verifica più approfondita, il file potrà essere inviato a VirusTotal.

&nbsp;
## Aspetti Tecnici e Implementazione
Veniamo al vero obbiettivo di questo documento, ovvero l'analisi della fattibilita' tecnica del progetto, che tenga conto sia delle tempische di sviluppo che delle tecnologie a noi disponibili.

**Interazione con WireGuard tramite comandi di sistema:**
WireGuard viene tipicamente gestito tramite comandi di sistema, come ```wg``` per mostrare lo stato della connessione e ```wg-quick``` per avviare o interrompere un tunnel. Java, tuttavia, non ha accesso nativo ai processi di sistema, quindi dobbiamo utilizzare chiamate esterne tramite la classe ProcessBuilder o librerie come JNA (Java Native Access) per invocare questi comandi.
Di seguito riportiamo un esempio che rappresenta come sarebbe per noi possibile eseguire una chiamata di sistema al servizio WireGuard, con l'obbiettivo di stampare lo stato delle connessioni su shell:
```
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class WireGuardManager {

    public static void getWireGuardStatus() {
        try {
            // Creiamo il comando da eseguire
            ProcessBuilder processBuilder = new ProcessBuilder("wg", "show");
            Process process = processBuilder.start();

            // Leggiamo l'output del comando
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            System.out.println("Stato WireGuard:");
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }

            // Verifichiamo l'uscita del processo
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                System.err.println("Errore durante l'esecuzione del comando.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        getWireGuardStatus();
    }
}
```
Documentazione: [ProcessBuilder](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/ProcessBuilder.html)

In alternativa, Se si preferisce un’interazione più diretta con le librerie di sistema (ad esempio per invocare funzioni C direttamente), potremmo usare JNA.

```
import com.sun.jna.Library;
import com.sun.jna.Native;

public class JNASystemCall {

    public interface CLibrary extends Library {
        CLibrary INSTANCE = Native.load("c", CLibrary.class);

        // Definizione del metodo di sistema
        int system(String command);
    }

    public static void main(String[] args) {
        // Eseguire un comando di sistema tramite JNA
        CLibrary.INSTANCE.system("wg show");
    }
}
```
Documentazione: [JNA Documentation](https://github.com/java-native-access/jna)

**Monitoraggio dei file scaricati e analisi con ClamAV e VirusTotal:**
La parte di monitoraggio dei file scaricati potrà essere implementata utilizzando le funzionalità di Java per osservare i cambiamenti nel file system (WatchService). Quando un nuovo file viene rilevato nella cartella di download, il software lo sottoporrà a scansione utilizzando ClamAV. Se il risultato della scansione è positivo (ovvero, viene rilevata una minaccia), il file può essere bloccato o eliminato, in base alle preferenze dell’utente. Se invece il file risulta sospetto ma non chiaramente pericoloso, sarà possibile inviarlo a VirusTotal per una scansione più approfondita.
Di questa implementazione non fornisco alcun esempio per via della maggiore difficoltà di programmazione, tuttavia sono sicuro che ChatGPT o simili saranno in grado di fornire esempi esplicativi sufficientemente validi allo scopo di questa analisi.

Documentazione: 
- [WatchService](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/nio/file/WatchService.html)
- [clamscan](https://docs.clamav.net/manual/Usage/Scanning.html)

&nbsp;
## Rischi e Sfide

**Interazione con WireGuard:**
Il progetto presenta alcune sfide tecniche significative. La prima riguarda la gestione dei processi di sistema, che può variare a seconda del sistema operativo. Mentre su Linux la gestione di WireGuard è abbastanza semplice tramite comandi shell, su Windows e macOS potrebbe essere necessario adattare il codice per funzionare correttamente. A tal riguardo ci viene in mente la necessità di gestione delle PATH, per permettere il riconoscimento delle chiamate shell da perte del sistema windows.
Inoltre, utilizzare JNA per invocare funzioni di sistema può introdurre vulnerabilità, soprattutto se non viene eseguita una corretta validazione degli input. È importante evitare comandi shell che potrebbero essere soggetti a injection attack.

**Monitoraggio dei File Scaricati e Scansione Antivirus:**
Un’altra sfida è rappresentata dal monitoraggio in tempo reale dei file scaricati. Questa funzionalità potrebbe influire sulle prestazioni del sistema, soprattutto se vengono scaricati molti file contemporaneamente o se i file sono di grandi dimensioni.
Non solo, quando un file viene scaricato da un browser, spesso viene creato come file temporaneo (ad esempio .part in Firefox) e rinominato una volta completato il download. Se il monitoraggio avviene troppo presto, potremmo scansionare file incompleti o in uso, causando errori.

Un'altra sfida alla quale saremo sottoposti sarebbe la corretta gestione dei falsi positivi generati da ClamAV, una cattiva gestione può portare a cancellazioni o blocchi inappropriati, causando insoddisfazione dell'utente.
Inoltre, l’uso di servizi online come VirusTotal introduce problemi di privacy e di gestione delle chiavi, poiché i file devono essere codificati in SHA256 per l'invio a un server esterno.

**Soluzioni a Mitigazioni**
- *Implementare un controllo per verificare se il file è stato completato prima di avviare la scansione (ad esempio, aspettando un periodo di inattività del file).*
- *Fornire all'utente opzioni configurabili per gestire i falsi positivi (ad esempio, spostare i file in quarantena anziché eliminarli immediatamente).*
- *Utilizzare un sistema di caching per evitare di inviare più volte lo stesso file a VirusTotal, riducendo il numero di richieste API.*
- *Chiedere il consenso esplicito all'utente prima di inviare file a VirusTotal e informarlo delle implicazioni sulla privacy.*
- *Eseguire controlli di sicurezza sull’input del percorso file prima di eseguire* ```clamscan``` *per prevenire attacchi di iniezione.*
  
&nbsp;
## Conclusioni

Sebbene il progetto presenti delle complessità, la sua realizzazione è tecnicamente fattibile. L’applicazione risponderebbe a una necessità reale, combinando la gestione intuitiva di WireGuard con una protezione avanzata contro le minacce informatiche. L'utilizzo di Java come linguaggio porta con se il beneficio di mantenere il software portabile su diverse piattaforme, mentre l’integrazione con strumenti come ClamAV e VirusTotal garantisce un elevato livello di sicurezza.

Nel complesso, il progetto rappresenta una soluzione innovativa e utile per gli utenti che desiderano una gestione avanzata della VPN con un’attenzione particolare alla sicurezza.
