## Informazioni Generali

| Campo     | Valore                                                    |
|-----------|------------------------------------------------------------|
| Progetto  | WireShield – Client VPN con protezione antivirus integrata |
| Versione  | 1.0                                                        |
| Autore    | Davide Bonsembiante                                        |
| Data      | 15-04-2025                                                 |

&nbsp;

## Test Case ID: [WS-TC-004]  
### Titolo: Performance e Timing di Scansione con ClamAV

**Categoria di test:**  
Prestazioni e temporizzazione

**Priorità:**  
Alta

&nbsp;

## Obiettivo  
Misurare il tempo necessario per scansionare vari file di dimensioni e complessità diverse utilizzando ClamAV, e verificare che la performance del sistema rimanga adeguata sotto carico.

&nbsp;

## Pre-condizioni

- WireShield correttamente installato e configurato  
- ClamAV installato e attivo  
- Il servizio di antivirus (`AntivirusManager`) e monitoraggio dei file (`DownloadManager`) in esecuzione  
- Sistema con risorse sufficienti (CPU e memoria) per testare la performance

&nbsp;

## Ambiente di test

- Sistema operativo: Windows 10  
- Versione Java: OpenJDK 23  
- Versione ClamAV: 1.4.2  
- Dipendenze: JavaFX, ClamAV CLI, logger locale attivo

&nbsp;

## Dati di test

- Dataset misto di file:
  - File di piccole dimensioni (1-5 MB)
  - File di dimensioni medie (10-50 MB)
  - File di grandi dimensioni (100-500 MB)
  - File di tipo malizioso e benigno

&nbsp;

## Passi di esecuzione

1. Preparare i seguenti file per il test:
    - File di piccole dimensioni (esempio: `small_file.exe` da 3 MB)
    - File di medie dimensioni (esempio: `medium_file.exe` da 25 MB)
    - File di grandi dimensioni (esempio: `large_file.exe` da 200 MB)
2. Avviare il programma di test (`PerformanceTestClamAV.java`) allegato nella sezione **Allegati**
3. Esaminare il tempo totale di scansione per ogni file, come riportato nel log di output
4. Ripetere la scansione più volte per ognuno dei file di dimensioni diverse per verificare la coerenza dei risultati
5. Verificare che il sistema non vada in crash o rallenti in modo significativo durante le scansioni di grandi file
6. Valutare l’utilizzo delle risorse del sistema (CPU, memoria) durante le scansioni

&nbsp;

## Risultati attesi

- Il tempo di scansione per ogni file dovrebbe essere riportato nel log.
- I tempi di scansione dovrebbero essere accettabili e coerenti, in base alla dimensione del file (esempio: il file più grande dovrebbe richiedere più tempo, ma senza rallentamenti eccessivi).
- Non ci dovrebbero essere crash del sistema durante le scansioni.
- Il sistema non dovrebbe consumare una quantità eccessiva di risorse CPU/memoria e causare problemi a lavorare in parallelo.
  
&nbsp;

## Risultati effettivi

- [Da compilare durante l'esecuzione]

&nbsp;

## Stato

[Superato/Fallito]

&nbsp;

## Metriche rilevate

| Metrica             | Valore    |
|---------------------|-----------|
| Tempo di esecuzione (file piccoli) | [ms/s]    |
| Tempo di esecuzione (file medi)   | [ms/s]    |
| Tempo di esecuzione (file grandi) | [ms/s]    |
| Utilizzo CPU        | [%]       |
| Utilizzo memoria    | [MB]      |
| Altro               | [eventuali]

&nbsp;

## Allegati

### 📄 Codice Java – PerformanceTestClamAV.java

```java
import java.io.File;
import java.io.IOException;
import java.util.Arrays;

public class PerformanceTestClamAV {

    public static void main(String[] args) {
        // Lista dei file da testare
        File[] filesToScan = {
            new File("path_to_files/small_file.exe"),   // 3 MB
            new File("path_to_files/medium_file.exe"),  // 25 MB
            new File("path_to_files/large_file.exe")    // 200 MB
        };

        // Variabili per la misurazione dei tempi
        long startTime, endTime;
        long totalTime = 0;

        for (File file : filesToScan) {
            System.out.println("▶ Inizio scansione di: " + file.getName());
            
            // Iniziamo a misurare il tempo di scansione
            startTime = System.currentTimeMillis();
            int result = scanFileWithClamAV(file); // Funzione per la scansione con ClamAV
            endTime = System.currentTimeMillis();
            
            long elapsedTime = endTime - startTime;
            totalTime += elapsedTime;
            
            // Stampa dei risultati
            if (result == 0) {
                System.out.println("✅ Scansione completata con successo per: " + file.getName());
            } else {
                System.out.println("⚠️ Errore durante la scansione di: " + file.getName());
            }
            
            System.out.println("Tempo di scansione per " + file.getName() + ": " + elapsedTime + " ms");
        }

        // Stampa dei tempi totali
        System.out.println("\n🏁 Tempo totale di scansione per tutti i file: " + totalTime + " ms");
    }

    // Funzione per eseguire la scansione con ClamAV
    public static int scanFileWithClamAV(File file) {
        // Comando per eseguire la scansione con ClamAV tramite CLI
        String command = "clamdscan --no-summary --stdout " + file.getAbsolutePath();
        
        try {
            Process process = Runtime.getRuntime().exec(command);
            process.waitFor();
            return process.exitValue();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            return -1;
        }
    }
}
```

### Dettagli:

- Il codice misura il tempo di scansione per diversi file di diverse dimensioni e stampa i risultati in modo che possano essere analizzati.
- Ogni file viene scansionato tramite il comando `clamdscan` di ClamAV e il tempo di esecuzione per ciascuna scansione viene registrato.
- Alla fine del test, viene riportato il tempo totale di scansione per tutti i file, e ogni file viene testato singolarmente.