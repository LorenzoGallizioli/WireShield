## Informazioni Generali

| Campo     | Valore                                                    |
|-----------|------------------------------------------------------------|
| Progetto  | WireShield – Client VPN con protezione antivirus integrata |
| Versione  | 1.0                                                        |
| Autore    | Davide Bonsembiante                                        |
| Data      | 15-04-2025                                                 |

&nbsp;

## Test Case ID: [WS-TC-003] 
### Titolo: Analisi statistiche di falsi positivi e falsi negativi

**Categoria di test:**  
Analisi dei falsi positivi/negativi

**Priorità:**  
Media

&nbsp;

## Obiettivo  
Misurare accuratamente il tasso di falsi positivi e falsi negativi generati da ClamAV su un dataset noto, tramite esecuzione di test esterni automatizzati, per valutarne la precisione.

&nbsp;

## Pre-condizioni

- WireShield correttamente installato e configurato  
- ClamAV installato e attivo
- Dataset di test preparato (file benigni e dannosi, con etichette note)
- Il servizio di antivirus (`AntivirusManager`) e monitoraggio dei file (`DownloadManager`) in esecuzione  

&nbsp;

## Ambiente di test

- Sistema operativo: Windows 10 
- Versione Java: OpenJDK 23 
- Versione ClamAV: 1.4.2
- Dipendenze: JavaFX, ClamAV CLI, logger locale attivo

&nbsp;

## Dati di test

Dataset misto di:
- File benigni (benigno1.exe, benigno2.exe, ecc.)
- Malware noti (malware1.exe, malware2.exe, ecc.)
- Origine: repository open-source per test antivirus
- Etichette ground-truth predefinite per ciascun file

&nbsp;

## Passi di esecuzione

1. Compilare ed eseguire il codice `StatisticheTestClamAV.java` allegato nella sezione Allegati
2. Analizzare l’output a terminale, che fornirà:
   - Numero di file scansionati
   - Falsi positivi
   - Falsi negativi
   - Percentuali relative

&nbsp;

## Risultati attesi

- Il codice stampa:
  - Numero totale di file scansionati
  - Numero di malware correttamente rilevati
  - Numero di falsi positivi
  - Numero di falsi negativi
  - Percentuali relative
- Nessuna eccezione o crash nell'esecuzione
- Possibilità di ripetere il test con dataset estesi

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
| Tempo di esecuzione | [ms/s]    |
| Utilizzo CPU        | [%]       |
| Utilizzo memoria    | [MB]      |
| Altro               | [eventuali]

&nbsp;

## Allegati

### 📄 Codice Java – StatisticheTestClamAV.java

```java
import java.util.*;

public class StatisticheTestClamAV {

    private static class StatisticheAntivirus {
        private int fileScansionati = 0;
        private int malwareRilevati = 0;
        private int falsiPositivi = 0;
        private int falsiNegativi = 0;

        public void incrementaScansioni() { fileScansionati++; }
        public void incrementaRilevati() { malwareRilevati++; }
        public void incrementaFalsiPositivi() { falsiPositivi++; }
        public void incrementaFalsiNegativi() { falsiNegativi++; }

        public void stampaStatistiche() {
            System.out.println("📊 STATISTICHE ANTIVIRUS (ClamAV)");
            System.out.println("File scansionati     : " + fileScansionati);
            System.out.println("Malware rilevati     : " + malwareRilevati);
            System.out.println("Falsi positivi       : " + falsiPositivi);
            System.out.println("Falsi negativi       : " + falsiNegativi);
            System.out.println("Tasso falsi positivi : " +
                (fileScansionati == 0 ? "0%" : (falsiPositivi * 100 / fileScansionati) + "%"));
            System.out.println("Tasso falsi negativi : " +
                (fileScansionati == 0 ? "0%" : (falsiNegativi * 100 / fileScansionati) + "%"));
        }
    }

    public static void main(String[] args) {
        StatisticheAntivirus stats = new StatisticheAntivirus();

        // Dataset simulato: filename -> [attesoMalware, rilevatoDaClamAV]
        Map<String, Boolean[]> dataset = new LinkedHashMap<>();
        dataset.put("benigno1.exe", new Boolean[]{false, true});   // falso positivo
        dataset.put("malware1.exe", new Boolean[]{true, true});    // corretto
        dataset.put("malware2.exe", new Boolean[]{true, false});   // falso negativo
        dataset.put("benigno2.exe", new Boolean[]{false, false});  // corretto
        dataset.put("benigno3.exe", new Boolean[]{false, true});   // falso positivo

        for (Map.Entry<String, Boolean[]> entry : dataset.entrySet()) {
            String file = entry.getKey();
            boolean attesoMalware = entry.getValue()[0];
            boolean rilevatoMalware = entry.getValue()[1];

            System.out.println("▶ Scansione: " + file);
            stats.incrementaScansioni();

            if (attesoMalware && rilevatoMalware) {
                stats.incrementaRilevati();
                System.out.println("✅ Malware rilevato correttamente.");
            } else if (!attesoMalware && rilevatoMalware) {
                stats.incrementaFalsiPositivi();
                System.out.println("⚠️  Falso positivo.");
            } else if (attesoMalware && !rilevatoMalware) {
                stats.incrementaFalsiNegativi();
                System.out.println("❌ Falso negativo.");
            } else {
                System.out.println("✔️  File benigno rilevato correttamente.");
            }
            System.out.println();
        }

        stats.stampaStatistiche();
    }
}
```