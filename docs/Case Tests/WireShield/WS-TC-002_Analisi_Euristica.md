## Informazioni Generali

| Campo     | Valore                                                    |
|-----------|------------------------------------------------------------|
| Progetto  | WireShield – Client VPN con protezione antivirus integrata |
| Versione  | 1.0                                                        |
| Autore    | Davide Bonsembiante                                        |
| Data      | 15-04-2025                                                 |

&nbsp;

## Test Case ID: [WS-TC-002] 
### Titolo: Rilevamento euristico di malware modificato

**Categoria di test:**  
Analisi euristica

**Priorità:**  
Alta

&nbsp;

## Obiettivo  
Verificare che WireShield possa rilevare varianti di malware modificate attraverso l'analisi euristica, anche quando la firma esatta non è presente nel database di ClamAV.

&nbsp;

## Pre-condizioni

- WireShield correttamente installato e configurato  
- ClamAV installato e attivo
- Il servizio di antivirus (`AntivirusManager`) e monitoraggio dei file (`DownloadManager`) in esecuzione  
- Campione di malware open-source disponibile

&nbsp;

## Ambiente di test

- Sistema operativo: Windows 10 
- Versione Java: OpenJDK 23 
- Versione ClamAV: 1.4.2
- Dipendenze: JavaFX, ClamAV CLI, logger locale attivo

&nbsp;

## Dati di test

- File: `malware_sample.exe` (campione originale)
- File: `malware_sample_modified.exe` (campione modificato)
- Origine: Repository di malware open-source per test
- Modifiche: Alterazione di stringhe non-funzionali, cambiamento di metadati, modifica di parti non-eseguibili del binario

&nbsp;

## Passi di esecuzione

1. Preparare il campione di malware modificato:
    - Copiare il campione originale
    - Modificare parti non-funzionali con hexeditor
    - Cambiare stringhe e metadati senza alterare la funzionalità
2. Avviare WireShield
3. Scansionare il file modificato
4. Osservare il comportamento del sistema 
5. Verificare se il file viene rilevato come sospetto/dannoso
6. Controllare i log per verificare il tipo di rilevamento
7. Confermare che sia stato un rilevamento euristico e non basato su firma

&nbsp;

## Risultati attesi

- Il file malware_sample_modified.exe viene rilevato come potenzialmente dannoso  
- Il rilevamento è di tipo euristico (in base al tempo impiegato per analizzare il file) 
- Il file viene spostato in quarantena
- Il log contiene un messaggio tipo: `"Virus rilevato..."`  
- L'interfaccia chiede all'utente come procedere, ovvero eliminare il file, oppure ripristinarlo.

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

- Screenshot  
- Log  
- Altre evidenze
