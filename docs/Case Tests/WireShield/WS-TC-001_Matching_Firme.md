## Informazioni Generali

| Campo     | Valore                                                    |
|-----------|------------------------------------------------------------|
| Progetto  | WireShield – Client VPN con protezione antivirus integrata |
| Versione  | 1.0                                                        |
| Autore    | Davide Bonsembiante                                        |
| Data      | 15-04-2025                                                 |

&nbsp;

## Test Case ID: [WS-TC-001]  
### Titolo: Rilevamento di file contenente firma virale nota

**Categoria di test:**  
Rilevamento basato su firma

**Priorità:**  
Alta

&nbsp;

## Obiettivo  
Verificare che ClamAV rilevi correttamente un file con una firma virale nota (es. EICAR) e che WireShield sposti il file in quarantena, generando dei log e notificando l’utente.

&nbsp;

## Pre-condizioni

- WireShield correttamente installato e configurato  
- ClamAV installato e attivo
- Il servizio di antivirus (`AntivirusManager`) e monitoraggio dei file (`DownloadManager`) in esecuzione  
- File di test `eicar.com` disponibile

&nbsp;

## Ambiente di test

- Sistema operativo: Windows 10 
- Versione Java: OpenJDK 23 
- Versione ClamAV: 1.4.2
- Dipendenze: JavaFX, ClamAV CLI, logger locale attivo

&nbsp;

## Dati di test

- File: `eicar.com`  
- Origine: [https://www.eicar.org/](https://www.eicar.org/)  
- Contenuto: stringa di test antivirale standard  
- Note: il file **non è pericoloso**, ma serve solo per testare i motori antivirus

&nbsp;

## Passi di esecuzione

1. Avviare WireShield  
2. Scaricare `eicar.com`
3. Attendere la scansione automatica  
4. Controllare che il file sia stato spostato in `quarantena/`  
5. Verificare i logger presenti nel terminale
6. Controllare se ClamAV ha rilevato il file come dannoso e chiede come procedere, se rimuoverlo o ripristinarlo

&nbsp;

## Risultati attesi

- Il file `eicar.com` viene rilevato come infetto da ClamAV  
- Il file viene spostato in quarantena  
- Il log contiene un messaggio tipo: `"Virus rilevato..."`  
- L'interfaccia chiede all'utente come procedere, ovvero eliminare il file, oppure ripristinarlo.

&nbsp;

## Risultati effettivi

- [Da compilare durante l'esecuzione]

&nbsp;

## Stato

**Superato**

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
