
## Breve descrizione del funzionamento di Wireguard con la WindowsFirewallPlatform
Essenzialmente Wireguard non crea delle nuove regole permanenti sulla piattaforma firewall di windows, conseguentemente a cio l'uso di comandi come 'netsh' o tramite powershell non permettono l'identificazione delle regole.
Per ovviare questo problema (e quindi eseguire un analisi completa delle regole applicate in WFP) si e' reso necessario l'utilizzo di [WindowsFirewallPlatformExplorer](https://github.com/zodiacon/WFPExplorer/releases/tag/v0.5.4), il quale permette l'analisi completa delle regole impostate e quindi una migliore comprensione delle stesse.
<br> 
Definite quindi le regole e analizzata la loro effittiva presenza/natura, ho verificato dove e come essere vengono applicate, analizzando il codice sorgente (Open Source) di [WireGuard-Windows](https://github.com/WireGuard/wireguard-windows): 
<br>
Le regole vengono create basandosi sulla struttura della libreria win32 di Microsoft, essa stabilisce gli UUID dei vari layer di lavoro del firewall stesso, permettendo quindi di operare in modo molto granulare sullo stack.
Successivamente vengono quindi definite nel file `rules.go` le effettive funzioni (richiamante da `blocker.go`) che strutturano le regole che verranno poi attivate; questo e' molto importante in quanto conoscendo la sessione e l'interfaccia sulla quale si opera, sfuttando le diposzioni della lib win32, si potranno realizzare custom-rules ad-och.
L'interfaccia che viene operata e' definita localmente da un LUID, che viene poi convertito in identificativo globale attraverso alcune funzioni scritte in codice sorgente, sara' quindi necessario gestire e verificare questa cosa.
<br>
utilizzando la libreria messa a disposizione `embeddable-dll-service`, con relativa `tunnel.dll`, si dovrebbe aver accesso alle chiamate in modo simile a quanto fatto dal codice sorgente, comunque sara' mia premura nella giornata di domani o successivi verificare questo dettaglio.
L'obbiettivo rimane la realizzazione di uno scirpt che abiliti la connessione verso rete locale anche qunado la funzione kill-switch e' abilitata; non ho dubbi possa essere realizzato anche senza l'implementazione di `embeddable-dll-service`.
