# cybersec-project-group14

L’implementazione prevede lo sviluppo dell’interazione tra un client e un server che,
attraverso lo scambio di pacchetti su connessione HTTPS, risolvono il protocollo di
non-interactive zero knowledge proof secondo il modello di Schnoor.

Si è provveduto quindi a sviluppare uno script Python che esegue il compito del
client. Il codice di back-end del server è stato sviluppato attraverso il framework
Django, in Python, e servito sul web-server Apache attraverso Il modulo mod_wsgi.
Per una più semplice e immediata risoluzione di un protocollo ZKP tra Client e Server,
è stata realizzata group_utilities.py, una piccola libreria orientata alla
programmazione a oggetti.

Il web-server è stato quindi configurato affinché possa servire richieste HTTPS. A tal
fine sono stati generati il certificato del server e della CA che l’ha firmato.
Si rende noto che il gruppo utilizzato per eseguire il protocollo è 1024-bit MODP
Group with 160-bit Prime Order Subgroup come descritto nella sezione dedicata alla
zero knowledge proof.
