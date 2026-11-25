# Funzionalità

Screenshot delle funzionalità principali della demo. Ogni immagine ha una didascalia.

## 1. Accesso

![Schermata di accesso alla demo](../images/1-login.png)

*Accesso alla demo con la password configurata nel progetto (`WALLET_INSTANCE_PASSWORD`).*

## 2. Discovery del Credential Issuer e richiesta di emissione

![Discovery del Credential Issuer e richiesta di emissione](../images/2-credential-issuer-discovery-and-requests.png)

*Configurazione di un Credential Issuer da ispezionare (URL, Trust Anchor, modalità di discovery) e richiesta di emissione di un attestato dal catalogo caricato.*

## 3. Attestati ottenuti

![Ispezione degli attestati ottenuti](../images/3-issued-credentials.png)

*Attestati già ottenuti: metadata, attributi dell’utente, attestato in chiaro (Header, Payload, Disclosure o notazione diagnostica CBOR) e stato di revoca, per formati SD-JWT e mdoc CBOR.*

## 4. Storico Azioni HTTP e ispezione degli oggetti

![Storico delle azioni HTTP e ispezione degli oggetti](../images/4-http-logs-and-objects-inspection.png)

*Registro delle richieste e risposte verso credential issuer, verificatori e federazione, con ispezione del messaggio HTTP e dei JWT incorporati (header e payload).*

## 5. Presentazione cross-device

![Acquisizione del QR per la presentazione cross-device](../images/5-cross-device-presentation-flow.png)

*Avvio della presentazione OpenID4VP acquisendo il QR del Relying Party: caricamento di un’immagine o cattura di una porzione di schermo.*

## 6. Gestione della richiesta di presentazione e selective disclosure

![Conferma presentazione con selective disclosure e ispezione della richiesta](../images/6-presentatio-request-handling-with-selective-disclosure-and-presentation-request-inspection.png)

*Conferma della presentazione: metadata del verificatore, attributi richiesti con selective disclosure e ispezione della richiesta del verificatore (query DCQL).*

## 7. Dashboard Presentazioni

![Dashboard delle presentazioni verso i Relying Party](../images/7-rp-presentation-dashboard.png)

*Storico delle interazioni con i Relying Party: esito, metadata del verificatore, attestati richiesti e presentati, esportazione JSON.*
