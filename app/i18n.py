"""Locale selection for the wallet demo. Italian is the source language."""

from flask import session
from flask_babel import gettext

SUPPORTED_LANGS = ("it", "en")

JS_MESSAGES = (
    "Scegli un'attestazione",
    "Già ottenuta",
    "Attestazione",
    "Ottieni",
    "Ottieni attestazione",
    "Nessuno scambio registrato.",
    "Seleziona scambio",
    "Copia",
    "Copiato",
    "Seleziona gli scambi da rimuovere.",
    "Richiesta",
    "Risposta",
    "Richiesta HTTP",
    "Risposta HTTP",
    "Issuer di credenziali",
    "Verificatore",
    "Federazione",
    "Azioni",
    "Elenco degli scambi",
    "Configurazione di entità",
    "Metadata dell'issuer",
    "Pushed authorization",
    "Token",
    "Nonce",
    "Rilascio dell'attestazione",
    "Status List",
    "Request URI",
    "Risposta di presentazione",
    "Autorizzazione",
    "Elenco di federazione",
    "Altro",
    "Seleziona un'attestazione.",
    "Inserisci un URL http o https.",
    "eudiw lotl non è ancora implementato.",
    "Seleziona una modalità di discovery.",
    "Impossibile leggere i metadata di questo issuer.",
    "Richiesta in corso...",
    "Ti sto portando all'issuer per scegliere l'identità digitale. Al termine torni qui e l'attestazione viene salvata.",
    "Per il rilascio di {name}, non sarà condiviso alcun dato con l'issuer.",
    "Per il rilascio di {name}, saranno condivisi con l'issuer i seguenti dati:",
    "Premendo Continua autorizzi la trasmissione delle informazioni.",
    "Continua",
    "Annulla",
    "La risposta non contiene l'elenco dei dati da condividere.",
    "Non riesco a ottenere l'attestazione.",
    "Errore sconosciuto",
    "Attestazione ottenuta.",
    "Visualizzala",
    "Non riesco a salvare l'attestazione.",
    "Per l'accesso con il verificatore selezionato, non sarà condiviso alcun dato.",
    "Per l'accesso con il verificatore selezionato, saranno condivisi i seguenti dati:",
    "Impossibile effettuare l'accesso",
    "Rimuovere l'attestazione {name}?",
    "Attestazione {name} rimossa.",
    "Attestazione {name} rimossa. Il wallet è stato reimpostato.",
    "Non riesco a eliminare l'attestazione.",
    "Errore generico",
    "sconosciuto",
    "Impossibile visualizzare l'elemento selezionato",
    "Il wallet è stato reimpostato.",
    "La fotocamera non è disponibile. Serve HTTPS oppure localhost.",
    "Non riesco a usare la fotocamera. Controlla i permessi.",
    "Non trovo un QR valido in questa immagine. Riprova con un'immagine più nitida.",
    "Non riesco a inviare i dati:",
    "Accesso completato.",
    "Accesso non riuscito.",
    "Descrizione",
    "Formato",
    "Dati contenuti",
    "Identificativo di configurazione",
    "Nome del credential issuer",
    "URI del credential issuer",
    "Numero di credenziali offerte",
    "Credential offer",
    "QR code della credential offer",
    "Fonte",
    "Header",
    "Payload",
    "Payload cifrato: serve la chiave del destinatario per leggerlo.",
)


def get_locale() -> str:
    lang = session.get("lang") if session else None
    if lang in SUPPORTED_LANGS:
        return lang
    return "it"


def js_catalog() -> dict[str, str]:
    return {message: gettext(message) for message in JS_MESSAGES}
