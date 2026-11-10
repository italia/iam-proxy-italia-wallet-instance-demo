"""Locale selection for the wallet demo. Italian is the source language."""

from pathlib import Path

from flask import session
from flask_babel import gettext

SUPPORTED_LANGS = ("it", "en")

JS_MESSAGES = (
    "Seleziona una Attestazione disponibile",
    "Già ottenuta",
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
    "Wallet Provider Nonce",
    "Credential Issuer Nonce",
    "Wallet Attestation",
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
    "Hai appena ottenuto l'attestazione {name}.",
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
    "Non riesco a reimpostare il wallet.",
    "La fotocamera non è disponibile. Serve HTTPS oppure localhost.",
    "Non riesco a usare la fotocamera. Controlla i permessi.",
    "Inquadra una porzione dello schermo",
    "Trascina un riquadro attorno al QR Code.",
    "La cattura dello schermo non è disponibile.",
    "Non riesco a catturare lo schermo.",
    "Non trovo un QR valido in questa immagine. Riprova con un'immagine più nitida.",
    "Non riesco a inviare i dati:",
    "Accesso completato.",
    "Accesso completato presso {name}.",
    "Consulta la Dashboard Presentazioni per i dettagli dell'avvenuta presentazione.",
    "Accesso non riuscito.",
    "Nome",
    "Identificativo",
    "Sito",
    "Informativa",
    "Termini",
    "Contatti",
    "Descrizione",
    "Formato",
    "Attributi",
    "Dati contenuti",
    "Identificativo di configurazione",
    "Nome del credential issuer",
    "URI del credential issuer",
    "Numero di credenziali offerte",
    "1 attestazione disponibile",
    "{count} attestazioni disponibili",
    "Credential offer",
    "QR code della credential offer",
    "Fonte",
    "Header",
    "Payload",
    "Payload cifrato: serve la chiave del destinatario per leggerlo.",
)


def compile_translations() -> None:
    """Write messages.mo from messages.po when the catalog is missing or older."""
    from babel.messages.mofile import write_mo
    from babel.messages.pofile import read_po

    root = Path(__file__).resolve().parent / "translations"
    for po_path in root.glob("*/LC_MESSAGES/messages.po"):
        mo_path = po_path.with_suffix(".mo")
        if mo_path.exists() and mo_path.stat().st_mtime >= po_path.stat().st_mtime:
            continue
        with po_path.open("rb") as po_file:
            catalog = read_po(po_file)
        with mo_path.open("wb") as mo_file:
            write_mo(mo_file, catalog)


def get_locale() -> str:
    lang = session.get("lang") if session else None
    if lang in SUPPORTED_LANGS:
        return lang
    return "it"


def js_catalog() -> dict[str, str]:
    return {message: gettext(message) for message in JS_MESSAGES}
