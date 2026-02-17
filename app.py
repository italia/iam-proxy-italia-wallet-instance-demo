import json
import logging
import logging.config
import os
import sys

from flask import Flask, g, has_app_context

from constants import JWT_PREFIX, MSO_MDOC_PREFIX, SD_JWT_PREFIX
from routes.itwallet_routes import itwallet_routes
from routes.main_routes import main_routes
from routes.wallet_routes import wallet_routes
from utils.utils import remove_str_prefix, sanitize_for_logging

# Configura la codifica stdout
sys.stdout.reconfigure(encoding="utf-8")

app = Flask(__name__)
app.secret_key = "s3cr3t"
CONFIG_DIR = "config"

# Filtri personalizzati da usare nei template Jinja2


@app.template_filter("from_json")
def from_json_filter(value):
    """
    Converte il valore in lista Python.
    - Se è già una lista, la ritorna così com'è.
    - Se è una stringa JSON valida, la decodifica.
    - In caso di errore o valore None, ritorna lista vuota.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError) as e:
        # codeql[py/log-injection]
        logging.getLogger(__name__).error(
            "Errore parsing JSON nel filtro: %s, valore: %s",
            sanitize_for_logging(str(e)),
            sanitize_for_logging(value),
        )
        return []


@app.template_filter("split")
def split_string(value, delimiter):
    """Dividi una stringa in base a un delimitatore."""
    return value.split(delimiter)


@app.template_filter("format_credenziale")
def format_credenziale(value):
    """Ritorna il formato della credenziale in base al suo credential_id."""
    if not value:
        return "sconosciuto"

    valueLower = value.lower()

    if valueLower.startswith(JWT_PREFIX.lower()):
        return JWT_PREFIX.lower()
    elif valueLower.startswith(SD_JWT_PREFIX.lower()):
        return SD_JWT_PREFIX.lower()
    elif valueLower.startswith(MSO_MDOC_PREFIX.lower()):
        return MSO_MDOC_PREFIX.lower()
    else:
        return "sconosciuto"


@app.template_filter("tag_credenziale")
def tag_credenziale(value):
    """Ritorna il tag della credenziale in base al suo credential_id.
    Rimuove il prefisso e nella parte restante applica qusta regola:
     - Controlla il primo carattere, se è speciale (non lettera o numero), lo rimuove.
     - Se ce ne sono almeno 3, restituisce i primi 3 caratteri maiuscoli.
     - Altrimenti, restituisce i primi 3 caratteri della stringa originale in maiuscolo."""

    if not value:
        return "N/A"

    # Rimozione prefissi credenziali
    prefixes = [JWT_PREFIX, SD_JWT_PREFIX, MSO_MDOC_PREFIX]
    valueWithoutPrefix = remove_str_prefix(value, prefixes)

    # Rimuovi primo carattere se speciale
    if valueWithoutPrefix and not valueWithoutPrefix[0].isalnum():
        valueWithoutPrefix = valueWithoutPrefix[1:]

    # Prendi solo maiuscole dalla parte restante
    uppercase_chars = "".join(char for char in valueWithoutPrefix if char.isupper())

    if len(uppercase_chars) >= 3:
        return uppercase_chars[:3]
    else:
        # Cerca underscore non all'inizio
        if "_" in valueWithoutPrefix[1:]:  # underscore non all'inizio
            parts = valueWithoutPrefix.split("_", 1)  # Estrae parte dopo underscore
            if parts[1]:  # esiste qualcosa dopo l'underscore
                return (
                    parts[0][:3].upper() + "-" + parts[1][:1].upper()
                )  # limita a tre caratteri prima dell’underscore e accoda la prima lettera dopo l’underscore rendendola maiuscola.

        return valueWithoutPrefix.upper()[:3]


# Definizione del filtro per correlation_id
class CorrelationIdFilter(logging.Filter):
    """Il filtro CorrelationIdFilter prende la correlation_id dalla request corrente di Flask tramite g.correlation_id.
    g è un oggetto globale di Flask valido solo per la richiesta corrente.
    Prima che arrivi ogni richiesta, il middleware @app.before_request imposta g.correlation_id con il valore
    dell'header HTTP X-Correlation-ID. Se la request non ha quell'header, mette "N/A"."""

    def filter(self, record):
        # Prova a leggere la correlation_id dalla request, altrimenti None
        if has_app_context():
            record.correlation_id = getattr(g, "correlation_id", "N/A")
        else:
            record.correlation_id = "N/A"
        return True


# --- Caricamento config e logging ---
config_path = os.path.join(os.getcwd(), CONFIG_DIR, "config.json")
try:
    with open(config_path) as f:
        config_data = json.load(f)
        app.config.update(config_data)

    # Configura logging se presente nella config
    if "logging" in config_data:
        logging.config.dictConfig(config_data["logging"])
        logger = logging.getLogger(__name__)
        logger.info("✅ Logging configurato da config.json")
    else:
        # fallback logging base
        logging.basicConfig(level=logging.INFO)
        logger = logging.getLogger(__name__)
        logger.warning("⚠️ Nessuna configurazione logging trovata, uso default")

except Exception as e:
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    # codeql[py/log-injection]
    logger.error("❌ Errore caricamento configurazione: %s", sanitize_for_logging(str(e)))

# Registrazione dei blueprint
app.register_blueprint(main_routes)
app.register_blueprint(wallet_routes)
app.register_blueprint(itwallet_routes)

if __name__ == "__main__":
    # Recupera host e porta dalle variabili d'ambiente Flask se presenti, altrimenti usa default
    host = os.environ.get("FLASK_RUN_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_RUN_PORT", 8080))

    logger.info("🚀 Avvio dell'app Flask...")
    # codeql[py/log-injection]
    logger.info(
        "🌐 L'app è accessibile all'indirizzo: http://localhost:%s (o http://<docker-host-ip>:%s)",
        sanitize_for_logging(port),
        sanitize_for_logging(port),
    )

    app.run(host=host, port=port, debug=True, use_reloader=False)
