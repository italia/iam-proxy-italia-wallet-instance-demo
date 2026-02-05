import json
import logging
from datetime import datetime
from urllib.parse import urlparse

from flask import Blueprint, current_app, g, jsonify, render_template, request, session

from constants import (
    CONTENT_PDF_BASE_64_PREFIX,
    EU_COUNTRIES,
    IDP_VALID,
    ISO_18013_5_NAME,
    MSO_MDOC_PREFIX,
    SD_JWT_PREFIX,
)
from service.itwallet_service import ItWalletService
from state import app_state
from utils.itwalletUtils import get_status_description
from utils.utils import (
    estrai_parametro_query_string,
    estrai_testo_from_dati_pdf_base64,
    extract_claim,
    guess_credential_configuration_icon,
)

logger = logging.getLogger(__name__)

itwallet_routes = Blueprint("itwallet_routes", __name__)

# Esempio di middleware per impostare la correlation_id per ogni request
@itwallet_routes.before_request
def set_correlation_id():
    g.correlation_id = request.headers.get("X-Correlation-ID", "default-id")

@itwallet_routes.after_request
def add_charset_to_json(response):
    if response.content_type.startswith("application/json"):
        response.headers["Content-Type"] = "application/json; charset=utf-8"
    return response

@itwallet_routes.route("/itwallet/reset", methods=["GET"])
def wallet_reset():
    """
    Route per resettare l'IT Wallet.

    La rispota è nel formato:
        {
            "success": true
        }
    e in caso di errore:
        {
            "success": false,
            "data": {
                "error": "Parametro 'country' mancante"
            }
        }
    """
    _clear_session()

    logger.info("➡️  Ricevuta request GET /itwallet/reset")

    try:
        # Svuota la memoria del wallet ma non la sessione
        app_state.credential_store.clear()
        app_state.selected_country = ""
        app_state.wallet_initialized = False

        logger.info("✅ Il Wallet è stato resettato correttamente")
        return jsonify({"success": True}), 200
    except Exception as e:
        logger.error(f"❌ {e}")
        return jsonify({"success": False, "data": {"error": f"{e}"}}), 500

@itwallet_routes.route("/itwallet/cb", methods=["GET"])
def wallet_callback():
    # Converte request.args in lista ordinata di tuple
    params_list = list(request.args.items())

    if params_list:
        logger.info("➡️  Ricevuta request GET /itwallet/cb con query string:")
        for k, v in params_list:
            logger.info(f"   {k} = {v}")
    else:
        logger.info("➡️  Ricevuta request GET /itwallet/cb senza query string")

    # Salva i parametri in sessione come dict
    session["query_params"] = dict(params_list)

    return render_template("wallet_cb.html")

@itwallet_routes.route("/itwallet/init", methods=["GET"])
def initItWallet():
    """
    Route per inizializzare l'IT Wallet con parametri obbligatori via query string (es: ?country=IT&idp=CIE3).
    La rispota è nel formato:
        {
            "success": true,
            "data": {
                "redirect_url": <authorization_url>
            }
        }
    e in caso di errore:
        {
            "success": false,
            "data": {
                "error": "Parametro 'country' mancante"
            }
        }
    """
    _clear_session()

    logger.info("➡️  Ricevuta request GET /itwallet/init")

    try:
        # Recupera parametro obbligatorio 'country' dalla query string
        country = request.args.get("country")
        if not country:
            raise ValueError("Parametro 'country' mancante")

        country = country.upper()

        if country not in EU_COUNTRIES:
            raise ValueError(f"Parametro 'country' valorizzato con il paese '{country}' non riconosciuto come membro UE")

        # Recupera parametro obbligatorio 'country' dalla query string
        idp = request.args.get("idp")
        if not idp:
            raise ValueError("Parametro 'idp' mancante")

        idp = idp.upper()

        if idp not in IDP_VALID:
            raise ValueError(f"Parametro 'idp' valorizzato con il valore '{idp}' non riconosciuto")

        # Salvataggio in memoria del country e dell'idp selezionato
        app_state.selected_country = country
        app_state.selected_idp = idp

        service = ItWalletService(session)
        result = service.initialize_wallet(idp=idp, country=country)

        status_code = 200 if result["success"] else 500
        return jsonify(result), status_code

    except ValueError as ve:
        logger.error(f"❌ {ve}")
        return jsonify({"success": False, "data": {"error": f"{ve}"}}), 400
    except Exception as e:
        logger.error(f"❌ {e}")
        return jsonify({"success": False, "data": {"error": f"{e}"}}), 500

@itwallet_routes.route("/itwallet/init/complete", methods=["GET"])
def completedInitItWallet():
    """
    Route per finalizzare l'inizializzazione dell'IT Wallet.
    La risposta è nel formato:
        {
            "success": true,
            "data": {
                "message": "Wallet inizializzato con successo",
            }
        }
    e in caso di errore:
        {
            "success": false,
            "data": {
                "error": "Errore interno imprevisto"
            }
        }
    """
    logger.info("➡️  Ricevuta request GET /itwallet/init/complete")

    try:
        service = ItWalletService(session)
        result = service.complete_initialize_wallet()

        status_code = 200 if result["success"] else 500
        return jsonify(result), status_code

    except ValueError as ve:
        logger.error(f"❌ {ve}")
        return jsonify({"success": False, "data": {"error": f"{ve}"}}), 400
    except Exception as e:
        logger.error(f"❌ {e}")
        return jsonify({"success": False, "data": {"error": f"{e}"}}), 500

@itwallet_routes.route("/itwallet/credentialSupported", methods=["GET"])
def credentialSupported():
    """
    Route per recuperare le tipologie di credenziali supportate dall'IT Wallet.
    La rispota è nel formato:
        {
            "success": true,
            "data": <JSON Array>
        }
    e in caso di errore:
        {
            "success": false,
            "data": {
                "error": "Errore interno imprevisto"
            }
        }
    """
    logger.info("➡️  Ricevuta request GET /itwallet/credentialSupported")

    try:
        # Recupera credendenziali supportate dal wallet
        wallet_credentialSupported = extract_claim(current_app.config,"metadata.credential_flow.credential_configurations_supported")
        if not wallet_credentialSupported:
            raise ValueError("Nessuna tipologia credendenziale configurata")

        wallet_credentialSupported_list = list(wallet_credentialSupported)

        logger.info("✅ Tipologie di credenziali supportate dal wallet:")
        for c in wallet_credentialSupported_list:
            logger.info(f" - {c}")

        logger.info(f"ℹ️  Nel wallet hai al momento: {app_state.credential_store.keys_with_vct()}")

        # Genera lista di dizionari
        result = []
        for credential_configurations_id in wallet_credentialSupported_list:
            result.append({
                "id": credential_configurations_id,
                "label": credential_configurations_id,
                "icon": guess_credential_configuration_icon(credential_configurations_id)
            })

        return jsonify({
            "success": True,
            "data": result
        }), 200

    except ValueError as ve:
        logger.error(f"❌ {ve}")
        return jsonify({"success": False, "data": {"error": f"{ve}"}}), 400
    except Exception as e:
        logger.error(f"❌ {e}")
        return jsonify({"success": False, "data": {"error": f"{e}"}}), 500

@itwallet_routes.route("/itwallet/objectTypesInMemory", methods=["GET"])
def objectTypesInMemory():
    """
    Route per recuperare le tipologie di oggetti presenti nella memoria del Wallet.
    La risposta è nel formato:
        {
            "success": true,
            "data": <JSON Array>
        }
    e in caso di errore:
        {
            "success": false,
            "data": {
                "error": "Errore interno imprevisto"
            }
        }
    """
    logger.info("➡️  Ricevuta request GET /itwallet/objectTypesInMemory")

    try:
        # Recupera tipologie di oggetti presenti nella memoria del Wallet.
        objectTypesInMemory = app_state.get_store_types()

        logger.info(f"✅ Tipologie di oggetti presenti nella memoria del Wallet:  {objectTypesInMemory}")

        return jsonify({
            "success": True,
            "data": objectTypesInMemory
        }), 200

    except Exception as e:
        logger.error(f"❌ {e}")
        return jsonify({"success": False, "data": {"error": f"{e}"}}), 500

@itwallet_routes.route("/itwallet/viewObjectTypeInMemory", methods=["POST"])
def viewObjectTypeInMemory():
    """
    Route per visualizzare una specifica tipologia di oggetto presente nella memoria del Wallet.
    La risposta è nel formato:
        {
            "success": true,
            "data": <JSON Array>
        }
    e in caso di errore:
        {
            "success": false,
            "data": {
                "error": "Errore interno imprevisto"
            }
        }
    """
    _clear_session()

    logger.info("➡️  Ricevuta request POST /itwallet/viewObjectInMemory")

    try:
        data = request.get_json()  # <-- recupera il JSON dal body della richiesta
        logger.info(f"{data}")

        # Verifica presenza della chiave objectType
        objectTypeValue = data.get("objectType")
        if not objectTypeValue:
            return jsonify({"success": False, "data": {"error": "Missing request parameter 'objectType'"}}), 400

        # Recupera il contenuto dell'oggetto richiesto (lista di valori).
        result = app_state.get_store(objectTypeValue)

        logger.info(f"✅ Recuperato oggetto di tipo {objectTypeValue} dalla memoria del Wallet")
        logger.debug(json.dumps(result, indent=2, ensure_ascii=False))

        return jsonify({
            "success": True,
            "data": result
        }), 200

    except Exception as e:
        logger.error(f"❌ {e}")
        return jsonify({"success": False, "data": {"error": f"{e}"}}), 500

@itwallet_routes.route("/itwallet/onboardedRelyingParties", methods=["GET"])
def onboardedRelyingParties():
    """
    Route per recuperare i Relying Parties onboardati.
    La risposta è nel formato:
        {
            "success": true,
            "data": <JSON Array>
        }
    e in caso di errore:
        {
            "success": false,
            "data": {
                "error": "Errore interno imprevisto"
            }
        }
    """
    logger.info("➡️  Ricevuta request GET /itwallet/onboardedRelyingParties")

    try:
        # Recupera Relying Parties onboardati
        service = ItWalletService(session)
        result = service.getOnboardedRelyingParties()

        if result["success"]:
            onboardedRelyingParties = list(result["data"])

            logger.info("✅ Relying Party onboardati:")
            for rp in onboardedRelyingParties:
                logger.info(f" - {rp}")

            # Genera lista di dizionari
            result = []
            for rp in onboardedRelyingParties:
                result.append({
                    "id": rp,
                    "label": rp,
                    "icon": "🏛️"
                })

            return jsonify({
                "success": True,
                "data": result
            }), 200

        else:
            return jsonify(result), 500
    except ValueError as ve:
        logger.error(f"❌ {ve}")
        return jsonify({"success": False, "data": {"error": f"{ve}"}}), 400
    except Exception as e:
        logger.error(f"❌ {e}")
        return jsonify({"success": False, "data": {"error": f"{e}"}}), 500

@itwallet_routes.route("/itwallet/deleteCredential", methods=["POST"])
def deleteCredentialItWallet():
    """
    Route per aggiungere una credenziale all'IT Wallet.
    La rispota è nel formato:
        {
            "success": true,
            "data": {
                "credential_id": <credential_id>,
                "wallet_initialized": True|False,
            }
        }
    e in caso di errore:
        {
            "success": false,
            "data": {
                "error": "Errore interno imprevisto"
            }
        }
    """

    _clear_session()

    logger.info("➡️  Ricevuta request POST /itwallet/deleteCredential")

    try:
        data = request.get_json()  # <-- recupera il JSON dal body della richiesta
        logger.info(f"{data}")

        # Verifica presenza della chiave credentialId
        credential_id = data.get("credentialId")
        if not credential_id:
            return jsonify({"success": False, "data": {"error": "Missing request parameter 'credentialId'"}}), 400

        service = ItWalletService(session)
        result = service.delete_credential_wallet(credential_id)

        status_code = 200 if result["success"] else 500
        return jsonify(result), status_code

    except ValueError as ve:
        logger.error(f"❌ {ve}")
        return jsonify({"success": False, "data": {"error": f"{ve}"}}), 400
    except Exception as e:
        logger.error(f"❌ {e}")
        return jsonify({"success": False, "data": {"error": f"{e}"}}), 500

@itwallet_routes.route("/itwallet/addCredential", methods=["POST"])
def addCredentialItWallet():
    """
    Route per aggiungere una credenziale all'IT Wallet.
    La rispota è nel formato:
        {
            "success": true,
            "data": <JSON Array>
        }
    e in caso di errore:
        {
            "success": false,
            "data": {
                "error": "Errore interno imprevisto"
            }
        }
    """
    _clear_session()

    logger.info("➡️  Ricevuta request POST /itwallet/addCredential")

    try:
        data = request.get_json()  # <-- recupera il JSON dal body della richiesta
        logger.info(f"{data}")

        # Verifica presenza della chiave credentialId
        credential_configuration_id = data.get("credentialId")
        if not credential_configuration_id:
            return jsonify({"success": False, "data": {"error": "Missing request parameter 'credentialId'"}}), 400

        service = ItWalletService(session)
        result = service.add_credential_wallet(credential_configuration_id)

        status_code = 200 if result["success"] else 500
        return jsonify(result), status_code

    except ValueError as ve:
        logger.error(f"❌ {ve}")
        return jsonify({"success": False, "data": {"error": f"{ve}"}}), 400
    except Exception as e:
        logger.error(f"❌ {e}")
        return jsonify({"success": False, "data": {"error": f"{e}"}}), 500

@itwallet_routes.route("/itwallet/addCredential/complete", methods=["POST"])
def completedAddCredentialItWallet():
    """
    Route per completare l'aggiunta di una credenziale all'IT Wallet.
    La risposta è nel formato:
        {
            "success": true,
            "data": {
                "message": "Credenziale aggiunta con successo",
                ...
            }
        }
    e in caso di errore:
        {
            "success": false,
            "data": {
                "error": "Errore interno imprevisto"
            }
        }
    """
    logger.info("➡️  Ricevuta request POST /itwallet/addCredential/complete")

    try:
        data = request.get_json()  # <-- recupera il JSON dal body della richiesta
        logger.info(f"{data}")

        # Verifica presenza del parametro credentialsPresenting
        credentials_presenting = data.get("credentialsPresenting")
        if not credentials_presenting:
            raise ValueError("La richiesta non presenta il parametro 'credentialsPresenting'")

        if not isinstance(credentials_presenting, list):
            raise ValueError("Il calore del parametro 'credentialsPresenting' fornito nella richiesta presenta un formato non valido")


        service = ItWalletService(session)
        result = service.complete_add_credential_wallet(credentials_presenting)

        status_code = 200 if result["success"] else 500
        return jsonify(result), status_code

    except ValueError as ve:
        logger.error(f"❌ {ve}")
        return jsonify({"success": False, "data": {"error": f"{ve}"}}), 400
    except Exception as e:
        logger.error(f"❌ {e}")
        return jsonify({"success": False, "data": {"error": f"{e}"}}), 500

@itwallet_routes.route("/itwallet/loginToRelyingParty", methods=["POST"])
def loginToRelyingParty():
    """
    Route per autenticarsi ad un Relying Party.
    La risposta è nel formato:
        {
            "success": true,
            "data": <JSON Array>
        }
    e in caso di errore:
        {
            "success": false,
            "data": {
                "error": "Errore interno imprevisto"
            }
        }
    """
    _clear_session()

    logger.info("➡️  Ricevuta request POST /itwallet/loginToRelyingParty")

    try:
        data = request.get_json()  # <-- recupera il JSON dal body della richiesta
        logger.info(f"{data}")

        relyingPartyId = data.get("relyingPartyId")
        qrCodeContent = data.get("qrCodeContent")

        relyingPartyIdParsed = urlparse(relyingPartyId)
        # Verifica se relyingPartyId è un URL valido
        if relyingPartyIdParsed.scheme and relyingPartyIdParsed.netloc:
            logger.info(f"✅ L'ID del Relying Party selezionato è un URL valido {relyingPartyId}")

            qrCodeContentParsed = urlparse(qrCodeContent)

            # Verifica se qrCodeContentParsed è un URL valido
            if qrCodeContentParsed.scheme and qrCodeContentParsed.netloc:
                logger.info(f"✅ Il contenuto del QR Code è un URL valido: {qrCodeContent}")

                clientId = estrai_parametro_query_string(qrCodeContent, "client_id")
                if not clientId:
                    raise ValueError("L'URL specificata nel QR Code non presenta il parametro 'client_id' in query string")

                if clientId != relyingPartyId:
                    raise ValueError(f"L'URL specificata nel QR Code presenta il parametro 'client_id' in query string il cui valore non è valido: atteso '{relyingPartyId}', trovato '{clientId}'")

                requestUri = estrai_parametro_query_string(qrCodeContent, "request_uri")
                if not requestUri:
                    raise ValueError("L'URL specificata nel QR Code non presenta il parametro 'request_uri' in query string")

                requestUriMethod = estrai_parametro_query_string(qrCodeContent, "request_uri_method")
                if not requestUriMethod:
                    requestUriMethod="get"

                state = estrai_parametro_query_string(qrCodeContent, "state")
                if not requestUri:
                    raise ValueError("L'URL specificata nel QR Code non presenta il parametro 'state' in query string")

            else:
                raise ValueError(f"Il contenuto del QR Code non è un URL valido: {qrCodeContent}")

        else:
            raise ValueError(f"L'ID del Relying Party selezionato non è un URL valido: {relyingPartyId}")

        service = ItWalletService(session)
        result = service.loginToVerifier(clientId, requestUri, requestUriMethod, state)

        status_code = 200 if result["success"] else 500
        return jsonify(result), status_code
    except ValueError as ve:
        logger.error(f"❌ {ve}")
        return jsonify({"success": False, "data": {"error": f"{ve}"}}), 400
    except Exception as e:
        logger.error(f"❌ {e}")
        return jsonify({"success": False, "data": {"error": f"{e}"}}), 500

@itwallet_routes.route("/itwallet/loginToVerifier/complete", methods=["POST"])
def completedLoginToVerifier():
    """
    Route per completare l'autenticazione a un verifier.
    La risposta è nel formato:
        {
            "success": true
        }
    e in caso di errore:
        {
            "success": false,
            "data": {
                "error": "Errore interno imprevisto"
            }
        }
    """
    logger.info("➡️  Ricevuta request POST /itwallet/loginToVerifier/complete")

    try:
        data = request.get_json()  # <-- recupera il JSON dal body della richiesta
        logger.info(f"{data}")

        # Verifica presenza del parametro credentialsPresenting
        credentials_presenting = data.get("credentialsPresenting")
        if not credentials_presenting:
            raise ValueError("La richiesta non presenta il parametro 'credentialsPresenting'")

        if not isinstance(credentials_presenting, list):
            raise ValueError("Il calore del parametro 'credentialsPresenting' fornito nella richiesta presenta un formato non valido")

        service = ItWalletService(session)
        result = service.complete_loginToVerifier(credentials_presenting)

        status_code = 200 if result["success"] else 500
        return jsonify(result), status_code

    except ValueError as ve:
        logger.error(f"❌ {ve}")
        return jsonify({"success": False, "data": {"error": f"{ve}"}}), 400
    except Exception as e:
        logger.error(f"❌ {e}")
        return jsonify({"success": False, "data": {"error": f"{e}"}}), 500

@itwallet_routes.route("/itwallet/template/<credentialType>", methods=["GET"])
def credentialTypeTemplate(credentialType):
    _clear_session()

    logger.info(f"➡️  Ricevuta request GET /itwallet/template/{credentialType}")

    result = app_state.credential_store.find_by_prefix_with_key(credentialType)

    if result:
        key, value = result
        logger.info(f"✅ Recuperata dalla memoria credenziale con chiave {key}")

        vct = value.get("vct", "")
        logger.info(f"ℹ️  Il vct della credenziale {key} è: {vct}")

        status = value.get("status", "")
        statusDecr = get_status_description(status)
        logger.info(f"ℹ️  La credenziale {key} è in stato: {status} {statusDecr}")

        claims = value.get("claims", {})
        claims = unescape_json(claims)

        data_row = value.get("data_row", {})

        issuing_country = ""
        issuing_authority = ""

        content = claims.get("content")

        contentList = []

        if content and content.startswith(CONTENT_PDF_BASE_64_PREFIX):
            logger.debug("ℹ️  La credenziale presenta un claim 'content' contenente dati pdf_base64")
            contentList = estrai_testo_from_dati_pdf_base64(content)

            if contentList and len(contentList) > 0:
                logger.debug("✅ Il PDF contiene almeno una pagina con contenuto.")
                for i, pagina in enumerate(contentList, start=1):
                    logger.debug(f"📄 Pagina {i}:\n{pagina}\n{'-'*40}")

        dt_iat_local_formatted = dt_exp_local_formatted = None
        metadata = ""

        if key.startswith(MSO_MDOC_PREFIX):
            name_space = claims.get("nameSpaces", {}).get(ISO_18013_5_NAME, {})
            issuing_country = name_space.get("issuing_country")
            issuing_authority = name_space.get("issuing_authority")

            validity_info = claims.get("mso", {}).get("validityInfo", {})
            iat = validity_info.get("validFrom") #stringa in formato ISO 8601 con timezone UTC
            exp = validity_info.get("validUntil") #stringa in formato ISO 8601 con timezone UTC

            try:
                # Parsing della stringa in oggetto datetime con timezone UTC
                dt_iat_utc = datetime.fromisoformat(iat)
                dt_exp_utc = datetime.fromisoformat(iat)

                # Conversione nel timezone locale (esempio: Europe/Rome)
                local_tz = datetime.now().astimezone().tzinfo
                dt_iat_local = dt_iat_utc.astimezone(local_tz)
                dt_exp_local = dt_exp_utc.astimezone(local_tz)

                # Formattazione finale come dd-mm-yyyy HH:MM:SS
                dt_iat_local_formatted = dt_iat_local.strftime("%d-%m-%Y %H:%M:%S")
                dt_exp_local_formatted = dt_exp_local.strftime("%d-%m-%Y %H:%M:%S")
            except (TypeError, ValueError):
                dt_iat_local_formatted = dt_exp_local_formatted = None
                logger.error(f"❌ Non è stato possibile leggere l'intervallo di validità della credenziale {key}")

        elif key.startswith(SD_JWT_PREFIX):
            issuing_country = claims.get("issuing_country")
            issuing_authority = claims.get("issuing_authority")
            iat = claims.get("iat") #int in formato unix time stamp con timezone UTC
            exp = claims.get("exp") #int in formato unix time stamp con timezone UTC

            try:
                dt_iat_utc = datetime.fromtimestamp(int(iat))
                dt_exp_utc = datetime.fromtimestamp(int(exp))

                # Conversione nel timezone locale (esempio: Europe/Rome)
                local_tz = datetime.now().astimezone().tzinfo
                dt_iat_local = dt_iat_utc.astimezone(local_tz)
                dt_exp_local = dt_exp_utc.astimezone(local_tz)

                # Formattazione finale come dd-mm-yyyy HH:MM:SS
                dt_iat_local_formatted = dt_iat_local.strftime("%d-%m-%Y %H:%M:%S")
                dt_exp_local_formatted = dt_exp_local.strftime("%d-%m-%Y %H:%M:%S")

            except (TypeError, ValueError):
                dt_iat_local_formatted = dt_exp_local_formatted = None
                logger.error(f"❌ Non è stato possibile leggere l'intervallo di validità della credenziale {key}")

        if dt_iat_local_formatted and dt_exp_local_formatted:
            metadata = f"Credenziale emessa da {issuing_authority} ({issuing_country}) il {dt_iat_local_formatted}, scade il {dt_exp_local_formatted}."
        else:
            metadata = f"Credenziale emessa da {issuing_authority} ({issuing_country})"

        logger.info(f"ℹ️  Il metadata della credenziale {key} è: {metadata}")

        try:
            templateContent = render_template(credentialType+".html", data_row=data_row, claims=claims, metadata=metadata, status=status, statusDecr=statusDecr, contentList=contentList)
            return templateContent
        except Exception as e:
            logger.error(f"❌ {e}")
            return f"Nessun template trovato per la credenziale di tipo {credentialType} nel wallet", 500
    else:
        logger.error(f"❌ Nessuna credenziale di tipo {credentialType} trovata nella memoria")
        return f"Nessuna credenziale di tipo {credentialType} trovata nel wallet", 400

def _clear_session():
    # Salva le chiavi da preservare
    preserved = {
        "session_id": session.get("session_id"),
        "pin_authenticated": session.get("pin_authenticated")
    }

    # Pulisce la sessione
    session.clear()

    # Ripristina le chiavi
    session.update({k: v for k, v in preserved.items() if v is not None})


def unescape_json(value):
    """Rimuove gli escape da stringhe JSON e converte in dict se necessario."""
    if isinstance(value, str):
        try:
            # Prova a interpretare la stringa come JSON (se contiene escape)
            return json.loads(value)
        except json.JSONDecodeError:
            # Non era un JSON valido, restituisce la stringa originale
            return value
    elif isinstance(value, dict):
        # Applica ricorsivamente ai valori del dizionario
        return {k: unescape_json(v) for k, v in value.items()}
    elif isinstance(value, list):
        # Applica ricorsivamente agli elementi della lista
        return [unescape_json(v) for v in value]
    else:
        return value
