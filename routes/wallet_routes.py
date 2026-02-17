import logging

import bcrypt
from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for

from state import app_state
from utils.utils import generate_nonce, sanitize_for_logging

logger = logging.getLogger(__name__)

wallet_routes = Blueprint("wallet_routes", __name__)


@wallet_routes.route("/wallet/activate", methods=["GET"])
def show_activation():
    return render_template("wallet_activation.html")


@wallet_routes.route("/wallet/activate", methods=["POST"])
def activate_wallet():
    pin = request.form.get("pin")
    confirm = request.form.get("confirm_pin")
    if pin != confirm or not pin.isdigit() or not (4 <= len(pin) <= 8):
        flash("PIN non valido o non corrispondente", "error")
        return redirect(url_for("wallet_routes.show_activation"))

    # Hasha il PIN e salvalo nella memoria Flask
    app_state.stored_hashed_pin = bcrypt.hashpw(pin.encode(), bcrypt.gensalt())
    flash("Wallet attivato correttamente!", "success")

    return redirect(url_for("wallet_routes.wallet_access"))


@wallet_routes.route("/wallet/access", methods=["GET", "POST"])
def wallet_access():
    if request.method == "POST":
        pin_attempt = request.form.get("pin_attempt", "")

        if not pin_attempt:
            return render_template("wallet_access.html")

        if app_state.stored_hashed_pin and bcrypt.checkpw(pin_attempt.encode(), app_state.stored_hashed_pin):
            # Salvataggio in sessione pin_authenticated=True
            session["pin_authenticated"] = True

            # Creo nuovo ID di sessione, lo salvo in sessione e lo uso come correlation id per i log
            session_id = generate_nonce()
            session["session_id"] = session_id

            # codeql[py/log-injection]
            logger.info("✅ Effettuato login (sessione inizializzata id=%s).", sanitize_for_logging(session_id))

            return redirect(url_for("wallet_routes.wallet_home", session_id=session_id))
        else:
            logger.error("❌ Login fallito: PIN errato")
            flash("PIN errato. Riprova.", "error")

    return render_template("wallet_access.html")


@wallet_routes.route("/wallet/home", methods=["GET"])
def wallet_home():
    session_id = request.args.get("session_id", "")
    selected_country = app_state.selected_country
    wallet_initialized = app_state.wallet_initialized
    credential_store = app_state.credential_store

    # Ottieni tutte le chiavi delle credenziali
    credential_keys = credential_store.keys()

    if not session.get("pin_authenticated"):
        return redirect(url_for("wallet_routes.wallet_access"))

    return render_template(
        "wallet_home.html",
        session_id=session_id,
        selected_country=selected_country,
        wallet_initialized=wallet_initialized,
        credential_keys=credential_keys,
    )


@wallet_routes.route("/wallet/logout", methods=["GET"])
def logout():
    session_id = session.get("session_id", "")
    # codeql[py/log-injection]
    logger.info("✅ Effettuato logout (sessione cancellata id=%s).", sanitize_for_logging(session_id))

    # Svuota la sessione
    session.clear()

    # flash("Logout effettuato con successo.", "success")
    return redirect(url_for("wallet_routes.wallet_access"))
