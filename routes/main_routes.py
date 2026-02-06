import os
from flask import Blueprint, current_app, render_template, send_from_directory, session, redirect, url_for
from state import app_state

main_routes = Blueprint("main_routes", __name__)

@main_routes.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(current_app.root_path, 'static'),
        'images/wallet_logo.svg',
        mimetype='image/svg+xml'
    )

@main_routes.app_errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@main_routes.app_errorhandler(500)
def internal_error(e):
    return render_template("500.html"), 

@main_routes.route("/.well-known/appspecific/com.chrome.devtools.json")
def devtools_config():
    return "", 204  # No Content, ma evita il 404

@main_routes.route("/debug/session")
def debug_session():
    return dict(session)

@main_routes.route("/")
def index():
    if not app_state.stored_hashed_pin:
        return redirect(url_for("wallet_routes.show_activation"))
    if session.get("pin_authenticated"):
        return redirect(url_for("wallet_routes.wallet_home"))
    return redirect(url_for("wallet_routes.wallet_access"))