import sys

from app import create_app
from app.constants import APP_SETTINGS_KEY

sys.stdout.reconfigure(encoding="utf-8")

app = create_app()

if __name__ == "__main__":
    app_config = app.config[APP_SETTINGS_KEY].app
    app.logger.info("Initializing Flask application...")
    app.run(
        host=app_config.host or "0.0.0.0", port=app_config.port or 8080, debug=app_config.debug_mode, use_reloader=False
    )
