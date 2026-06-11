import os
import sys

from app import create_app
from app.utils.utils import sanitize_for_logging
from settings import DEFAULT_HOST, DEFAULT_PORT

sys.stdout.reconfigure(encoding="utf-8")

app = create_app()

if __name__ == "__main__":
    host = os.environ.get("FLASK_RUN_HOST", DEFAULT_HOST)
    port = int(os.environ.get("FLASK_RUN_PORT", str(DEFAULT_PORT)))

    app.logger.info("Initializing Flask application...")
    app.logger.info(
        "Application listening on: http://localhost:%s (or http://<docker-host-ip>:%s)",
        sanitize_for_logging(port),
        sanitize_for_logging(port),
    )
    app.run(host=host, port=port, debug=True, use_reloader=False)
