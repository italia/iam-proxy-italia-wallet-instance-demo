import os
import socketserver
import ssl
import sys

from werkzeug.serving import BaseWSGIServer

from app import create_app
from app.constants import APP_SETTINGS_KEY

sys.stdout.reconfigure(encoding="utf-8")

app = create_app()


class ThreadedTLSServer(socketserver.ThreadingMixIn, BaseWSGIServer):
    """Accept plain TCP immediately and finish TLS on a worker thread.

    Werkzeug wraps the listening socket, so one stalled handshake blocks every
    other connection. The browser keeps such a connection open.
    """

    multithread = True
    daemon_threads = True

    def __init__(self, host: str, port: int, wsgi_app, tls_context: ssl.SSLContext):
        super().__init__(host, port, wsgi_app)
        self.ssl_context = tls_context

    def finish_request(self, request, client_address):
        try:
            request.settimeout(10)
            tls_conn = self.ssl_context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, TimeoutError, OSError):
            try:
                request.close()
            except OSError:
                pass
            return None
        return super().finish_request(tls_conn, client_address)


if __name__ == "__main__":
    app_config = app.config[APP_SETTINGS_KEY].app
    app.logger.info("Initializing Flask application...")
    host = app_config.host or "0.0.0.0"
    port = app_config.port or 8080
    tls_cert = os.environ.get("WALLET_TLS_CERT")
    tls_key = os.environ.get("WALLET_TLS_KEY")
    if tls_cert and tls_key:
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.load_cert_chain(tls_cert, tls_key)
        server = ThreadedTLSServer(host, port, app, tls_context)
        server.log_startup()
        server.serve_forever()
    else:
        app.run(host=host, port=port, debug=app_config.debug_mode, use_reloader=False, threaded=True)
