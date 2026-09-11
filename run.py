from flask import Flask, send_from_directory, request, render_template
from pathlib import Path
import os
from apps.lobby import lobby_bp
from apps.user import user_bp
from apps.direct import direct_bp
from apps.board import board_bp
from apps.root import root_bp
from common.database import register_cli_commands
from common.session import get_current_csrf_token, get_current_user
from common.transport import (
    DEFAULT_SERVER_PORT,
    register_security_headers,
    register_transport_cli_commands,
    resolve_server_port,
    ssl_context_from_config,
    transport_config_from_environment,
)

BASE_DIR = Path(__file__).resolve().parent
TRANSPORT_DEFAULTS = transport_config_from_environment()

app = Flask(__name__)
app.config.from_mapping(
    DATABASE=BASE_DIR / 'data' / 'secureboard.db',
    AVATAR_DIR=BASE_DIR / 'static' / 'img' / 'avatars',
    SESSION_LIFETIME_SECONDS=3600,
    SESSION_COOKIE_SECURE=False,
    TRANSPORT_MODE=TRANSPORT_DEFAULTS["TRANSPORT_MODE"],
    TLS_CERT_FILE=TRANSPORT_DEFAULTS["TLS_CERT_FILE"],
    TLS_KEY_FILE=TRANSPORT_DEFAULTS["TLS_KEY_FILE"],
    PORT=TRANSPORT_DEFAULTS["PORT"] or DEFAULT_SERVER_PORT,
    HOST=os.environ.get("SECUREBOARD_HOST", "127.0.0.1"),
    PSEUDONYMIZATION_KEY=os.environ.get("PSEUDONYMIZATION_KEY"),
    MESSAGE_ENCRYPTION_KEY=os.environ.get("MESSAGE_ENCRYPTION_KEY"),
    AI_MODERATION_PROVIDER=os.environ.get("AI_MODERATION_PROVIDER"),
    AI_MODERATION_MODEL=os.environ.get("AI_MODERATION_MODEL"),
    OPENAI_API_KEY=os.environ.get("OPENAI_API_KEY"),
    AI_MODERATION_TIMEOUT_SECONDS=os.environ.get(
        "AI_MODERATION_TIMEOUT_SECONDS", "10"
    ),
)
register_cli_commands(app)
register_transport_cli_commands(app)
register_security_headers(app)


@app.context_processor
def inject_current_user():
    """Expose only the database-authoritative role to shared templates."""
    user = get_current_user()
    if user is None:
        return {"current_user": None}
    csrf_token = get_current_csrf_token()
    if csrf_token is None:
        return {"current_user": None}
    return {
        "current_user": {"role": user["role"]},
        "csrf_token": csrf_token,
    }

@app.route('/robots.txt')
def robots():
    return send_from_directory(app.static_folder, 'robots.txt')

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html', path=request.path), 404

app.register_blueprint(lobby_bp)
app.register_blueprint(user_bp)
app.register_blueprint(direct_bp)
app.register_blueprint(board_bp)
app.register_blueprint(root_bp)


def run_server(application=app, *, host=None, port=None, debug=False):
    """Start the local server in the explicitly configured HTTP/HTTPS mode.

    HTTPS configuration is validated before Flask starts.  In particular,
    missing or invalid certificate material raises instead of falling back to
    an insecure HTTP listener.
    """

    selected_port = resolve_server_port(
        application.config.get("PORT", DEFAULT_SERVER_PORT)
        if port is None
        else port
    )
    ssl_context = ssl_context_from_config(application.config)
    run_kwargs = {
        "debug": debug,
        "host": host or application.config.get("HOST", "127.0.0.1"),
        "port": selected_port,
        "use_reloader": False,
    }
    if ssl_context is not None:
        run_kwargs["ssl_context"] = ssl_context
    application.run(**run_kwargs)


if __name__ == '__main__':
    run_server()
