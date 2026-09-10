from flask import Flask, send_from_directory, request, render_template
from pathlib import Path
from apps.lobby import lobby_bp
from apps.user import user_bp
from apps.direct import direct_bp
from apps.board import board_bp
from apps.root import root_bp
from common.database import register_cli_commands
from common.session import get_current_user

BASE_DIR = Path(__file__).resolve().parent

app = Flask(__name__)
app.config.from_mapping(
    DATABASE=BASE_DIR / 'data' / 'secureboard.db',
    AVATAR_DIR=BASE_DIR / 'static' / 'img' / 'avatars',
    SESSION_LIFETIME_SECONDS=3600,
    SESSION_COOKIE_SECURE=False,
)
register_cli_commands(app)


@app.context_processor
def inject_current_user():
    """Expose only the database-authoritative role to shared templates."""
    user = get_current_user()
    if user is None:
        return {"current_user": None}
    return {"current_user": {"role": user["role"]}}

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


if __name__ == '__main__':
    app.run(debug=False, port=1337)
