from flask import Blueprint

lobby_bp = Blueprint(
    'lobby',
    __name__,
    template_folder='templates',
    static_folder='static',
    static_url_path='/lobby_static'
)

from . import routes
