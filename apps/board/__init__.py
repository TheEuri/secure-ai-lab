from flask import Blueprint

board_bp = Blueprint(
    'board',
    __name__,
    template_folder='templates',
    static_folder='static',
    static_url_path='/board_static'
)

from . import routes