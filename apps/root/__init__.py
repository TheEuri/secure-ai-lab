from flask import Blueprint

root_bp = Blueprint(
    'root',
    __name__,
    template_folder='templates',
    static_folder='static',
    static_url_path='/root_static'
)

from . import routes