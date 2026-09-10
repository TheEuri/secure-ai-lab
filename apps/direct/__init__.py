from flask import Blueprint

direct_bp = Blueprint(
    'direct',
    __name__,
    template_folder='templates',
    static_folder='static',
    static_url_path='/direct_static'
)

from . import routes