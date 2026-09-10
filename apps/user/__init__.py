from flask import Blueprint

user_bp = Blueprint(
    'user',
    __name__,
    template_folder='templates',
    static_folder='static',
    static_url_path='/user_static'
)

from . import routes