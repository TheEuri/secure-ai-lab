from flask import Blueprint

cryptolab_bp = Blueprint(
    "cryptolab",
    __name__,
    template_folder="templates",
    static_folder="static",
    static_url_path="/cryptolab_static",
)

from . import routes  # noqa: E402,F401
