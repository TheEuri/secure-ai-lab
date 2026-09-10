
from urllib.parse import urlsplit

from flask import abort, redirect, render_template, request, url_for

from apps.root import root_bp
from apps.root.logic.root import (
    delete_reply,
    delete_topic_and_replies,
    get_admin_dashboard_data,
)
from common.session import get_current_user


def _origin_parts(value, *, allow_path=False):
    """Return a normalized origin tuple only for a verifiable HTTP(S) URL."""
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError):
        return None

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    if not allow_path and (parsed.path or parsed.query or parsed.fragment):
        return None

    effective_port = port
    if effective_port is None:
        effective_port = 443 if scheme == "https" else 80
    return scheme, parsed.hostname.lower(), effective_port


def _has_same_origin_request():
    expected_origin = _origin_parts(request.url_root, allow_path=True)
    if expected_origin is None:
        return False

    if "Origin" in request.headers:
        return _origin_parts(request.headers.get("Origin")) == expected_origin

    referer = request.headers.get("Referer")
    if not referer:
        return False
    return _origin_parts(referer, allow_path=True) == expected_origin


def _require_admin():
    current = get_current_user()
    if not current:
        return None, redirect("/login")
    if current.get("role") != "admin":
        abort(403)
    return current, None


@root_bp.route("/admin")
def admin_dashboard():
    current, denial = _require_admin()
    if denial:
        return denial
    return render_template(
        "admin.html",
        user=current,
        dashboard=get_admin_dashboard_data(),
        page="admin",
    )


@root_bp.route("/admin/topics/<int:topic_id>/delete", methods=["POST"])
def delete_admin_topic(topic_id):
    _, denial = _require_admin()
    if denial:
        return denial
    if not _has_same_origin_request():
        abort(403)
    delete_topic_and_replies(topic_id)
    return redirect(url_for("root.admin_dashboard"))


@root_bp.route("/admin/replies/<int:reply_id>/delete", methods=["POST"])
def delete_admin_reply(reply_id):
    _, denial = _require_admin()
    if denial:
        return denial
    if not _has_same_origin_request():
        abort(403)
    delete_reply(reply_id)
    return redirect(url_for("root.admin_dashboard"))
