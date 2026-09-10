from pathlib import Path

from flask import (
    abort,
    current_app,
    make_response,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from apps.user import user_bp

from common.session import (
    create_session,
    get_current_user,
    revoke_user_sessions,
    set_session_cookie,
)
from common.security_audit import record_security_event

from common.users import get_user_by_username, get_user_by_id

from apps.user.logic.users import update_password, update_avatar_file, update_bio


@user_bp.route("/user/<username>")
def public_user(username):
    current = get_current_user()
    if not current:
        return redirect("/login")
    user = get_user_by_username(username)
    if not user:
        return abort(404)
    return render_template(
        "public_profile.html",
        user=user,
        is_own_profile=current["id"] == user["id"],
        page="user",
    )

@user_bp.route("/user")
def user_by_id():
    current = get_current_user()
    if not current:
        return redirect("/login")
    user_id = request.args.get("id", type=int)
    if not user_id:
        return redirect("/")
    user = get_user_by_id(user_id)
    if not user:
        return abort(404)
    return render_template(
        "public_profile.html",
        user=user,
        is_own_profile=current["id"] == user["id"],
        page="user",
    )

@user_bp.route("/profile")
def profile():
    current = get_current_user()
    if not current:
        return redirect("/login")
    return render_template(
        "edit_profile.html",
        user=current,
        is_own_profile=True,
        page="user",
    )


@user_bp.route("/user/avatar/<int:user_id>")
def avatar(user_id):
    """Present the deterministic avatar for a profile, or the local fallback."""
    avatar_dir = Path(current_app.config["AVATAR_DIR"])
    avatar_filename = f"{user_id}.jpg"
    if (avatar_dir / avatar_filename).is_file():
        return send_from_directory(str(avatar_dir), avatar_filename)
    return redirect(url_for("user.static", filename="img/default-avatar.svg"))


@user_bp.route("/profile/edit_password", methods=["POST"])
def edit_password():
    current = get_current_user()
    if not current:
        return redirect("/login")
    password = request.form.get("password")
    confirm = request.form.get("confirm")
    if not password or password != confirm:
        return redirect("/profile")
    updated = update_password(current["id"], password)
    record_security_event(
        "auth.password.changed",
        "success" if updated else "failure",
        actor_user_id=current["id"],
        target_type="user",
        target_id=current["id"],
        request_method=request.method,
        request_path=request.path,
    )
    if not updated:
        return redirect("/profile")

    revoke_user_sessions(current["id"])
    replacement_token = create_session(current["id"])
    response = make_response(redirect("/profile"))
    return set_session_cookie(response, replacement_token)

@user_bp.route("/profile/edit_avatar", methods=["POST"])
def edit_avatar():
    current = get_current_user()
    if not current:
        return redirect("/login")
    target_id = request.form.get("user_id", type=int)
    if not target_id:
        target_id = current["id"]

    file = request.files.get("avatar")
    if not file or file.filename == "":
        return redirect("/profile")

    update_avatar_file(target_id, file)
    record_security_event(
        "profile.avatar.updated",
        "success",
        actor_user_id=current["id"],
        target_type="user",
        target_id=target_id,
        request_method=request.method,
        request_path=request.path,
    )
    return redirect("/profile")

@user_bp.route("/profile/edit_bio", methods=["POST"])
def edit_bio():
    current = get_current_user()
    if not current:
        return redirect("/login")
    target_id = request.form.get("user_id", type=int)
    if not target_id:
        target_id = current["id"]

    new_bio = request.form.get("bio", "")
    updated = update_bio(target_id, new_bio)
    record_security_event(
        "profile.bio.updated",
        "success" if updated else "failure",
        actor_user_id=current["id"],
        target_type="user",
        target_id=target_id,
        request_method=request.method,
        request_path=request.path,
    )
    return redirect("/profile")
