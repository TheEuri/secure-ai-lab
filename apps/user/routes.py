from flask import (
    abort,
    make_response,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from apps.user import user_bp

from common.session import (
    csrf_protect,
    create_session,
    get_current_user,
    revoke_user_sessions,
    set_session_cookie,
)
from common.security_audit import record_security_event
from common.file_integrity import (
    AvatarPersistenceError,
    AvatarValidationError,
    canonical_avatar_path,
)

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
    avatar_path = canonical_avatar_path(user_id)
    if avatar_path.is_file():
        return send_from_directory(str(avatar_path.parent), avatar_path.name)
    return redirect(url_for("user.static", filename="img/default-avatar.svg"))


@user_bp.route("/profile/edit_password", methods=["POST"])
@csrf_protect
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
@csrf_protect
def edit_avatar():
    current = get_current_user()
    if not current:
        return redirect("/login")
    target_id = current["id"]
    if "user_id" in request.form:
        supplied_target_id = request.form.get("user_id", type=int)
        if supplied_target_id != target_id:
            abort(403)

    file = request.files.get("avatar")
    if not file:
        return redirect("/profile")

    try:
        update_avatar_file(target_id, file)
    except AvatarValidationError as exc:
        if exc.status_code == 413:
            return "Avatar excede o limite permitido.", 413
        return "Avatar inválido.", 400
    except AvatarPersistenceError:
        # Replacement and digest persistence are separate resources.  Surface
        # failure without claiming success or exposing storage details.
        return "Não foi possível atualizar o avatar.", 500
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
@csrf_protect
def edit_bio():
    current = get_current_user()
    if not current:
        return redirect("/login")
    target_id = current["id"]
    if "user_id" in request.form:
        supplied_target_id = request.form.get("user_id", type=int)
        if supplied_target_id != target_id:
            abort(403)

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
