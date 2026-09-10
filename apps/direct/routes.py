from flask import request, render_template, redirect, url_for
from apps.direct import direct_bp
from common.session import get_current_user
from apps.direct.logic.chat import send_message, get_chat_history, get_active_conversations
from common.users import get_user_by_username

@direct_bp.route('/direct', methods=['GET', 'POST'])
def direct():
    current = get_current_user()
    if not current:
        return redirect("/login")

    error = None
    selected_chat = None

    if request.method == 'POST':
        to_user = request.form.get('to_user', '').strip()
        message = request.form.get('message', '').strip()

        if not to_user:
            error = "You must specify a recipient."
        elif not message:
            error = "Message cannot be empty."
        else:
            success = send_message(current["id"], to_user, message)
            if not success:
                error = f"User <b>{to_user}</b> does not exist."
                selected_chat = None
            else:
                selected_chat = to_user
    else:
        query_chat = request.args.get('to_user', '').strip()
        if query_chat:
            if get_user_by_username(query_chat):
                selected_chat = query_chat

    conversations = get_active_conversations(current["id"])
    chat_history = []
    if selected_chat:
        chat_history = get_chat_history(current["id"], selected_chat)

    return render_template(
        "direct.html",
        user=current,
        conversations=conversations,
        selected_chat=selected_chat,
        chat_history=chat_history,
        error=error,
        page="direct"
    )
