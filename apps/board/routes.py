from flask import request, render_template, redirect, url_for, abort
from apps.board import board_bp
from common.session import get_current_user
from apps.board.logic.forum import (
    get_all_boards, get_board_by_id, get_comments_for_board,
    add_board, add_comment, search_boards
)

@board_bp.route('/board')
def board_home():
    current = get_current_user()
    if not current:
        return redirect("/login")
    boards = get_all_boards()
    return render_template('board_home.html', user=current, boards=boards)

@board_bp.route("/board/<board_id>")
def board_topic(board_id):
    current = get_current_user()
    if not current:
        return redirect("/login")
    board = get_board_by_id(board_id)
    if not board:
        abort(404)
    comments = get_comments_for_board(board_id)
    return render_template("board_topic.html", user=current, board=board, comments=comments)

@board_bp.route("/board/new", methods=["GET", "POST"])
def board_new():
    current = get_current_user()
    if not current:
        return redirect("/login")
    if request.method == "POST":
        title = request.form.get("title", "")
        body = request.form.get("body", "")
        if title and body:
            add_board(current["id"], title, body)
            return redirect(url_for("board.board_home"))
    return render_template("board_new.html", user=current)

@board_bp.route("/board/<int:board_id>/reply", methods=["POST"])
def board_reply(board_id):
    current = get_current_user()
    if not current:
        return redirect("/login")
    body = request.form.get("body", "")
    if body:
        add_comment(board_id, current["id"], body)
    return redirect(url_for("board.board_topic", board_id=board_id))

@board_bp.route("/board/search")
def board_search():
    current = get_current_user()
    if not current:
        return redirect("/login")
    q = request.args.get("q", "")
    boards = search_boards(q)
    return render_template("board_home.html", user=current, boards=boards)
