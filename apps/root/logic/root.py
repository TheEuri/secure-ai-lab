from common.users import get_db


def _fetch_all(cursor):
    return [dict(row) for row in cursor.fetchall()]


def get_admin_dashboard_data():
    with get_db() as conn:
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) AS total FROM users", ())
        user_count = cur.fetchone()["total"]
        cur.execute("SELECT COUNT(*) AS total FROM board", ())
        topic_count = cur.fetchone()["total"]
        cur.execute("SELECT COUNT(*) AS total FROM comments", ())
        reply_count = cur.fetchone()["total"]

        cur.execute(
            "SELECT id, username, role FROM users ORDER BY username ASC",
            (),
        )
        members = _fetch_all(cur)
        cur.execute(
            """
            SELECT board.id, board.title, board.body, board.created_at,
                   users.username AS author_name
            FROM board
            JOIN users ON board.author_id = users.id
            ORDER BY board.created_at DESC, board.id DESC
            """,
            (),
        )
        topics = _fetch_all(cur)
        cur.execute(
            """
            SELECT comments.id, comments.board_id, comments.body, comments.created_at,
                   users.username AS author_name, board.title AS topic_title
            FROM comments
            JOIN users ON comments.author_id = users.id
            JOIN board ON comments.board_id = board.id
            ORDER BY comments.created_at DESC, comments.id DESC
            """,
            (),
        )
        replies = _fetch_all(cur)

    return {
        "counts": {
            "users": user_count,
            "topics": topic_count,
            "replies": reply_count,
        },
        "members": members,
        "topics": topics,
        "replies": replies,
    }


def delete_topic_and_replies(topic_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM comments WHERE board_id = ?", (topic_id,))
        cur.execute("DELETE FROM board WHERE id = ?", (topic_id,))
        conn.commit()


def delete_reply(reply_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM comments WHERE id = ?", (reply_id,))
        conn.commit()
