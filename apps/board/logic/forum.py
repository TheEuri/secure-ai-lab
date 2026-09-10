from common.users import get_db

def get_all_boards():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT board.id, board.title, board.body, board.created_at, users.username as author_name,
                   (SELECT COUNT(*) FROM comments WHERE comments.board_id = board.id) AS reply_count
            FROM board
            JOIN users ON board.author_id = users.id
            ORDER BY board.created_at DESC
        """)
        return [dict(row) for row in cur.fetchall()]

def get_comments_for_board(board_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT comments.id, comments.body, comments.created_at, users.username as author_name, comments.author_id
            FROM comments
            JOIN users ON comments.author_id = users.id
            WHERE comments.board_id = ?
            ORDER BY comments.created_at ASC
        """, (board_id,))
        return [dict(row) for row in cur.fetchall()]

def add_board(author_id, title, body):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO board (author_id, title, body) VALUES (?, ?, ?)",
            (author_id, title, body)
        )
        conn.commit()
        return cur.lastrowid

def add_comment(board_id, author_id, body):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO comments (board_id, author_id, body) VALUES (?, ?, ?)",
            (board_id, author_id, body)
        )
        conn.commit()
        return cur.lastrowid

def get_board_by_id(board_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(f"""
            SELECT board.id, board.title, board.body, board.created_at, users.username as author_name, board.author_id
            FROM board
            JOIN users ON board.author_id = users.id
            WHERE board.id = {board_id}
        """)
        row = cur.fetchone()
        return dict(row) if row else None

def search_boards(query):
    with get_db() as conn:
        cur = conn.cursor()
        try:
            cur.execute(f"""
                SELECT board.id, board.title, board.body, board.created_at, users.username as author_name,
                       (SELECT COUNT(*) FROM comments WHERE comments.board_id = board.id) AS reply_count
                FROM board
                JOIN users ON board.author_id = users.id
                WHERE board.title LIKE '%{query}%' OR board.body LIKE '%{query}%'
                ORDER BY board.created_at DESC
            """)
            return [dict(row) for row in cur.fetchall()]
        except Exception as e:
            return [{"title": f"SQL Error: {e}", "body": "", "author_name": "", "created_at": "", "reply_count": 0}]