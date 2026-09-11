from common.users import get_db, hash_password
from common.file_integrity import update_avatar

def update_password(user_id, new_password):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (hash_password(new_password), user_id)
        )
        conn.commit()
        return cur.rowcount == 1

def update_avatar_file(user_id, file_storage):
    """Store a validated canonical avatar and preserve the legacy filename API."""

    filename, _digest = update_avatar(user_id, file_storage)
    return filename

def update_bio(user_id, new_bio):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET bio = ? WHERE id = ?",
            (new_bio, user_id)
        )
        conn.commit()
        return cur.rowcount == 1
