from pathlib import Path
import os
import sqlite3
from flask import current_app, has_app_context

from common.users import get_db, hash_password

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
    if has_app_context() and current_app.config.get('AVATAR_DIR'):
        avatar_dir = Path(current_app.config['AVATAR_DIR'])
    else:
        base_dir = Path(__file__).resolve().parents[3]
        avatar_dir = base_dir / 'static' / 'img' / 'avatars'
    os.makedirs(avatar_dir, exist_ok=True)
    filename = f"{user_id}.jpg"
    filepath = avatar_dir / filename
    file_storage.save(filepath)
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
