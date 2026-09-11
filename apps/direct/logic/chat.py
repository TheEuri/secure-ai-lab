from common.users import get_db, get_user_by_username
from common.message_crypto import decrypt_message, encrypt_message, MessageDecryptionError

def send_message(sender_id, recipient_username, text):
    recipient = get_user_by_username(recipient_username)
    if not recipient:
        return False
    with get_db() as conn:
        with conn:
            cur = conn.execute(
                """
                INSERT INTO chat (sender_id, recipient_id, text)
                VALUES (?, ?, '')
                """,
                (sender_id, recipient["id"]),
            )
            message_id = cur.lastrowid
            ciphertext, nonce, version = encrypt_message(
                text, message_id, sender_id, recipient["id"]
            )
            updated = conn.execute(
                """
                UPDATE chat
                SET message_ciphertext = ?, message_nonce = ?, crypto_version = ?
                WHERE id = ?
                """,
                (ciphertext, nonce, version, message_id),
            )
            if updated.rowcount != 1:
                raise RuntimeError("Private-message write did not complete safely.")
    return True

def get_chat_history(user_id, other_username):
    from common.users import get_user_by_username
    other = get_user_by_username(other_username)
    if not other:
        return []
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT
                c.id,
                c.sender_id,
                c.recipient_id,
                c.text,
                c.timestamp,
                c.message_ciphertext,
                c.message_nonce,
                c.crypto_version,
                u.username AS sender
            FROM chat c
            JOIN users u ON c.sender_id = u.id
            WHERE
                (c.sender_id = ? AND c.recipient_id = ?)
                OR
                (c.sender_id = ? AND c.recipient_id = ?)
            ORDER BY c.timestamp ASC
        """, (user_id, other["id"], other["id"], user_id))
        rows = cur.fetchall()
        history = []
        for row in rows:
            metadata = (
                row["message_ciphertext"],
                row["message_nonce"],
                row["crypto_version"],
            )
            if all(value is None for value in metadata):
                text = row["text"]
            elif all(value is not None for value in metadata) and row["text"] == "":
                text = decrypt_message(
                    bytes(row["message_ciphertext"]),
                    bytes(row["message_nonce"]),
                    row["crypto_version"],
                    row["id"],
                    row["sender_id"],
                    row["recipient_id"],
                )
            else:
                raise MessageDecryptionError()
            history.append({
                "id": row["id"],
                "sender": row["sender"],
                "text": text,
                "timestamp": row["timestamp"],
                "type": "message"
            })
        return history

def get_active_conversations(user_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT
                u.username,
                MAX(c.timestamp) AS last_msg
            FROM users u
            JOIN chat c
              ON (u.id = c.sender_id AND c.recipient_id = ?)
              OR (u.id = c.recipient_id AND c.sender_id = ?)
            WHERE u.id != ?
            GROUP BY u.id
            ORDER BY last_msg DESC
        """, (user_id, user_id, user_id))
        return [row["username"] for row in cur.fetchall()]
