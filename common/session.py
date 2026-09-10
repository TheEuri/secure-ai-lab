from flask import request
import json
import base64
import time

from common.users import get_user_by_id

def generate_token(username: str, role: str = 'user', user_id: int = 0, ttl_seconds: int = 3600) -> str:
    token = {
        "u": username,
        "id": user_id,
        "r": role,
        "exp": int(time.time()) + ttl_seconds,
        "v": 1
    }
    raw = json.dumps(token, separators=(',', ':'))
    return base64.b64encode(raw.encode()).decode()

def decode_token(token: str):
    try:
        decoded = base64.b64decode(token.encode()).decode()
        data = json.loads(decoded)
        return {
            "username": data.get("u"),
            "user_id": data.get("id"),
            "role": data.get("r"),
            "exp": data.get("exp"),
            "v": data.get("v")
        }
    except Exception:
        return None

def get_current_user(strict=True):
    token = request.cookies.get("session_id")
    if not token:
        return None if strict else {}
    token_data = decode_token(token)
    if not token_data:
        return None if strict else {}
    now = int(time.time())
    if token_data.get("exp") is not None and now > int(token_data["exp"]):
        return None if strict else {}
    user = get_user_by_id(token_data["user_id"])
    if user and user["username"] == token_data["username"]:
        return user
    return None if strict else {}
