from flask import request, render_template, redirect, make_response

import time

from . import lobby_bp
from apps.lobby.logic.users import (
    ACCOUNT_CREATED,
    ACCOUNT_CREATION_ERROR,
    DUPLICATE_EMAIL,
    DUPLICATE_USERNAME,
    DUPLICATE_USERNAME_AND_EMAIL,
    create_user,
)

from common.session import get_current_user, generate_token
from common.security_audit import record_security_event
from common.users import (
    email_exists,
    get_user_by_username,
    username_exists,
    verify_and_rehash_password,
)


FAST_DELAY = 0.05
SLOW_DELAY = 0.1

@lobby_bp.route('/')
def index():
    current = get_current_user()
    if not current:
        return redirect("/login")

    return redirect('/board')

@lobby_bp.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    username_input = ''

    if request.method == 'POST':
        username_input = request.form.get('username', '')
        password = request.form.get('password', '')
        user = get_user_by_username(username_input)
        error_message = 'Invalid credentials.'

        if not user:
            time.sleep(FAST_DELAY)
            error = error_message
            record_security_event(
                "auth.login.failure",
                "failure",
                request_method=request.method,
                request_path=request.path,
            )

        elif not verify_and_rehash_password(user["id"], user["password"], password):
            time.sleep(SLOW_DELAY)
            error = error_message
            record_security_event(
                "auth.login.failure",
                "failure",
                actor_user_id=user["id"],
                target_type="user",
                target_id=user["id"],
                request_method=request.method,
                request_path=request.path,
            )

        else:
            record_security_event(
                "auth.login.success",
                "success",
                actor_user_id=user["id"],
                target_type="user",
                target_id=user["id"],
                request_method=request.method,
                request_path=request.path,
            )
            session_token = generate_token(user['username'], user['role'], user['id'])
            resp = make_response(redirect('/board'))
            resp.set_cookie(
                'session_id',
                session_token,
                path='/',
                httponly=False,
                secure=False,
                samesite=None
            )
            return resp

    return render_template('login.html', error=error, username=username_input)


@lobby_bp.route('/register', methods=['GET', 'POST'])
def register():
    submitted_username = ''
    message = None

    if request.method == 'POST':
        submitted_username = request.form.get('username', '').strip()
        email_input = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not submitted_username or not email_input or not password:
            message = 'Username, email, and password are required.'
        else:
            uname_exists = username_exists(submitted_username)
            email_in_use = email_exists(email_input)

            if uname_exists and email_in_use:
                time.sleep(SLOW_DELAY)
                result = DUPLICATE_USERNAME_AND_EMAIL
            elif uname_exists:
                time.sleep(FAST_DELAY)
                result = DUPLICATE_USERNAME
            elif email_in_use:
                time.sleep(FAST_DELAY)
                result = DUPLICATE_EMAIL
            else:
                time.sleep(0.01)
                result = create_user(submitted_username, password, email_input)

            if result == ACCOUNT_CREATED:
                message = 'Account created. You may now log in.'
            elif result == DUPLICATE_USERNAME_AND_EMAIL:
                message = 'That username and email are already in use.'
            elif result == DUPLICATE_USERNAME:
                message = 'That username is already in use.'
            elif result == DUPLICATE_EMAIL:
                message = 'That email is already in use.'
            elif result == ACCOUNT_CREATION_ERROR:
                message = 'The account could not be created. Please try again.'
            else:
                message = 'The account could not be created. Please try again.'

    return render_template('register.html', message=message, username=submitted_username)


@lobby_bp.route('/logout')
def logout():
    current = get_current_user()
    if current:
        record_security_event(
            "auth.logout",
            "success",
            actor_user_id=current["id"],
            target_type="user",
            target_id=current["id"],
            request_method=request.method,
            request_path=request.path,
        )
    resp = make_response(redirect('/login'))
    resp.delete_cookie('session_id', path='/')
    return resp
