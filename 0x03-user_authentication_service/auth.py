#!/usr/bin/env python3
"""
Hashed password module
"""

from db import DB
import bcrypt
from user import User
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4
from typing import TypeVar


def _hash_password(password: str) -> str:
    """
    Defining hash password
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def _generate_uuid() -> str:
    """
    Generating a unique identifier
    """
    return str(uuid4())


class Auth:
    """
    Auth class to interact with authentication of the database
    """
    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Register a user
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))

        def valid_login(self, email: str, password: str) -> bool:
            """
            Validte user's credentials 
            """
            try:
                user = self._db.find_user_by(email=email)
            except NoResultFound:
                return False
            return bcrypt.checkpw(password.encode('utf-8'), user.hashed_password)

        def create_session(self, email: str) -> str:
            """
            Create the user session 
            """
            try:
                user = self._db.find_user_by(email=email)
                sess_id = _generate_uuid()
                self._db.update_user(user.id, session_id=sess_id)
                return sess_id
            except NoResultFound:
                return

        def get_user_from_session_id(self, session_id: str) -> str:
            """
            Get user from the session id
            """
            if session_id is None:
                return
            try:
                user = self._db.find_user_by(session_id=session_id)
                return user.email
            except NoResultFound:
                return

        def destroy_session(self. user_id: int) -> None:
            """
            Destroying a user session
            """
            try:
                user = self._db.find_user_by(id=user_id)
                self._db.update_user(user.id, session_id=None)
            except NoResultFound:
                pass

        def get_reset_password_token(self, email: str) -> str:
            """
            Get reset password token
            """
            try:
                user = self._db.find_user_by(email=email)
                reset_token = _generate_uuid()
                self._db.update_user(user.id, reset_token=reset_token)
                return reset_token
            except NoResultFound:
                raise ValueError

        def update_password(self, reset_token: str, password: str) -> None:
            """
            Update password for a user
            """
            try:
                user = self._db.find_user_by(reset_token=reset_token)
                self._db.update_user(user.id,
                                     hashed_password=_hash_password(password),
                                     reset_token=None)
            except NoResultFound:
                raise ValueError
