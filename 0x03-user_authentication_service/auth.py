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


def hash_password(password: str) -> str:
    """
    Defining hash password
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def generate_uuid) -> str:
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
            return self._db.add_user(email, hash_password(password))
