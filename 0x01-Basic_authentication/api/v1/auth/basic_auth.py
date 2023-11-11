#!/usr/bin/env python3
"""
Basic Authentication module
"""


from api.v1.auth.auth import Auth
from typing import TypeVar, List
from models.user import User
import base64
import binascii


class BasicAuth(Auth):
    """
    class BasicAuth
    """

    def extract_bas64_authorization_header(
            self, authorization_header: str) -> str:
        """
        Return the Base64 part of the authorization
        header for a Basic Authentication
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        header_array = authorization_header.split(" ")
        if header_array[0] != "Basic":
            return None
        else:
            return header_array[1]

        def decode_base64_authorization_header(
                self, base64_authorization_header: str) -> str:
            """
            Return the decoded value of base64 string
            base64_authorization_header
            """
            b64_auth_header = base64_authorization_header
            if b64_auth_header and isinstance(b64_auth_header, str):
                try:
                    encode = b64_auth_header.encode('utf-8')
                    base = base64.b64decode(encode)
                    return base.decode('utf-8')
                except binascii.Error:
                    return None

        def extract_user_credentials(
                self, decode_base64_authorization_header: str) -> (str, str):
            """
            Returns the user email and password from the base64 decoded value
            """
            decoded_64 = decoded_base64_authorization_header
            if (decoded_64 and isinstance(decoded_64, str) and
                ":" in decoded_64):
                res = decoded_64.split(":", 1)
                return (res[0], res[1])
            return (None, None)

        def current_user(self, request=None) -> TypeVar('User'):
            """Get the current user"""
            Auth_header = self.authorization_header(request)
            if Auth_header is not None:
                token = self.extract_base64_authorization_header(Auth_header)
                if token is not None:
                    decoded = self.decode_base64_authorization_header(token)
                    if decoded is not None:
                        email, pword = self.extract_user_credentials(decoded)
                        if email is not None:
                            return self.user_object_from_credentials(email, pword)
            return

        def user_object_from_credentials(self, user_email: str,
                                         user_pwd: str) -> TypeVar('User'):
            """
            Returns the User instance based on his email and password
            """
            if user_email is None or not isinstance(user_email, str):
                return None
            if user_pwd is Non or not isinstance(user_pwd, str):
                return None
            try:
                user = User.search({'email': user_email})
                if not user or user == []:
                    return None
                for u in user:
                    if u.is_valid_password(user_pwd):
                        return u
                    return None
            except Exception:
                return None
