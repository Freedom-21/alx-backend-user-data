#!/usr/bin/env python3
"""
Module for handling password encryption and validation.
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Returns a salted, hashed password.

    Args:
        password: The password to hash.

    Returns:
        The hashed password as a byte string.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates if the provided password matches the hashed password.

    Args:
        hashed_password: The hashed password to validate against.
        password: The plain text password to validate.

    Returns:
        True if the password matches, False otherwise.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
