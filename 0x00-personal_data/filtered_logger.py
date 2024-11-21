#!/usr/bin/env python3
"""
Module for logging user data with sensitive information obfuscated.
"""

import re
import logging
import os
import mysql.connector
from typing import List


def filter_datum(
        fields: List[str],
        redaction: str,
        message: str,
        separator: str
) -> str:
    """
    Obfuscates specified fields in a log message.

    Args:
        fields: List of field names to obfuscate.
        redaction: String used to replace the original field values.
        message: The log message containing the fields to obfuscate.
        separator: The character separating the fields in the message.

    Returns:
        The log message with specified fields obfuscated.
    """
    pattern = '|'.join([f"{field}=.*?{separator}" for field in fields])
    return re.sub(
        pattern,
        lambda x: f"{x.group().split('=')[0]}={redaction}{separator}", message)


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class in logs."""

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initialize the formatter with fields to redact.

        Args:
            fields: List of field names to redact from the log messages.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record with sensitive information redacted.

        Args:
            record: The log record to be formatted.

        Returns:
            The formatted string with sensitive information redacted.
        """
        message = super().format(record)
        return filter_datum(
            self.fields,
            self.REDACTION,
            message,
            self.SEPARATOR
        )


PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def get_logger() -> logging.Logger:
    """
    Returns a logger object configured with a RedactingFormatter.

    Returns:
        A logger object with the specified configuration.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(fields=PII_FIELDS))
    logger.addHandler(handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Returns a connector to the MySQL database.

    Returns:
        A MySQLConnection object to the database.
    """
    username = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    password = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME")

    return mysql.connector.connect(
        user=username,
        password=password,
        host=host,
        database=db_name
    )


def main() -> None:
    """
    Retrieves all rows in a filtered format.
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT name, email, phone, ssn, password, ip, last_login, user_agent \
        FROM users;"
        )
    logger = get_logger()

    for row in cursor:
        message = (
            f"name={row[0]}; email={row[1]}; phone={row[2]}; ssn={row[3]}; "
            f"password={row[4]}; ip={row[5]}; \
            last_login={row[6]}; user_agent={row[7]};"
        )
        logger.info(message)

    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
