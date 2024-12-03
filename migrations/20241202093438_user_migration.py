"""
This module contains a Caribou migration.

Migration Name: user_migration
Migration Version: 20241202093438
"""
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode


def upgrade(connection):
    sql = """
            create table users
            ( id INTEGER PRIMARY KEY AUTOINCREMENT
            , username TEXT
            , password TEXT
            ) """
    connection.execute(sql)

    example_users = [
        ('user1', 'password123'),
        ('user2', 'password123'),
        ('user3', 'helloWorld'),
        ('user4', 'password123'),
        ('user5', 'password123'),
        ('user6', '12345678'),
        ('user7', 'letmein'),
        ('user8', 'abc123'),
        ('user9', 'password!'),
        ('user10', 'welcome2023')
    ]

    sql = 'insert into users values (NULL, :1, :2)'
    for username, password in example_users:
        connection.execute(sql, [username, hash_data(password)])

    connection.commit()
    pass


def downgrade(connection):
    # add your downgrade step here
    connection.execute('drop table users')
    pass


def hash_data(data):
    logging.info("Starting hash SHA-256")
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data.encode('utf-8'))
    hashed_data = digest.finalize()
    logging.info("Hashing completed")
    return b64encode(hashed_data).decode('utf-8')
