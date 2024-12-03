import sys
import socket
import threading
import logging
import sqlite3
from utils import generate_rsa_keypair, rsa_encrypt, rsa_decrypt
from utils import aes_encrypt, aes_decrypt, generate_rsa_keypair, hash_data, verify_hash

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

clients = {}
user_credentials = {}
private_key, public_key = generate_rsa_keypair()


def initialize_user_credentials():
    logging.info("Initialize credentials moved to migration")
    # """Initialize user credentials with example users."""
    # Credentials moved to migration
    # example_users = [
    #     ('user1', 'password123'),
    #     ('user2', 'password123'),
    #     ('user3', 'helloWorld'),
    #     ('user4', 'password123'),
    #     ('user5', 'password123'),
    #     ('user6', '12345678'),
    #     ('user7', 'letmein'),
    #     ('user8', 'abc123'),
    #     ('user9', 'password!'),
    #     ('user10', 'welcome2023')
    # ]
    #
    # for username, password in example_users:
    #     user_credentials[username] = hash_data(password)
    #     logging.warning( f"Hashing password for user {username} & password {password} result {user_credentials[username]}" )


def handle_client(client_socket, client_address):
    credentials_login = client_socket.recv(1024).decode('utf-8')
    username, password = credentials_login.split(':', 1)

    # Hash the received password
    encrypted_password = hash_data(password)

    logging.warning(f"Hashing password for user: {password}")

    logging.warning(f"Result Hashing password for user: {encrypted_password}")

    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()

    # Check if the username exists and the password matches
    if user is None:
        logging.info('user not found')
        client_socket.send("LOGIN_FAILED".encode('utf-8'))
        return

    if encrypted_password != user[2]:
        logging.info(f'password not match {encrypted_password} != {user[2]}')
        client_socket.send("LOGIN_FAILED".encode('utf-8'))
        return

    logging.info('login success')
    client_socket.send("LOGIN_SUCCESS".encode('utf-8'))

    client_name = client_socket.recv(1024).decode('utf-8')
    clients[client_name] = client_socket
    logging.info(f"{client_name} connected from {client_address}")

    # Kirim daftar pengguna yang terhubung ke client baru
    send_user_list()
    get_chat_history(client_name)

    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if message:
                target_name, encrypted_message = message.split(':', 1)
                logging.info(target_name)
                if target_name in clients:
                    target_socket = clients[target_name]

                    store_chat(client_name, target_name, encrypted_message)
                    target_socket.send(f"{client_name}:{encrypted_message}".encode('utf-8'))
                    logging.info(f"Message from {client_name} to {target_name}: {encrypted_message}")
        except:
            client_socket.close()
            del clients[client_name]
            logging.info(f"{client_name} disconnected")
            send_user_list()  # Kirim daftar pengguna setelah seseorang terputus
            break

    conn.close()


def store_chat(sender, receiver, message):
    logging.info(f"Storing chat from {sender} to {receiver}")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    try:
        user_from = conn.execute('SELECT id FROM users WHERE username = ?', (sender,)).fetchone()
        user_to = conn.execute('SELECT id FROM users WHERE username = ?', (receiver,)).fetchone()
        cursor.execute('INSERT INTO chats ("from", "to", message) VALUES (?, ?, ?)',
                       (user_from[0], user_to[0], message))
        conn.commit()
    except Exception as e:
        logging.error(f"Error storing chat: {e}")
        conn.rollback()

    conn.close()


def get_chat_history(sender):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    user_from = conn.execute('SELECT id FROM users WHERE username = ?', (sender,)).fetchone()
    cursor.execute('''
        SELECT message, sender.username as sender_name, reciver.username as reciver_name
        FROM chats
        LEFT JOIN users as sender on sender.id = chats."from"
        LEFT JOIN users as reciver on reciver.id = chats."to"
        WHERE chats."from" = ? OR chats."to" = ?
    ''', (user_from[0], user_from[0]))

    messages = cursor.fetchall()
    conn.close()

    for client_name, client_socket in clients.items():
        client_socket.send(f"CHAT:{messages}".encode('utf-8'))


def send_user_list():
    user_list = ', '.join(clients.keys())
    for client_name, client_socket in clients.items():
        logging.info(client_name)
        client_socket.send(f"USER_LIST:{user_list}".encode('utf-8'))


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 5555))
    server.listen(5)
    logging.info("Server started on port 5555")

    try:
        while True:
            client_socket, client_address = server.accept()
            client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_handler.start()
    except KeyboardInterrupt:
        print("Server shutting down...")
        server.close()
        sys.exit(0)


if __name__ == "__main__":
    initialize_user_credentials()
    start_server()
