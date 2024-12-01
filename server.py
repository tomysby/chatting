import socket
import threading
import logging
from utils import generate_rsa_keypair, rsa_encrypt, rsa_decrypt
from utils import aes_encrypt, aes_decrypt, generate_rsa_keypair, hash_data, verify_hash

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

clients = {}
user_credentials = {} 
private_key, public_key = generate_rsa_keypair()

def initialize_user_credentials():
    """Initialize user credentials with example users."""
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
    
    for username, password in example_users:
        user_credentials[username] = hash_data(password)
        logging.warning( f"Hashing password for user {username} & password {password} result {user_credentials[username]}" )

def handle_client(client_socket, client_address):

    credentials_login = client_socket.recv(1024).decode('utf-8')
    username, password = credentials_login.split(':', 1)

    # Hash the received password
    encrypted_password = hash_data(password)

    logging.warning(f"Hashing password for user: {password}")

    logging.warning(f"Result Hashing password for user: {encrypted_password}")

    # Check if the username exists and the password matches
    if username not in user_credentials:
        client_socket.send("LOGIN_FAILED".encode('utf-8'))
        return

    if user_credentials[username] != encrypted_password:
        client_socket.send("LOGIN_FAILED".encode('utf-8'))
        return
    
    client_socket.send("LOGIN_SUCCESS".encode('utf-8'))


    client_name = client_socket.recv(1024).decode('utf-8')
    clients[client_name] = client_socket
    logging.info(f"{client_name} connected from {client_address}")

    # Kirim daftar pengguna yang terhubung ke client baru
    send_user_list()

    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if message:
                target_name, encrypted_message = message.split(':',1)
                if target_name in clients:
                    target_socket = clients[target_name]
                    target_socket.send(f"{client_name}:{encrypted_message}".encode('utf-8'))
                    logging.info(f"Message from {client_name} to {target_name}: {encrypted_message}")
        except:
            client_socket.close()
            del clients[client_name]
            logging.info(f"{client_name} disconnected")
            send_user_list()  # Kirim daftar pengguna setelah seseorang terputus
            break

def send_user_list():
    user_list = ', '.join(clients.keys())
    for client_name, client_socket in clients.items():
        client_socket.send(f"USER_LIST:{user_list}".encode('utf-8'))

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 5555))
    server.listen(5)
    logging.info("Server started on port 5555")

    while True:
        client_socket, client_address = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_handler.start()

if __name__ == "__main__":
    initialize_user_credentials()
    start_server()
