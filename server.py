import socket
import threading
import logging
from utils import generate_rsa_keypair, rsa_encrypt, rsa_decrypt

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

clients = {}
private_key, public_key = generate_rsa_keypair()

def handle_client(client_socket, client_address):
    client_name = client_socket.recv(1024).decode('utf-8')
    clients[client_name] = client_socket
    logging.info(f"{client_name} connected from {client_address}")

    # Kirim daftar pengguna yang terhubung ke client baru
    send_user_list()

    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if message:
                target_name, encrypted_message = message.split(':', 1)
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
    start_server()
