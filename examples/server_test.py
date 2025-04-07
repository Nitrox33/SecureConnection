from connection import SecureConnection
from time import sleep
import threading
SERVER = SecureConnection(host="localhost", port=43221, verbose=False) # Replace with your server's IP and port

SERVER.start_server(thread=True) # start the server

print("Server started, waiting for clients...")
try:
    last_number_client = 0
    last_thread_number = threading.active_count()
    while True:
        sleep(1)
        if threading.active_count() != last_thread_number:
            print(f'New thread started ({threading.active_count()})')
            last_thread_number = threading.active_count()
        if len(SERVER.clients) != last_number_client:
            print("Connected clients:")
            last_number_client = len(SERVER.clients)
            for client in SERVER.clients:
                print(f'Client IP: {client.ip}')
except KeyboardInterrupt:
    print("\nStopping server...")
    SERVER.stop_server()
    print("Server stopped.")
    