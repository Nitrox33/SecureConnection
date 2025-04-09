from connection import SecureConnection, Client
import time
import threading
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
import colorama
import os
colorama.init(autoreset=True)
import string
import logging

from connection import MAX_MESSAGE_SIZE

color_map = {
    "red": colorama.Fore.RED,
    "green": colorama.Fore.GREEN,
    "blue": colorama.Fore.BLUE,
    "yellow": colorama.Fore.YELLOW,
    "cyan": colorama.Fore.CYAN,
    "magenta": colorama.Fore.MAGENTA,
}

def ask_while_valid(prompt: str, valid_responses: list[str] = None) -> str:
    session = PromptSession(True)
    with patch_stdout(True):
        while True:
            response = session.prompt(prompt).lower()
            if valid_responses is None or response in valid_responses:
                return response
            print(f"{colorama.Fore.RED}Please enter one of the following: {', '.join(valid_responses)}{colorama.Style.RESET_ALL}")

def print_server_status(SERVER, last_number_client=0, last_thread_number=0) -> None:
    """Prints the status of the server, including the number of connected clients and active threads."""
    if threading.active_count() != last_thread_number:
        print(f'New thread started ({threading.active_count()})')
        last_thread_number = threading.active_count()
    if len(SERVER.clients) != last_number_client:
        print("Connected clients:")
        last_number_client = len(SERVER.clients)
        for client in SERVER.clients:
            logging.info(f"Client {client.ip}:{client.port} connected")
            print(f'Client IP: {client.ip}')

def handle_client_message(server: SecureConnection, message: bytes, client: Client) -> None:
    """Handles incoming messages from clients.
    This function is called when a message is received from a client.
    It prints the message to the console. and sends it to all other connected clients.

    Args:
        message (bytes): The message received from the client.
        client (Client): The client that sent the message.
    """
    logging.info(f"Received message from {client.ip}:{client.port}:{message.decode()}...")
    
    if len(message) > MAX_MESSAGE_SIZE:  # 10 MB limit
        server.send(f"Your message is too long ({len(message)/1024/1024:.2f} MB). Max size is 10 MB.".encode(), client=client)
        return
    
    if message.startswith(b"/upload"):
        print("Receiving file...")
        print(f"File size: {len(message)} bytes")
        file_data = message[7:]
        file_name = f"received_{int(time.time())}.txt"
        with open(file_name, "wb") as f:
            f.write(file_data)
        server.send(f"server: File {file_name} received.".encode(), client=client)
        print(f"File {file_name} received from {client.ip}:{client.port}.")
        
        return
    
    if message.startswith(b"/name"):
        name = message.decode().split(" ")[1]
        if len(name) > 20:
            server.send(f"Name too long. Max 20 characters.".encode(), client=client)
            return
        client.name = name
        server.send(f"Your name is now {name}".encode(), client=client)
        return
    
    if message.startswith(b"/color"):
        color = message.decode().split(" ")[1]
        if color in ["red", "green", "blue", "yellow", "cyan", "magenta"]:
            server.send(f"Your color is now {color}".encode(), client=client)
            client.name_color = color_map[color]
            return
        else:
            server.send(f"Invalid color. Available colors: red, green, blue, yellow, cyan, magenta".encode(), client=client)
            return
        
    if message.startswith(b"/help"): # todo: add help message
        help_message = (
            "/name <name> - Set your name\n"
            "/color <color> - Set your name color (red, green, blue, yellow, cyan, magenta)\n"
            "/help - Show this help message\n"
            "/upload <file_path> - Upload a file\n"
            "/exit - Disconnect from the server\n"
        )
        server.send(help_message.encode(), client=client)
        return

    if message.startswith(b"/exit"):
        server.send("Goodbye!".encode(), client=client)
        server.disconnect(client)
        return
        
    name = client.name if client.name else f"Client {client.ip}:{client.port}"
    color = client.name_color if client.name_color else ""

    message = color.encode() + name.encode() + b": " + colorama.Style.RESET_ALL.encode() + message
    print(f"{message.decode()}")
    for c in server.clients:
        if c != client:
            server.send(message, client=c)

def server_mode(ip: str, port: int) -> None:
    """Handles the server mode of the application.
    This function initializes the server, starts it, and handles incoming messages from clients.
    It also allows the user to send messages to all connected clients.
    It uses the SecureConnection class to manage the server connection and threading.

    Args:
        ip (str): The IP address for the server.
        port (int): The port number for the server.
    """
    logging.info(f"Starting server on {ip}:{port}")
    SERVER = SecureConnection(host=ip, port=port, verbose=False)
    SERVER.start_server(thread=True)
    last_number_client = 0
    last_thread_number = threading.active_count()
    SERVER.handle_client_function = handle_client_message
    session = PromptSession()
    logging.info("Server started. Waiting for clients...")
    try:
        with patch_stdout(True):
            while True:
                user_input: str = session.prompt("> ")
                if user_input.lower() == '/exit':
                    break
                for client in SERVER.clients:
                    SERVER.send("server: ".encode() + user_input.encode(), client=client)
                
    except KeyboardInterrupt:
        print("keyboard interrupt received")
    finally:
        SERVER.stop_server()

def client_mode(ip: str, port: int) -> None:
    com = SecureConnection(host=ip, port=port, verbose=False)
    com.connect()
    com.start_listener(lambda x: print(f"{x.decode()}"))
    session = PromptSession()
    name = ""
    try:
        with patch_stdout(True):
            while True:
                input_message: str = session.prompt(name + "> ")
                if input_message.lower() == "/exit":
                    try:
                        name = input_message.split(" ")[1]
                    except IndexError:
                        print("Usage: /name <name>")
                elif input_message.startswith("/test"):
                    input_message = string.ascii_letters * 1000 * 2 * 100 # 52 * 1000 * 2 * 100 = 9.91 MB
                    print(f"Sending {len(input_message)/1024/1024:.2f} MB")
                elif input_message.startswith("/upload"):
                    try:
                        file_path = input_message[7:]
                        upload_file(file_path, com)
                    except IndexError:
                        print("Usage: /upload <file_path>")
                    continue
                com.send(input_message.encode())
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        print("\nDisconnecting...")
        com.disconnect()
        print("Disconnected.")

def upload_file(file_path: str, con: SecureConnection) -> None:
    # Check if the file exists and it's size
    if not os.path.isfile(file_path):
        print(f"File {file_path} does not exist.")
        return
    file_size = os.path.getsize(file_path)
    if file_size > MAX_MESSAGE_SIZE:  # 10 MB limit
        print(f"File {file_path} is too large. Max size is {MAX_MESSAGE_SIZE / 1024 / 1024} MB.")
        return
    print("Uploading file...")
    with open(file_path, "rb") as f:
        data = f.read()
        con.send(b"/upload" + data)
    print(f"File {file_path} uploaded.")
    
def main():
    mode = ask_while_valid("Enter 's' for server or 'c' for client: ", ['s', 'c'])
    ip = input("Enter the IP address (leave empty for localhost): ") or "localhost"
    port = int(input("Enter the port (leave empty for 43221): ") or 43221)
    
    if mode == 's':
        logging.basicConfig(
            filename='chat.log',
            level=logging.INFO,
            format='%(asctime)s %(levelname)s: %(message)s'
        )
        server_mode(ip, port)
            
    elif mode == 'c':
        while True:
            try:
                client_mode(ip, port)
                break
            except ConnectionRefusedError:
                print(f"Connection refused. Server not running on {ip}:{port}.")
                ip = input("Enter the IP address (leave empty for localhost): ") or "localhost"
                port = int(input("Enter the port (leave empty for 43221): ") or 43221)
                continue
            except KeyboardInterrupt:
                print("\nExiting...")
                break
            except Exception as e:
                print(f"An error occurred: {e}")
                print("Reconnecting...")
                time.sleep(2)
if __name__ == "__main__":
    main()