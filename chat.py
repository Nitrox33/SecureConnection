from connection import SecureConnection, Client
import time
import threading
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
import colorama

colorama.init(autoreset=True)

color_table = {
    "red": colorama.Fore.RED,
    "green": colorama.Fore.GREEN,
    "blue": colorama.Fore.BLUE,
    "yellow": colorama.Fore.YELLOW,
    "cyan": colorama.Fore.CYAN,
    "magenta": colorama.Fore.MAGENTA,
}


def ask_while_valid(prompt: str, valid_responses: list[str] = None) -> str:
    session = PromptSession()
    with patch_stdout():
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
            print(f'Client IP: {client.ip}')

def handle_client_message(server: SecureConnection, message: bytes, client: Client) -> None:
    """Handles incoming messages from clients.
    This function is called when a message is received from a client.
    It prints the message to the console. and sends it to all other connected clients.

    Args:
        message (bytes): The message received from the client.
        client (Client): The client that sent the message.
    """
    if "/name" in message.decode():
        name = message.decode().split(" ")[1]
        client.name = name
        server.send(f"Your name is now {name}".encode(), client=client)
        return
    
    if "/color" in message.decode():
        color = message.decode().split(" ")[1]
        if color in ["red", "green", "blue", "yellow", "cyan", "magenta"]:
            client.color = color
            server.send(f"Your color is now {color}".encode(), client=client)
            client.name_color = color_table[color]
            return
        else:
            server.send(f"Invalid color. Available colors: red, green, blue, yellow, cyan, magenta".encode(), client=client)
            return
        
    if "/help" in message.decode():
        help_message = (
            "/name <name> - Set your name\n"
            "/color <color> - Set your name color (red, green, blue, yellow, cyan, magenta)\n"
            "/help - Show this help message\n"
            "/exit - Disconnect from the server\n"
        )
        server.send(help_message.encode(), client=client)
        return

    if "/exit" in message.decode():
        server.send("Goodbye!".encode(), client=client)
        server.disconnect(client)
        return
        
    name = client.name if client.name else f"Client {client.ip}:{client.port}"
    color = client.name_color if client.name_color else colorama.Style.RESET_ALL
    
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
    SERVER = SecureConnection(host=ip, port=port, verbose=False)
    SERVER.start_server(thread=True)
    last_number_client = 0
    last_thread_number = threading.active_count()
    SERVER.handle_client_function = handle_client_message
    session = PromptSession()
    try:
        with patch_stdout():
            while True:
                user_input: str = session.prompt("> ")
                if user_input.lower() == 'exit':
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
    try:
        with patch_stdout():
            while True:
                input_message = session.prompt("> ")
                if input_message.lower() == 'exit':
                    break
                com.send(input_message.encode())
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        print("\nDisconnecting...")
        com.disconnect()
        print("Disconnected.")

def main():
    mode = ask_while_valid("Enter 's' for server or 'c' for client: ", ['s', 'c'])
    ip = input("Enter the IP address (leave empty for localhost): ") or "localhost"
    port = int(input("Enter the port (leave empty for 43221): ") or 43221)
    
    if mode == 's':
        server_mode(ip, port)
            
    elif mode == 'c':
        client_mode(ip, port)
        
if __name__ == "__main__":
    main()