from connection import Client
from asyncConnection import AsyncioSecureConnection
import time
import asyncio
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
import colorama
import os
colorama.init(autoreset=True)
import logging

logging.basicConfig(
            level=logging.ERROR,
            format='%(asctime)s %(levelname)s: %(message)s'
        )

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

async def handle_client_message(server: AsyncioSecureConnection, message: bytes, client: Client) -> None:
    if message.startswith(b'/name'):
        name = message.split(b" ")[1]
        client.name = name.decode()
        print(f"{colorama.Fore.GREEN}Client {client.ip}:{client.port} changed name to {client.name}{colorama.Style.RESET_ALL}")
    else:
        print(f"{colorama.Fore.CYAN}{client.name}> {message.decode()}{colorama.Style.RESET_ALL}")

        # Broadcast the message to all other clients
        mesg_to_send = client.name.encode() + b"> " + message
        for c in server.clients:
            if c != client:
                await server.send(mesg_to_send, client=c)

async def receiver_function(server: AsyncioSecureConnection, message: bytes) -> None:
    print(f"{colorama.Fore.CYAN}{message.decode()}{colorama.Style.RESET_ALL}")
    
async def on_client_exit(server: AsyncioSecureConnection, client: Client) -> None:
    print(f"{client.name if client.name != "" else client.ip} has left the chat.")
    await server.send(f"{client.name if client.name != "" else client.ip} has left the chat.".encode())

async def client_mode(ip: str, port: int) -> None:
    client = AsyncioSecureConnection(ip, port)
    client.receiver_function = receiver_function
    print(ip, port)
    p = PromptSession()
    print(f"{colorama.Fore.YELLOW}Connecting to server...{colorama.Style.RESET_ALL}")
    await client.connect()
    print(f"{colorama.Fore.GREEN}Connected to server at {ip}:{port}{colorama.Style.RESET_ALL}")
    name: str = await p.prompt_async("Enter your name: ")
    await client.send(b"/name " + name.encode())
    try:
        with patch_stdout(True):
            while True:
                message: str = await p.prompt_async(name + "> ")
                if message == "":
                    continue
                if message.lower() == '/exit':
                    break
                elif message.startswith("/name"):
                    name = message.split(" ")[1]
                await client.send(message.encode())
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"An error occurred: {e}")

async def server_mode(ip: str, port: int) -> None:
    server = AsyncioSecureConnection(ip, port)
    server.create_server_socket()
    server.handle_client_function = handle_client_message
    server.on_exit_function = on_client_exit
    p = PromptSession()
    asyncio.create_task(server.handle_connections())
    name = "server"
    try:
        with patch_stdout(True):
            while True:
                message: str = await p.prompt_async(name + "> ")
                if message == "":
                    continue
                if message.startswith('/exit'):
                    break
                elif message.startswith("/name"):
                    name = message.split(" ")[1]
                elif message.startswith("/info"):
                    print(f"Server IP: {ip}, Port: {port}")
                    print(f"Connected clients: {len(server.clients)}")
                    print("Client list:")
                    for client in server.clients:
                        print(f"{client.ip}:{client.port} - {client.name} - {client.socket} - keys {client.aes_key.hex()[:8]}... {client.hmac_key.hex()[:8]}...")
                    continue
                elif message.startswith("/help"):
                    print("Available commands:")
                    print("/help - Show this help message")
                    print("/info - Show server info")
                    print("/exit - Exit the server")
                    continue                
                await server.send(name.encode() + b"> " + message.encode())
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"An error occurred: {e}")

async def main():
    mode = await asyncio.to_thread(ask_while_valid, "Enter 's' for server or 'c' for client: ", ['s', 'c'])
    ip = await asyncio.to_thread(input, "Enter the IP address (leave empty for localhost): ") or "127.0.0.1"
    port = await asyncio.to_thread(input, "Enter the port (leave empty for 43221): ") or 43221

    if mode == 's':
        await server_mode(ip, port)
            
    elif mode == 'c':
        await client_mode(ip, port)

if __name__ == "__main__":
    print("Starting chat application...")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"An error occurred: {e}")