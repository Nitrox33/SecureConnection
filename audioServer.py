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
from chat import ask_while_valid
from connection import MAX_MESSAGE_SIZE
import pyaudio
import wave

received_buffer: list[bytes] = []
RATE = 44000
CHUNK = 1024
CHANNELS = 1
FORMAT = pyaudio.paInt16 # 16-bit PCM

def handle_client_message(server: SecureConnection, message: bytes, client: Client) -> None:
    """Handles incoming messages from clients."""
    received_buffer.append(message)
    
def play_audio(connection: SecureConnection) -> None:
    """Plays audio from a list of chunks."""
    p = pyaudio.PyAudio()
    stream = p.open(format=FORMAT,
                    channels=CHANNELS,
                    rate=RATE,
                    output=True)
    
    while True and connection.is_connected():
        if not received_buffer:
            continue
        stream.write(received_buffer[0])
        received_buffer.pop(0)
    
    stream.stop_stream()
    stream.close()
    p.terminate()


def server_mode(ip: str, port: int, device_index: int) -> None:
    SERVER = SecureConnection(host=ip, port=port, verbose=False)
    SERVER.start_server(thread=True)
    SERVER.handle_client_function = handle_client_message
    play_thread = threading.Thread(target=play_audio, args=(SERVER,))
    play_thread.start()
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            SERVER.stop_server()
            return

def client_mode(ip: str, port: int, device_index: int) -> None:
    com = SecureConnection(host=ip, port=port, verbose=False)
    com.connect()
    com.start_listener(lambda audio: received_buffer.append(audio))
    print("launching audio thread")
    record_thread = threading.Thread(target=record_and_send_audio, args=(com, device_index,))
    record_thread.start()
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping client...")
            com.disconnect()
            return

def record_and_send_audio(connection: SecureConnection, device_index: int) -> None:
    """Records audio and sends it to the server."""
    p = pyaudio.PyAudio()
    
    stream = p.open(format=FORMAT,
                    channels=CHANNELS,
                    rate=RATE,
                    input=True,
                    input_device_index=device_index,
                    frames_per_buffer=CHUNK)
    
    while True and connection.is_connected():
        data = stream.read(CHUNK) # each chunk is 1024 * 2 = 2048 (because of 16-bit PCM) bytes
        connection.send(data)

    stream.stop_stream()
    stream.close()
    p.terminate()
 
def choose_microphone():
    """Lists available microphones and allows the user to choose one."""
    p = pyaudio.PyAudio()
    info = p.get_host_api_info_by_index(0)
    numdevices = info.get('deviceCount')
    
    print("Available microphones:")
    for i in range(numdevices):
        if p.get_device_info_by_host_api_device_index(0, i).get('maxInputChannels') > 0:
            print(f"{i}: {p.get_device_info_by_host_api_device_index(0, i).get('name')}")
    
    device_index = int(input("Select a microphone by index: "))
    return device_index
 
def main():
    mode = ask_while_valid("Enter 's' for server or 'c' for client: ", ['s', 'c'])
    ip = input("Enter the IP address (leave empty for localhost): ") or "localhost"
    port = int(input("Enter the port (leave empty for 43221): ") or 43221)
    device_index = choose_microphone()
    if mode == 's':
        logging.basicConfig(
            filename='chat.log',
            level=logging.INFO,
            format='%(asctime)s %(levelname)s: %(message)s'
        )
        server_mode(ip, port, device_index)
            
    elif mode == 'c':
        while True:
            try:
                client_mode(ip, port, device_index)
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