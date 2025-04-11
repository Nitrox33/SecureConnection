from connection import SecureConnection, Client, MAX_MESSAGE_SIZE
from chat import ask_while_valid
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
import colorama
import logging 
import pyaudio # for audio input/output
import struct # for struct.unpack
import zlib # to compress the audio, not the best but works
import time
import threading

colorama.init(autoreset=True)

class SecureAudio(SecureConnection):
    def __init__(self,host='localhost', port=12345, verbose=False, logging_path=None) -> None:     
        super().__init__(host, port, verbose, logging_path)
        self.received_buffer: list = []
        
        self.RATE: int = 44100 # Sample rate (44.1 kHz)
        self.CHANNELS: int = 1 # 1 channel for mono audio
        self.CHUNK: int = 1024 # 1024 samples per buffer (at 44.1 kHz, this is 23 ms)
        self.FORMAT: int  = pyaudio.paInt16 # 16-bit PCM (2 bytes per sample)

        self.TIME_PER_CHUNK: float = self.CHUNK / self.RATE # 0.023 time per chunk in seconds
        
        self.muted = False # if True the mic wron't send audio to the server
        self.play = False # if True the server will play the audio received from the clients
        
        self.input_device_index: int = 0
        self.output_device_index: int = 0

def handle_client_message(server: SecureAudio, message: bytes, client: Client) -> None:
    """Handles incoming messages from clients."""
    if message.startswith(b"/message"):
        print(message[9:]) # print the rest
        return
    if len(client.input_buffer) > 20:
        return
    client.input_buffer.append(message) # add the message to the input buffer

def play_audio(connection: SecureAudio) -> None:
    """Plays audio from a list of chunks."""
    p = pyaudio.PyAudio()
    stream = p.open(format=connection.FORMAT,
                    channels=connection.CHANNELS,
                    rate=connection.RATE,
                    output=True)
    
    while True and connection.is_connected():
        latest_chunks = []
        for client in connection.clients:
            if client.input_buffer:
                if len(client.input_buffer) > 3:
                    client.input_buffer.pop(0)
                data = zlib.decompress(client.input_buffer.pop(0)) # decompress the audio data
                latest_chunks.append(data)
        if not latest_chunks:
            time.sleep(0.01)
            continue
        chunk = mix_frames_bytes(latest_chunks) # mix the chunks
        stream.write(chunk)
    
    stream.stop_stream()
    stream.close()
    p.terminate()

def mix_frames_bytes(frames: list[bytes]) -> bytes:
    """
    Mixes multiple PCM audio frames (in bytes) into a single audio frame by summing corresponding samples.

    Args:
        frames (List[bytes]): A list of audio frames in bytes, where each frame is raw 16-bit PCM data.

    Returns:
        bytes: A mixed audio frame in raw 16-bit PCM format.
    """
    if not frames:
        return b''

    frame_length = len(frames[0])
    num_samples = frame_length // 2  # Each sample is 2 bytes (16-bit)

    # Unpack all frames into lists of integers
    unpacked_frames = [list(struct.unpack('<' + 'h' * num_samples, f)) for f in frames]

    # Mix the frames
    mixed = [0] * num_samples
    for frame in unpacked_frames:
        for i in range(num_samples):
            mixed[i] += frame[i]

    # Clamp to 16-bit PCM range
    clamped = [max(min(sample, 32767), -32768) for sample in mixed]

    # Pack back into bytes
    return struct.pack('<' + 'h' * num_samples, *clamped)

def server_mode(ip: str, port: int, device_index: int) -> None: # todo index_device
    server = SecureAudio(host=ip, port=port, verbose=False, logging_path=None)
    server.start_server(thread=True)
    server.handle_client_function = handle_client_message
    play_thread = threading.Thread(target=play_audio, args=(server,))
    play_thread.start()
    session = PromptSession()
    try:
        with patch_stdout(True):
            while True:
                text: str = session.prompt("> ") # waiting for commands
                if text.startswith("/help"):
                    print("this is the help panel")
                
    except KeyboardInterrupt:
        server.stop_server()
        return

def client_mode(ip: str, port: int, device_index: int) -> None:
    com = SecureAudio(host=ip, port=port, verbose=False, logging_path=None)
    com.connect()
    com.input_device_index = device_index # add the input device to the server object
    com.start_listener(lambda audio: com.received_buffer.append(audio))
    start_record_and_send_thread(com)
    session = PromptSession()
    try:
        with patch_stdout(True):
            while True:
                text: str = session.prompt("> ") # waiting for commands
                if text:
                    if text.startswith("/mute"):
                        com.muted = True
                    elif text.startswith("/unmute"):
                        com.muted = False
                    elif text.startswith("/reconnect"):
                        com.disconnect()
                        com.connect()
                        com.start_listener(lambda audio: com.received_buffer.append(audio))
                        start_record_and_send_thread(com)

                    else:
                        com.send(b'/message ' + text.encode())
                    
                        
    except KeyboardInterrupt:
        print("\nStopping client...")
        com.disconnect()
        return

def start_record_and_send_thread(connection: SecureAudio) -> None:
    print("launching audio thread")
    record_thread = threading.Thread(target=record_and_send_audio, args=(connection,))
    record_thread.start()

def record_and_send_audio(connection: SecureAudio) -> None:
    """Records audio and sends it to the server."""
    p = pyaudio.PyAudio()
    stream = p.open(format=connection.FORMAT,
                    channels=connection.CHANNELS,
                    rate=connection.RATE,
                    input=True,
                    input_device_index=connection.input_device_index,
                    frames_per_buffer=connection.CHUNK)
    
    print("thread launched")
    while True and connection.is_connected():
        data = stream.read(connection.CHUNK) # if each chunk is 1024 * 2 = 2048 bytes (because of 16-bit PCM that is 2 bytes per sample)
        if not connection.muted:
            try:
                cdata = zlib.compress(data) # compress the audio data
                logging.debug(f"Sending audio data to server: {len(cdata)} bytes")
                connection.send(cdata)
            except TimeoutError:
                print("Timeout error: Server not responding")
                continue
            except ConnectionResetError:
                print("Connection reset error: Server not responding")
                break

    print("Stopping audio stream...")
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
    
    device_index = int(input("Select a microphone by index: ") or 0)
    return device_index

def main():
    mode = ask_while_valid("Enter 's' for server or 'c' for client: ", ['s', 'c'])
    ip = input("Enter the IP address (leave empty for localhost): ") or "localhost"
    port = int(input("Enter the port (leave empty for 43221): ") or 43221)
    device_index = choose_microphone()
    if mode == 's':
        logging.basicConfig(
            level=logging.DEBUG,
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