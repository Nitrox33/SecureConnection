from connection import SecureConnection, Client, MAX_MESSAGE_SIZE
from asyncConnection import AsyncioSecureConnection
from chat import ask_while_valid
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
import colorama
import logging 
import pyaudio # for audio input/output
import struct # for struct.unpack
import zlib # to compress the audio, not the best but works
import socket
import numpy as np
import asyncio
import time

colorama.init(autoreset=True)

logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s %(levelname)s: %(message)s'
        )

class SecureAudio(AsyncioSecureConnection):
    def __init__(self,host='localhost', port=12345, verbose=False) -> None:     
        super().__init__(host, port, verbose)
        self.received_buffer: list = []
        
        self.RATE: int = 16000 # Sample rate (44.1 kHz)
        self.CHANNELS: int = 1 # 1 channel for mono audio
        self.CHUNK: int = 1024 # 1024 samples per buffer (at 44.1 kHz, this is 23 ms)
        self.FORMAT: int  = pyaudio.paInt16 # 16-bit PCM (2 bytes per sample)

        self.TIME_PER_CHUNK: float = self.CHUNK / self.RATE # 0.023 time per chunk in seconds (test 0.8)
        logging.debug(f"Time per chunk: {self.TIME_PER_CHUNK} seconds")
        # 0.8 is a factor to reduce the time per chunk, this is to avoid lag in the audio

        self.muted = False # if True the mic wron't send audio to the server
        self.play = False # if True the server will play the audio received from the clients
        
        self.input_device_index: int = 0
        self.output_device_index: int = 0

        self.loop = None # asyncio loop

async def handle_client_message(server: SecureAudio, message: bytes, client: Client) -> None:
    """Handles incoming messages from clients."""
    if message.startswith(b"/message"):
        print(message[9:]) # print the rest
        return
    if len(client.input_buffer) > 20:
        return
    client.input_buffer.append(message) # add the message to the input buffer

async def handle_server_message(com: SecureAudio, message: bytes) -> None:
    """handle incoming messages from the server."""
    if message.startswith(b"/message"):
        print(message[9:]) # print the rest
        return
    if len(com.received_buffer) > 20:
        return
    com.received_buffer.append(message) # add the message to the input buffer

async def mix_multiple_audio(connection: SecureAudio):  # côté serveur
    logging.debug("Starting audio mixing...")
    debug_timing = []
    target = connection.TIME_PER_CHUNK * 0.8 # 0.8 is a factor to reduce the time per chunk, this is to avoid lag in the audio
    while connection.is_connected():
        try:
            t1 = time.perf_counter()
            latest_chunks = []
            # Construire la liste des derniers chunks et les consommer du buffer
            for client in connection.clients:
                if client.input_buffer:
                    # Optionnel : nettoyer le buffer si trop de valeurs accumulées
                    if len(client.input_buffer) > 5:
                        logging.warning(f"Buffer overflow for client {client.id}, dropping oldest packet.")
                        client.input_buffer.pop(0)
                    try:
                        # Retirer le premier élément du buffer et le stocker dans une variable
                        compressed_chunk = client.input_buffer.pop(0)
                        data = zlib.decompress(compressed_chunk)
                        latest_chunks.append(data)
                        # Stocker également ce chunk dans l'objet client pour usage ultérieur
                        client.latest_chunk = data
                    except Exception as e:
                        logging.error("Error while decompressing chunk: " + str(e))
                        continue
                else:
                    client.latest_chunk = generate_silence_chunk(connection.CHUNK)  # silence if no data

            if not latest_chunks:
                t2 = time.perf_counter()
                await asyncio.sleep(0.001) # wait for a bit if no data
                continue

            chunk = mix_frames_bytes(latest_chunks)  # création du mix global
            global_voice = np.frombuffer(chunk, dtype=np.int16)

            # Puis, dans votre boucle:
            tasks = []
            for client in connection.clients:
                if hasattr(client, "latest_chunk"):
                    tasks.append(process_and_send(client, global_voice, connection))

            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)


            await asyncio.sleep(target) # wait for a bit to avoid blocking the loop
            t2= time.perf_counter()
            debug_timing.append(t2-t1)
            if len(debug_timing) > 10:
                debug_timing.pop(0)
            logging.debug(f"Average time per chunk (mix): {sum(debug_timing)/len(debug_timing)*1000} milliseconds, target: {target*1000} milliseconds")
            target += (connection.TIME_PER_CHUNK - sum(debug_timing)/len(debug_timing))*0.1 # wait for the next chunk
        except Exception as e:
            logging.error("Error while mixing audio: " + str(e))
            await asyncio.sleep(0.001)
            
        
        # connection.received_buffer.append(zlib.compress(chunk)) # add the mixed chunk to the buffer
        # await connection.send(zlib.compress(chunk)) # send the mixed chunk to the server

async def process_and_send(client, global_voice, connection):
    try:
        # Fonction à exécuter dans un thread pour éviter le blocage de l'event loop.
        def mixing_task():
            voice_data = np.frombuffer(client.latest_chunk, dtype=np.int16)
            mixed_chunk = global_voice.copy() - voice_data
            mixed_chunk = np.clip(mixed_chunk, -32768, 32767).astype(np.int16)
            return zlib.compress(mixed_chunk.tobytes())

        to_send = await asyncio.get_running_loop().run_in_executor(None, mixing_task)
        await connection.send(to_send, client=client)
        del client.latest_chunk  # Nettoyage après traitement
    except Exception as e:
        logging.error("Error while mixing audio frames: " + str(e))

async def play_audio(connection: SecureAudio) -> None:
    """Plays audio from a list of chunks."""
    logging.debug("Starting audio playback...")
    p = pyaudio.PyAudio()
    n_number_time_too_long = 0  # Counter for silence detection
    stream = p.open(format=connection.FORMAT,
                    channels=connection.CHANNELS,
                    rate=connection.RATE,
                    output_device_index= connection.output_device_index if connection.output_device_index else None,
                    output=True)
    
    debug_timing = []
    t1 = time.perf_counter()
    while connection.is_connected():
        if connection.received_buffer:
            logging.debug(f"buffer len : {len(connection.received_buffer)}")
            if len(connection.received_buffer) > 3:
                n_number_time_too_long += 1
                if n_number_time_too_long > 5:
                    connection.received_buffer.clear()
                    n_number_time_too_long = 0
                    continue
                print("Buffer overflow, dropping oldest chunks")
                connection.received_buffer.pop(0)
            
            data = await asyncio.get_running_loop().run_in_executor(None, zlib.decompress, connection.received_buffer.pop(0))
            await asyncio.get_running_loop().run_in_executor(None, stream.write, data)
            t2 = time.perf_counter()
            debug_timing.append(t2-t1)
            t1 = time.perf_counter()
            
            if len(debug_timing) > 10:
                debug_timing.pop(0)
            logging.debug(f"Average time per chunk (playing): {sum(debug_timing)/len(debug_timing)*1000} milliseconds")

        else:
            await asyncio.sleep(0.0001)
    
    stream.stop_stream()
    stream.close()
    p.terminate()

async def record_and_send_audio(connection: SecureAudio) -> None:
    """Records audio and sends it to the server."""
    p = pyaudio.PyAudio()
    stream = p.open(
        format=connection.FORMAT,
        channels=connection.CHANNELS,
        rate=connection.RATE,
        input=True,
        input_device_index=connection.input_device_index,
        frames_per_buffer=connection.CHUNK
    )

    connection.threshold = 0  # Set a threshold for silence detection
    
    print("Audio thread launched")
    debug_timing = []

    while connection.is_connected():
        # Run the blocking stream.read() in a thread pool so it doesn't block the event loop.
        t1 = time.perf_counter()
        data = await asyncio.get_running_loop().run_in_executor(
            None, stream.read, connection.CHUNK
        )
        if not connection.muted:
            try:
                cdata = zlib.compress(data)  # compress the audio data
                if len(cdata) > connection.threshold:
                    await connection.send(cdata)
                    
                
                t2 = time.perf_counter()
                debug_timing.append(t2-t1)
                if len(debug_timing) > 10:
                    debug_timing.pop(0)
                logging.debug(f"Average time per chunk (recording): {sum(debug_timing)/len(debug_timing)*1000} milliseconds")
                await asyncio.sleep(connection.TIME_PER_CHUNK - (t2-t1)*2)  # wait for the next chunk

            except TimeoutError:
                print("Timeout error: Server not responding")
                continue
            except ConnectionResetError:
                print("Connection reset: Server not responding")
                break

    print("Stopping audio stream...")
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

async def server_mode(ip: str, port: int, input_index: int, output_index: int) -> None: # todo index_device
    server = SecureAudio(host=ip, port=port, verbose=False)
    server.loop = asyncio.get_event_loop()
    server.create_server_socket()
    server.handle_client_function = handle_client_message

    h = asyncio.create_task(server.handle_connections())
    m = asyncio.create_task(mix_multiple_audio(server)) # mix the incoming audio and send it to the clients
    #asyncio.create_task(play_audio(server)) # start the server loop
    session = PromptSession()
    try:
        with patch_stdout(True):
            while True:
                text: str = await session.prompt_async("> ") # waiting for commands
                if text.startswith("/info"):
                    print(f"Server IP: {ip}, Port: {port}")
                    print(f"Connected clients: {len(server.clients)}")
                    print("Client list:")
                    for client in server.clients:
                        print(f"{client.ip}:{client.port} - keys {client.aes_key.hex()[:8]}... {client.hmac_key.hex()[:8]}...")
                    continue
                if text.startswith("/kick"):
                    try:
                        client_ip = text.split(" ")[1]
                        client_port = int(text.split(" ")[2])
                        for client in server.clients:
                            if client.ip == client_ip and client.port == client_port:
                                server.kick_client(client)
                                break
                        else:
                            print(f"Client {client_ip}:{client_port} not found")
                            
                    except Exception as e:
                        print(f"Error kicking client: {e}")
                    continue
                if text.startswith("/help"):
                    print("this is the help panel")
                
    except KeyboardInterrupt:
        logging.info("Stopping server...")
        return
    except asyncio.CancelledError:
        server.stop_server()
        logging.info("Stopping server...")

async def client_mode(ip: str, port: int, device_index: int, output_index: int) -> None:
    com = SecureAudio(host=ip, port=port, verbose=False)
    com.loop = asyncio.get_event_loop()
    com.input_device_index = device_index # add the input device to the server object
    com.output_device_index = output_index # add the output device to the server object
    com.receiver_function = handle_server_message # set the function to handle incoming messages

    await com.connect(start_receiver=True) # start the receiver thread
    asyncio.create_task(play_audio(com)) # start the audio thread
    asyncio.create_task(record_and_send_audio(com)) # start the audio thread
    
    session = PromptSession()
    try:
        with patch_stdout(True):
            while True:
                text: str = await session.prompt_async("> ") # waiting for commands
                if text:
                    if text.startswith("/mute"):
                        com.muted = True
                    elif text.startswith("/unmute"):
                        com.muted = False
                    elif text.startswith("/reconnect"):
                        await com.connect(start_receiver=True)
                    elif text.startswith("/threshold"):
                        if hasattr(com, "threshold"):
                            try:
                                com.threshold = int(text.split(" ")[1])
                                print(f"Threshold set to {com.threshold}")
                            except:
                                print("Invalid threshold value")

                    elif text.startswith("/help"):
                        print("this is the help panel")
                        print("/mute: mute the microphone")
                        print("/unmute: unmute the microphone")
                        print("/reconnect: reconnect to the server")
                        print("/threshold <value>: set the threshold for silence detection")
                        print("/message <message>: send a message to the server")

                    elif text.startswith("/message"):
                        await com.send(text.encode())
                    
                        
    except KeyboardInterrupt:
        print("\nStopping client...")
        return

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

def choose_output_device():
    """Lists available output devices and allows the user to choose one."""
    p = pyaudio.PyAudio()
    info = p.get_host_api_info_by_index(0)
    numdevices = info.get('deviceCount')
    
    print("Available output devices:")
    for i in range(numdevices):
        if p.get_device_info_by_host_api_device_index(0, i).get('maxOutputChannels') > 0:
            print(f"{i}: {p.get_device_info_by_host_api_device_index(0, i).get('name')}")
    
    device_index = int(input("Select an output device by index: ") or 0)
    return device_index

def generate_silence_chunk(chunk_size: int) -> bytes:
    silent_chunk = np.zeros(chunk_size, dtype=np.int16)
    return silent_chunk

async def main():
    mode = await asyncio.to_thread(ask_while_valid, "Enter 's' for server or 'c' for client: ", ['s', 'c'])
    ip = await asyncio.to_thread(input, "Enter the IP address (leave empty for localhost): ") or socket.gethostbyname(socket.gethostname())
    port = await asyncio.to_thread(input, "Enter the port (leave empty for 43221): ") or 43221
    if mode == 'c':
        input_index = await asyncio.to_thread(choose_microphone)
        output_index = await asyncio.to_thread(choose_output_device)
    else:
        input_index = 0
        output_index = 0
        
    if mode == 's':
        await server_mode(ip, port, input_index, output_index)
            
    elif mode == 'c':
        await client_mode(ip, port, input_index, output_index)


if __name__ == "__main__":
    asyncio.run(main())