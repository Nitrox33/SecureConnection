import asyncio
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP # for RSA encryption/decryption
from Crypto.Cipher import AES # for after the RSA key exchange
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
import logging 
from connection import Client, key_derivation


class AsyncioSecureConnection:
    """
    A class to handle secure connections using asyncio and socket.
    This class is designed to work with asyncio for asynchronous I/O operations.
    """
    def __init__(self, host: str = '127.0.0.1', port: int = 8888, verbose = False):
        self.verbose = verbose
        self.host = host
        self.port = port
        self.socket = None # the main socket for the server
        
        self.is_server = False
        self.is_client = False
        self.is_connected = lambda: self.is_server or self.is_client
        self.clients: list[Client] = []  # list of client sockets for the server
        
        self.private_key = None
        self.public_key = None
        self.aes_key = None
        self.hmac_key = None
        
        self.handle_client_function: callable = None # callback function to handle the client messages, must take 3 arguments: the AsyncioSecureConnection self, the message and the client object
        self.receiver_function: callable = None # callback function to handle the server messages, must take 2 arguments: the AsyncioSecureConnection self and the message
        self.on_exit_function: callable = None # callback function to handle the exit of the server, must take 2 argument: the AsyncioSecureConnection self and the client object

    def create_server_socket(self):
        """Create a server socket and bind it to the specified host and port."""
        logging.info(f"Creating server socket on {self.host}:{self.port}...")
        self.is_server = True
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.generate_rsa_key()
        self.socket.listen(5)
        self.socket.setblocking(False)  # Must set to non-blocking mode


    def generate_rsa_key(self, size: int = 2048, save: bool = False) -> None:
        """Generate an RSA key pair."""
        self.private_key = RSA.generate(size)
        self.public_key = self.private_key.public_key()
        if save:
            with open("private.pem", "wb") as f:
                print("Choose a secure passphrase to protect your private key: ")
                password = input()
                logging.info(f"Saving private key with passphrase: {password}")
                f.write(self.private_key.export_key(passphrase=password, pkcs=8, protection="scryptAndAES128-CBC")) # change passphrase
                logging.info("Private key saved as 'private.pem'.")
            with open("public.pem", "wb") as f:
                f.write(self.public_key.export_key(format="PEM"))
                logging.info("Public key saved as 'public.pem'.")

    def stop_server(self):
        """Stop the server and close all client connections."""
        self.is_server = False
        for client in self.clients:
            client.socket.close()
        if self.socket:
            self.socket.close()
        self.clients.clear()  # Clear the list of clients
        self.socket = None  # Clear the server socket
        logging.info("Server stopped and all client connections closed.")

    async def handle_client(self, client: Client):
        """
        Handles communication with a connected client.
        Receives data from the socket and echoes back the received message.
        """
        loop = asyncio.get_running_loop()
        logging.debug(f"Task for client {client.ip}:{client.port} Started.")
    
        try:
            while True and self.is_server and client in self.clients:
                # Receive data from the client asynchronously.
                message = await self.recv(client=client, encrypted=True)  # receive data from the client
                if not message:
                    logging.info(f"Client {client.ip}:{client.port} disconnected.")
                    break
                if self.handle_client_function:
                    # the user can handle the client function as a callback function
                    await self.handle_client_function(self, message, client)
                else:
                    logging.info(f"Received message from client {client.ip}:{client.port}: {message}")
                    logging.debug(f"Sending message to client {client.ip}:{client.port}: {message}")
                    await self.send(b"Message received!", encrypted=True, client=client)

        except asyncio.CancelledError:
            logging.info(f"Task for client {client.ip}:{client.port} cancelled.")
        except ConnectionError:
            logging.info(f"Client {client.ip}:{client.port} disconnected.")
        except Exception as e:
            logging.error(f"Error handling client {client.ip}:{client.port}: {e}")
        finally:
            client.socket.close()
            if client in self.clients:
                self.clients.remove(client)
            if self.on_exit_function:
                await self.on_exit_function(self, client)
            logging.debug(f"Task for client {client.ip}:{client.port} stopped.")

    async def handle_connections(self):
        """
        Accepts incoming connections and creates a new task for each client.
        """
        loop = asyncio.get_running_loop()
        try:
            while self.is_connected():
                # Accept a new connection asynchronously.
                logging.debug("Waiting for incoming connections...")
                client_sock, addr = await loop.sock_accept(self.socket)

                current_client = Client(client_sock)
                self.clients.append(current_client)
                try:
                    await self.send(self.public_key.export_key(format="DER"), client=current_client, encrypted=False)  # send public key to client    
                    self.server_salt = get_random_bytes(8)  # generate a random salt for the server
                    await self.send(self.server_salt, client=current_client, encrypted=False)  # send server's salt to client

                    # ---- receiving data from the client ----
                    logging.debug(f"Waiting for client {current_client.ip}:{current_client.port} to send main key and salt...")
                    r_key_encrypted = await self.recv(encrypted=False, client=current_client)  # receive main_key from client
                    client_salt_encrypted = await self.recv(encrypted=False, client=current_client)  # receive client salt
                    logging.debug(f"Received main key and client salt from client {current_client.ip}:{current_client.port}")

                    # ---- decrypting the main key ----
                    logging.debug(f"Decrypting main key with private key...")
                    main_key = self.decrypt_rsa(r_key_encrypted)  # decrypt the main_key with private key
                    self.client_salt = self.decrypt_rsa(client_salt_encrypted)  # decrypt the client salt with private key
                    logging.debug(f"Decrypted main key: {main_key.hex()[:8]}...")

                    # ---- key derivation ----
                    logging.debug(f"Deriving keys from main key...")
                    aes_key, hmac_key = key_derivation(main_key, self.server_salt, self.client_salt)  # derive keys from main key and salts
                    current_client.aes_key, current_client.hmac_key = aes_key, hmac_key  # derive a key from the AES key and server's salt
                
                except Exception as e:
                    logging.error(f"Error during key exchange with {current_client.ip}:{current_client.port}: {e}")
                    client_sock.close()
                    self.clients.remove(current_client)


                # Create and schedule a new asyncio task to handle the connection.
                logging.debug(f"Creating task for client {current_client.ip}:{current_client.port}...")
                asyncio.create_task(self.handle_client(current_client))
                logging.info(f"Client {current_client.ip}:{current_client.port} connected.")
        except asyncio.CancelledError:
            logging.info("Server stopped accepting new connections.")
        except Exception as e:
            logging.error(f"Error accepting connections: {e}")
            self.stop_server()

    async def send(self, message: bytes, client: Client = None, encrypted: bool = True):
        """
        Send a message to the client.
        If no client is specified, send to all connected clients.
        """
        if self.is_connected() == False:  # if not connected at all
            return

        if self.is_server:
            if not client: # if no client is specified, send to all clients
                mesg_to_send = message
                for client in self.clients:
                    if encrypted:
                        message = self.encrypt_aes_and_hmac(mesg_to_send, client.aes_key, client.hmac_key)
                    header = len(message).to_bytes(4, 'big')
                    await asyncio.get_event_loop().sock_sendall(client.socket, header + message)
            else:
                if encrypted:
                    message = self.encrypt_aes_and_hmac(message, client.aes_key, client.hmac_key)
                header = len(message).to_bytes(4, 'big')
                await asyncio.get_event_loop().sock_sendall(client.socket, header + message)

        elif self.is_client:
            if encrypted:
                message = self.encrypt_aes_and_hmac(message, self.aes_key, self.hmac_key)
            header = len(message).to_bytes(4, 'big')
            await asyncio.get_event_loop().sock_sendall(self.socket, header + message)
                
    async def recv(self, encrypted=True, client: Client = None) -> bytes:
        """Receive a message from the client."""
        if not self.is_connected: # if not connected at all
            return None

        if client is None: # if no client is specified, use the last client socket
            if self.is_server:
                client_socket = self.clients[-1].socket if self.clients else None  # get the last client socket
                aes_key, hmac_key = self.clients[-1].aes_key, self.clients[-1].hmac_key
            elif self.is_client:
                client_socket = self.socket
                aes_key, hmac_key = self.aes_key, self.hmac_key
        else:
            client_socket = client.socket # use the specified client socket
            aes_key, hmac_key = client.aes_key, client.hmac_key


        # --------- receive data ---------
        if client_socket:
            loop = asyncio.get_event_loop()
            try:
                header = await loop.sock_recv(client_socket, 4)  # Receive the header (4 bytes for message length)
                if not header:
                    raise ConnectionError("Socket closed or no data received.")
                message_length = int.from_bytes(header, 'big')
                data = b""
                while len(data) < message_length:
                    size =  message_length - len(data) # remaining size to receive - not needed if we use a fixed size
                    chunk = await loop.sock_recv(client_socket, size)
                    if not chunk:
                        raise ConnectionError("Socket closed during message reception.")
                    data += chunk

                if len(data) != message_length:
                    logging.error(f"Received incomplete message: {len(data)} bytes instead of {message_length} bytes.")
                    raise ValueError("Incomplete message received.")

                if encrypted:
                    data = self.decrypt_aes_and_hmac(data, aes_key, hmac_key)
                return data
            except (ConnectionError) as e:
                raise ConnectionError(f"Client disconnected {e}")
            except (ValueError) as e:
                logging.error(f"Error receiving data: {e}")
                return None
        return None

    async def connect(self, start_receiver: bool = True) -> None:
        """
        Connect to the server as a client.
        This function will perform the key exchange and establish a secure connection.
        """
        try:
            if self.is_client:
                logging.error("Already connected as a client.")
                return
            if self.is_server:
                logging.error("Already connected as a server.")
                return
            
            loop = asyncio.get_event_loop()

            # ----- create a socket and connect to the server ----
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # create a TCP socket
            self.socket.setblocking(False)

            await loop.sock_connect(self.socket, (self.host, self.port))  # connect to the server
            logging.info(f"Connected to {self.host}:{self.port}, exchanging keys...")
            
            self.is_client = True
            
            # ----- receiving data from the server ----
            logging.debug("Receiving public key and salt from server...")
            pub_key = await self.recv(encrypted=False)  # receive server's public key
            self.public_key = RSA.import_key(pub_key)
            self.server_salt = await self.recv(encrypted=False) # receive server's salt
            logging.debug(f"Received public key and salt from server: {self.server_salt.hex()}")
            
            # ---- sending data to the server ----
            logging.debug("Sending main key and salt to server...")
            main_key= get_random_bytes(16)  # generate a random main key
            main_key_encrypted = self.encrypt_rsa(main_key)  # encrypt the main key with server's public key
            await self.send(main_key_encrypted, encrypted=False) 
            self.client_salt = get_random_bytes(8)  # generate a random salt for the client
            client_salt_encrypted = self.encrypt_rsa(self.client_salt)
            await self.send(client_salt_encrypted, encrypted=False)  # send the client salt to the server
            logging.debug(f"Sent main key and salt to server: {self.client_salt.hex()}")

            # ---- key derivation ----
            logging.debug(f"Deriving keys from main key...")
            self.aes_key, self.hmac_key = key_derivation(main_key, self.server_salt, self.client_salt)  # derive a key from the AES key and server's saltr
            logging.debug(f"Derived keys: aes_key: {self.aes_key.hex()[:8]}... hmac_key: {self.hmac_key.hex()[:8]}...")
            logging.info(f"Client connected to server at {self.host}:{self.port}")

            if start_receiver:
                # Start the receiver task if requested.
                logging.debug("Starting receiver task...")
                asyncio.create_task(self.receiver())
        except Exception as e:
            logging.error(f"Error connecting to server: {e}")
            if self.socket:
                self.socket.close()
                self.socket = None

    async def receiver(self) -> None:
        """
        Start a receiver thread to handle incoming messages.
        This function will run in a separate thread and call the provided function with the received message.
        """
        if not self.is_client:
            logging.error("Not connected as a client.")
            return
        
        while self.is_connected():
            try:
                message = await self.recv(encrypted=True)  # receive data from the server
                logging.debug(f"Received message from server: {message}")
                if message and self.receiver_function:
                    await self.receiver_function(self, message)  # call the provided function with the received message
                elif message:
                    logging.info(f"Received message from server: {message}")

            except Exception as e:
                logging.error(f"Error receiving data: {e}")
                break
    
        self.is_client = False  # Keep the client connected
        logging.debug("Receiver task stopped.")

    def encrypt_rsa(self, message: bytes) -> bytes:
        """Encrypt a message using RSA public key."""
        if not self.public_key:
            raise ValueError("Public key is not available.")
        cipher = PKCS1_OAEP.new(self.public_key)
        encrypted_message = cipher.encrypt(message)
        return encrypted_message
    
    def decrypt_rsa(self, message: bytes) -> bytes:
        """Decrypt a message using RSA private key."""
        if not self.private_key:
            raise ValueError("Private key is not available.")
        cipher = PKCS1_OAEP.new(self.private_key)
        decrypted_message = cipher.decrypt(message)
        return decrypted_message

    def encrypt_aes_and_hmac(self, message: bytes, aes_key: bytes, hmac_key: bytes) -> bytes:
        """Encrypt a message using AES and HMAC."""
        if not aes_key or not hmac_key: 
            raise ValueError("AES key or HMAC key is not available.")
        
        # ---- AES encryption ----
        cipher = AES.new(aes_key, AES.MODE_CBC) # AES encryption
        iv = cipher.iv
        ciphertext = cipher.encrypt(pad(message, AES.block_size)) # AES encryption
        hmac = HMAC.new(hmac_key, ciphertext, SHA256).digest()
        
        return iv + ciphertext + hmac

    def decrypt_aes_and_hmac(self, message: bytes, aes_key: bytes, hmac_key: bytes) -> bytes:
        """Decrypt a message using AES and HMAC.
        This function will also verify the HMAC to ensure the integrity of the message.
        
        Args:
            message (bytes): The encrypted message to be decrypted. (format: iv[16] + ciphertext[:-32] + hmac[-32:])

        Returns:
            bytes: The decrypted message if HMAC verification is successful, None otherwise.
        """
        if len(message) < 16+32: # 16 bytes for iv and 32 bytes for hmac
            logging.error("Invalid message length.")
            return None
        
        iv = message[:AES.block_size]
        ciphertext = message[AES.block_size:-32]
        hmac = message[-32:]
        # ---- HMAC verification ----
        h = HMAC.new(hmac_key, ciphertext, SHA256)
        try:
            h.verify(hmac)
        except ValueError:
           raise ValueError("HMAC verification failed.")
        
        # ---- AES decryption ----
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        try:
            decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return decrypted_message
        except ValueError:
            raise ValueError("Decryption failed.")
        


async def main():
    server = AsyncioSecureConnection()
    server.create_server_socket()
    logging.info(f"Server started on {server.host}:{server.port}")
    try:
        await server.handle_connections()
    except KeyboardInterrupt:
        logging.info("Server stopped by user.")
    finally:
        server.socket.close()
        logging.info("Server socket closed.")

if __name__ == '__main__':
    asyncio.run(main())