import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP # for RSA encryption/decryption
from Crypto.Cipher import AES # for after the RSA key exchange
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import scrypt
from sys import getsizeof
import logging 
from concurrent.futures import ProcessPoolExecutor


"""
This script will implement a secure connection between a client and a server 
using RSA for authentication, AES for encryption and HMAC for integrity.

The connection will be established over TCP/IP. After the connection is established,
The server will respond with its public key and salt value. 
The client will respond with a random AES key encrypted with the server's public key and a random salt value.
The client and server will then derive a key from the AES key and the salt value using scrypt.
A simple HMAC mecanism is used to ensure the integrity and autentication of the messages.

todo: certificate?
todo: add a send_file function to send files
todo: add a receive_file function to receive files
todo logging
todo create better protocol for messages, like a header with the message type, length, name, etc.
"""

MAX_MESSAGE_SIZE: int = 1024**2 * 50 # 10 MB limit for the message size

def key_derivation(main_key: bytes, server_salt: bytes, client_salt: bytes) -> tuple[bytes, bytes]:
        salt = server_salt + client_salt  # concatenate the server and client salts
        main_key: bytes = scrypt(main_key, salt, 64, N=2**14, r=8, p=1)  # derive a key from the AES key and server's salt
        aes_key = main_key[:32]  # AES key (256 bits)
        hmac_key = main_key[32:]  # HMAC key (256 bits)
        return aes_key, hmac_key

class Client: # Client class to handle client management in the server
    """
    A class representing a client connected to the server.
    This class stores the client's IP address, port, socket, and keys.
    Attributes:
        ip (str): The IP address of the client.
        port (int): The port number of the client.
        socket (socket.socket): The socket associated with the client connection.
        aes_key (bytes): The AES key used for encryption/decryption.
        hmac_key (bytes): The HMAC key used for message integrity.
    """
    def __init__(self, socket: socket.socket):
        """ Initialize the Client object with the socket

        Args:
            socket (socket.socket): The socket associated with the client connection.
        """
        self.name = None
        self.name_color: str = None
        
        self.ip = socket.getpeername()[0]
        self.port = socket.getpeername()[1]
        self.socket = socket
        
        self.aes_key = None
        self.hmac_key = None

        self.id: int | None = None # id of the client, used to identify the client in the server
        self.input_buffer: list[bytes] = []
        
    def __repr__(self):
        return f"client {self.ip}:{self.port} --- aes_key: {self.aes_key.hex() if self.aes_key else 'None'} --- hmac_key: {self.hmac_key.hex() if self.hmac_key else 'None'}"

class SecureConnection:
    def __init__(self, host='localhost', port=12345, verbose=False, logging_path=None):
        socket.setdefaulttimeout(1)  # set a timeout for the socket to avoid blocking
        
        self.host = host
        self.port = port
        self.socket = None
        self.verbose = verbose
        
        self.is_server = False
        self.is_client = False
        self.is_connected = lambda: self.is_server or self.is_client
        self.clients: list[Client] = []  # list of client sockets for the server
        
        self.private_key = None
        self.public_key = None
        self.aes_key = None
        self.hmac_key = None
        
        self.threads: list[threading.Thread] = []
        self.handle_client_function: callable = None # callback function to handle the client messages, must take 3 arguments: the SecureConnexion self, the message and the client object
        
        if logging_path:
            logging.basicConfig(filename=logging_path, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        else:
            logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
        logging.info("SecureConnection initialized.")
        
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

    def load_rsa_key(self, private_key_path: str = None, public_key_path: str = None, password: str = None) -> None:
        """Load RSA keys from files."""
        if private_key_path:
            with open(private_key_path, "rb") as f:
                self.private_key = RSA.import_key(f.read(), passphrase=password)  # change passphrase
        if public_key_path:
            with open(public_key_path, "rb") as f:
                self.public_key = RSA.import_key(f.read())
        logging.info("RSA keys loaded.")

    def connect(self) -> None:
        """
        Connect to the server as a client.
        This function will perform the key exchange and establish a secure connection.
        """
        if self.is_client:
            logging.error("Already connected as a client.")
            return
        if self.is_server:
            logging.error("Already connected as a server.")
            return
        
        # ----- create a socket and connect to the server ----
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # create a TCP socket
        self.socket.connect((self.host, self.port))
        logging.info(f"Connected to {self.host}:{self.port}, exchanging keys...")
        
        self.is_client = True
        
        # ----- receiving data from the server ----
        logging.debug("Receiving public key and salt from server...")
        pub_key = self.recv(encrypted=False)  # receive server's public key
        self.public_key = RSA.import_key(pub_key)
        self.server_salt = self.recv(encrypted=False) # receive server's salt
        logging.debug(f"Received public key and salt from server: {self.server_salt.hex()}")
        
        # ---- sending data to the server ----
        logging.debug("Sending main key and salt to server...")
        main_key= get_random_bytes(16)  # generate a random main key
        main_key_encrypted = self.encrypt_rsa(main_key)  # encrypt the main key with server's public key
        self.send(main_key_encrypted, encrypted=False) 
        self.client_salt = get_random_bytes(8)  # generate a random salt for the client
        self.send(self.client_salt, encrypted=False)  # send client salt to server
        logging.debug(f"Sent main key and salt to server: {self.client_salt.hex()}")

        # ---- key derivation ----
        logging.debug(f"Deriving keys from main key...")
        self.aes_key, self.hmac_key = key_derivation(main_key, self.server_salt, self.client_salt)  # derive a key from the AES key and server's saltr
        logging.debug(f"Derived keys: aes_key: {self.aes_key.hex()[:8]}... hmac_key: {self.hmac_key.hex()[:8]}...")
        logging.info(f"Client connected to server at {self.host}:{self.port}")
    
    def disconnect(self, Client: Client = None) -> None:
        """Disconnect the client."""
        if self.is_client:
            self.is_client = False
            if self.threads:
                logging.info("Stopping threads...")
                for thread in self.threads:
                    thread.join() # wait for all threads to finish
            self.socket.close()
            self.socket = None
            logging.info("Client disconnected.")
        elif self.is_server: # we should finfd the thread that is managing the client
            if Client is None:
                self.clients[-1].socket.close()  # close the last client socket
                self.clients.pop()  # remove the last client from the list
            else:
                Client.socket.close()  # close the specified client socket
                self.clients.remove(Client)  # remove the specified client from the list
                
    def start_server(self, thread: bool = False) -> None:
        """Start the server."""
        socket.setdefaulttimeout(1)  # set a timeout for the socket to avoid blocking
        self.socket = socket.create_server((self.host, self.port))
        if not self.private_key:
            self.generate_rsa_key()   
        logging.info(f"Server started on {self.host}:{self.port}, waiting for clients...")
        self.socket.listen(5)
        self.is_server = True
        if thread:
            logging.info("Starting client manager thread...")
            self.threads.append(threading.Thread(target=self.client_manager))
            self.threads[-1].start()
                    
    def client_manager(self) -> None:
        """
        This function will run in a separate thread to manage client connections.
        It will accept client connections and start a new thread for each client.
        """
        if not self.is_server:
            logging.error("Server is not running.")
            return
        while True and self.is_server:
            try:
                self.accept_client(thread=True)  # accept a client connection
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break
            except Exception as e:
                logging.error(f"Error in client manager: {e}")
                break
        logging.debug("Client manager stopped.")
     
    def accept_client(self, thread: bool = False, timeout: float = 1.0) -> None:
        """Accept a client connection and perform key exchange.

        Args:
            thread (bool, optional): Whether to run the client handling in a separate thread. Defaults to False.
            timeout (float, optional): Timeout for the socket operation. Defaults to 1.0.
        """
        if not self.is_server:
            logging.error("Server is not running.")
            return
        
        #---- accept a client connection ----
        try:
            client_socket, addr = self.socket.accept()  # accept the client connection
        except socket.timeout:
            return
        except Exception:
            logging.error("Error accepting client connection.")
            return
        
        # --- create a client object and add it to the list of clients ---
        logging.info(f"Client accepted from {addr}")
        current_client = Client(client_socket)  # create a client object
        self.clients.append(current_client)  # add the client socket to the list of client sockets
        
        # ---- if problem with the client, close the socket and remove it from the list ----
        try:
            # ---- sending salt and public key to the client ----
            self.send(self.public_key.export_key(format="DER"), client=current_client, encrypted=False)  # send public key to client    
            self.server_salt = get_random_bytes(8)  # generate a random salt for the server
            self.send(self.server_salt, client=current_client, encrypted=False)  # send server's salt to client

            # ---- receiving data from the client ----
            logging.debug(f"Waiting for client {current_client.ip}:{current_client.port} to send main key and salt...")
            r_key_encrypted = self.recv(encrypted=False, client=current_client)  # receive main_key from client
            self.client_salt = self.recv(encrypted=False, client=current_client)  # receive client salt
            logging.debug(f"Received main key and client salt from client {current_client.ip}:{current_client.port}")

            # ---- decrypting the main key ----
            logging.debug(f"Decrypting main key with private key...")
            main_key = self.decrypt_rsa(r_key_encrypted)  # decrypt the main_key with private key
            logging.debug(f"Decrypted main key: {main_key.hex()[:8]}...")

            # ---- key derivation ----
            logging.debug(f"Deriving keys from main key...")
            with ProcessPoolExecutor() as executor: # use a process pool to optimize the key derivation time
                logging.debug(f"Main key: {main_key.hex()}")
                logging.debug(f"Salts: {self.server_salt.hex(), self.client_salt.hex()}")
                future = executor.submit(key_derivation, main_key, self.server_salt, self.client_salt)  # derive a key from the AES key and server's salt
                aes_key, hmac_key = future.result()
            logging.debug(f"Derived keys: aes_key: {aes_key.hex()[:8]}... hmac_key: {hmac_key.hex()[:8]}...")
            current_client.aes_key, current_client.hmac_key = aes_key, hmac_key  # derive a key from the AES key and server's salt
            
            # --- Start a new thread to handle the client ---
            if thread:
                logging.debug(f"Starting thread for client {current_client.ip}:{current_client.port}")
                self.threads.append(threading.Thread(target=self.handle_client, args=(current_client,)))
                self.threads[-1].start()
        except Exception as e:
            logging.error(f"Error during key exchange with client {current_client.ip}:{current_client.port}: {e}")
            current_client.socket.close()
            self.clients.remove(current_client)
        return

    def handle_client(self, current_client: Client) -> None:
        """
        Handle communication with a single client. (created by accept_client)
        This function will run in a separate thread for each client.
        """
        logging.debug(f"Thread for client {current_client.ip}:{current_client.port} Started.")
        while True and self.is_server:
            try:
                # --- receive data from the client ---
                message = self.recv(client=current_client, encrypted=True)
                if not message:
                    continue
                if self.handle_client_function:
                    # the user can handle the client function as a callback function
                    self.handle_client_function(self, message, current_client) # the callback function should handle the message and the client object
                else:
                    logging.info(f"Received message from client {current_client.ip}:{current_client.port}: {message}")
                    self.send(b"Message received!", encrypted=True, client=current_client)
            except socket.timeout:
                continue
            except Exception as e:
                current_client.socket.close()
                self.clients.remove(current_client)
                logging.info(f"Client {current_client.ip}:{current_client.port} disconnected.")
                break
        logging.debug(f"Thread [client handler] for client {current_client.ip}:{current_client.port} stopped.")
                
    def stop_server(self) -> None:
        logging.info("Stopping server...")
        """Stop the server."""
        if not self.is_server:
            logging.error("Server is not running.")
            return
        else:
            self.is_server = False
            
        if self.threads:
            for thread in self.threads:
                thread.join()
        self.threads.clear()
            
        for client in self.clients:
            client.socket.close()
        self.clients.clear()
        if self.socket:
            self.socket.close()
            logging.info("Server closed.")
        self.socket = None
    
    def start_listener(self, function: callable = None) -> None:
        logging.debug("Starting listener...")
        """Start a listener thread to receive data from the client."""
        if not self.is_client:
            logging.error("Client is not connected.")
            return
        self.threads.append(threading.Thread(target=self.listener, args=(function,)))
        self.threads[-1].start()
        logging.debug("Listener started.")
    
    def listener(self, function: callable) -> None:
        """Listen for incoming data in the client side"""
        if not self.is_client:
            logging.error("Client is not connected.")
            return
        if not self.socket:
            logging.error("Socket is not connected.")
            return
        while True and self.is_client:
            try:
                # ---- receive data from the server ----
                message = self.recv(encrypted=True)  # receive data from the server
                if not function:
                    logging.info(f"Received message from server: {message}")
                else:
                    function(message)
            except socket.timeout:
                if self.is_client:
                    continue
            except Exception as e:
                logging.error(f"Error receiving data from server: {e}")
                break
        logging.debug("Listener stopped.")
    
    def recv(self, encrypted=True, client: Client = None, file: bool = False) -> bytes:
        """Receive a message from the client."""
        if not self.is_server and not self.is_client: # if not connected at all
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

        if client_socket:
            try:
                header = client_socket.recv(4)
                if not header:
                    raise ConnectionError("Socket closed or no data received.")
                message_length = int.from_bytes(header, 'big')
                data = b""
                while len(data) < message_length:
                    size =  message_length - len(data) # remaining size to receive - not needed if we use a fixed size
                    chunk = client_socket.recv(size)
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
                raise ConnectionError("Client disconnected" + str(e))
            except (ValueError) as e:
                logging.error(f"Error receiving data: {e}")
                return None
        return None
    
    def send(self, message: bytes, encrypted: bool = True, client: Client = None, file_path: str = "") -> None:
        """Send a message to the client."""
        if not self.is_server and not self.is_client: # if not connected at all
            return
        
        if client is None:
            if self.is_server: # if server, send to the last client socket
                if len(self.clients) > 0:
                    client_socket = self.clients[-1].socket
                    aes_key, hmac_key = self.clients[-1].aes_key, self.clients[-1].hmac_key
                else:
                    logging.error("No clients connected.")
                    return
            elif self.is_client: # if client, send to the server socket
                client_socket = self.socket
                aes_key, hmac_key = self.aes_key, self.hmac_key
        else:
            client_socket = client.socket
            aes_key, hmac_key = client.aes_key, client.hmac_key
        
        if client_socket:
            if file_path != "": # if file path is specified, we need to send the file  #### to change
                # if file, we need to send the file size first
                with open(file_path, "rb") as file:
                    file_data = file.read()
                    file_data_encrypted = self.encrypt_aes_and_hmac(file_data, aes_key, hmac_key)
                    header = len(file_data_encrypted).to_bytes(4, 'big')
                    client_socket.sendall(header + b'/upload' + file_data_encrypted)
                return
            if encrypted:
                # Encrypt the message using AES and HMAC
                message = self.encrypt_aes_and_hmac(message, aes_key, hmac_key)
                header = len(message).to_bytes(4, 'big')
            else:
                header = len(message).to_bytes(4, 'big')
                
            client_socket.sendall(header + message)

        else:
            logging.error("Client socket is not connected.")

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
            print("Invalid message length.")
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
        
    def __repr__(self):
        return f"SecureConnection(aes_key={self.aes_key.hex() if self.aes_key else None}, hmac_key={self.hmac_key.hex() if self.hmac_key else None})"
     
    def show(self, verbose=False) -> None:
        """Display the current connection status."""
        print("Connection Status:")
        print(f"Host: {self.host}")
        print(f"Port: {self.port}")
        print(f"Socket: {self.socket}")
        print(f"Is Server: {self.is_server}")
        print(f"Is Client: {self.is_client}")
        
        if self.is_server:
            print(f"Server is running on {self.host}:{self.port}")
            if self.clients:
                print(f"Connected clients:")
                for client in self.clients:
                    print(f"- {client}")
        elif self.is_client:
            print(f"Client is connected to {self.host}:{self.port}")
        else:
            print("No connection established.")
        
        if self.private_key and verbose:
            print("Private Key:")
            print(self.private_key.export_key().decode())
            print(getsizeof(self.private_key))
        if self.public_key and verbose:
            print("Public Key:")
            print(self.public_key.export_key().decode())
            print(getsizeof(self.public_key))
        
        if self.socket:
            print("Socket Options:")
            print(self.socket.getsockname())  # local address
            print(self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF))  # in bytes
            print(self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF))