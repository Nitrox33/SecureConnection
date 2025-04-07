import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP # for RSA encryption/decryption
from Crypto.Cipher import AES # for after the RSA key exchange
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import scrypt
from sys import getsizeof

"""
This script will implement a secure connection between a client and a server 
using RSA for authentication, AES for encryption and HMAC for integrity.

The connection will be established over TCP/IP. After the connection is established,
The server will respond with its public key and salt value. 
The client will respond with a random AES key encrypted with the server's public key and a random salt value.
The client and server will then derive a key from the AES key and the salt value using scrypt.
A simple HMAC mecanism is used to ensure the integrity and autentication of the messages.

"""

class Client: # Client class to handle client management in the server
    def __init__(self, socket):
        self.ip = socket.getpeername()[0]
        self.port = socket.getpeername()[1]
        self.socket = socket
        self.aes_key = None
        self.hmac_key = None
        
    def __repr__(self):
        return f"client {self.ip}:{self.port} --- aes_key: {self.aes_key.hex() if self.aes_key else 'None'} --- hmac_key: {self.hmac_key.hex() if self.hmac_key else 'None'}"

class SecureConnection:
    def __init__(self, host='localhost', port=12345, verbose=False):
        self.host = host
        self.port = port
        self.socket = None
        self.verbose = verbose
        
        self.is_server = False
        self.is_client = False
        self.clients: list = []  # list of client sockets for the server
        
        self.private_key = None
        self.public_key = None
        self.aes_key = None
        self.hmac_key = None
        
    def generate_rsa_key(self, size=2048, save=False):
        """Generate an RSA key pair."""
        self.private_key = RSA.generate(size)
        self.public_key = self.private_key.public_key()
        if save:
            with open("private.pem", "wb") as f:
                print("Choose a secure passphrase to protect your private key: ")
                password = input()
                print(f"saving private key... with passphrase '{password}'")
                f.write(self.private_key.export_key(passphrase=password, pkcs=8, protection="scryptAndAES128-CBC")) # change passphrase
                print("Private key saved as 'private.pem'.")
            with open("public.pem", "wb") as f:
                f.write(self.public_key.export_key(format="PEM")) # change passphrase
                print("Public key saved as 'public.pem'.")

    def load_rsa_key(self, private_key_path=None, public_key_path=None):
        """Load RSA keys from files."""
        if private_key_path:
            with open(private_key_path, "rb") as f:
                self.private_key = RSA.import_key(f.read())
        if public_key_path:
            with open(public_key_path, "rb") as f:
                self.public_key = RSA.import_key(f.read())
        print("RSA keys loaded.")

    def connect(self):
        """Establish a connection to the server."""
        if self.is_client:
            print("Already connected to server.")
            return
        if self.is_server:
            print("Cannot connect as a client while the server is running.")
            return
        
        # ----- create a socket and connect to the server ----
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        print(f"Connected to server at {self.host}:{self.port}")
        self.is_client = True
        
        # ----- receiving data from the server ----
        pub_key = self.recv(encrypted=False)  # receive server's public key
        self.public_key = RSA.import_key(pub_key)
        if self.verbose: print(f"Received server's public key")
        self.server_salt = self.recv(encrypted=False) # receive server's salt
        if self.verbose: print(f"Received server's salt: {self.server_salt.hex()}")
        
        # ---- sending data to the server ----
        main_key= get_random_bytes(16)  # generate a random main key
        main_key_encrypted = self.encrypt_rsa(main_key)  # encrypt the main key with server's public key
        self.send(main_key_encrypted, encrypted=False) 
        if self.verbose: print(f"Sent main key to server: {main_key.hex()}")
        self.client_salt = get_random_bytes(8)  # generate a random salt for the client
        self.send(self.client_salt, encrypted=False)  # send client salt to server
        if self.verbose: print(f"Sent client salt: {self.client_salt.hex()}") 

        # ---- key derivation ----
        self.key_derivation(main_key)  # derive a key from the AES key and server's saltr
    
    def disconnect(self) -> None:
        """Disconnect the client."""
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # Socket already closed
            self.socket.close()
        self.socket = None

    def start_server(self) -> None:
        """Start the server."""
        self.socket = socket.create_server((self.host, self.port))
        if not self.private_key:
            self.generate_rsa_key()   
        print(f"Server started at {self.host}:{self.port}")
        self.is_server = True 
        
    def accept_client(self) -> None:
        """Accept a client connection."""
        if not self.is_server:
            print("Server is not running.")
            return
        
        #---- accept a client connection ----
        client_socket, addr = self.socket.accept() # accept the client connection
        print(f"Connection accepted from {addr}")
        current_client = Client(client_socket)  # create a client object
        self.clients.append(current_client)  # add the client socket to the list of client sockets
        # ---- sending salt and public key to the client ----
        self.send(self.public_key.export_key(format="DER"), client=current_client, encrypted=False)  # send public key to client    
        self.server_salt = get_random_bytes(8)  # generate a random salt for the server
        self.send(self.server_salt, client=current_client, encrypted=False)  # send server's salt to client
        if self.verbose: print(f"Sent server's salt: {self.server_salt.hex()}")

        # ---- receiving data from the client ----
        r_key_encrypted = self.recv(encrypted=False, client=current_client)  # receive main_key from client
        if self.verbose: print(r_key_encrypted.hex())
        main_key = self.decrypt_rsa(r_key_encrypted)  # decrypt the main_key with private key
        if self.verbose: print(f"main key: {main_key.hex()}")
        self.client_salt = self.recv(encrypted=False, client=current_client)  # receive client salt
        if self.verbose: print(f"Received client salt: {self.client_salt.hex()}")
        
        # ---- key derivation ----
        self.key_derivation(main_key)  # derive a key from the AES key and server's salt
        current_client.aes_key = self.aes_key
        current_client.hmac_key = self.hmac_key
        return

    def key_derivation(self, main_key:bytes) -> bytes:
        salt = self.server_salt + self.client_salt  # Ensure fixed lengths for salts
        main_key: bytes = scrypt(main_key, salt, 64, N=2**14, r=8, p=1)  # derive a key from the AES key and server's salt
        self.aes_key = main_key[:32]  # AES-256 key (32 bytes)
        self.hmac_key = main_key[32:]  # use the last 32 bytes as the HMAC key
        if self.verbose: print(f"AES key: {self.aes_key.hex()}")
        if self.verbose: print(f"HMAC key: {self.hmac_key.hex()}")
        return self.aes_key, self.hmac_key
        
    def stop_server(self) -> None:
        """Stop the server."""
        if self.socket:
            self.socket.close()
            print("Server stopped.")
        self.socket = None
        self.is_server = False
        
    def recv(self, encrypted=True, client: Client=None) -> bytes:
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
                    size = min(2048, message_length - len(data))
                    chunk = client_socket.recv(size)
                    if not chunk:
                        raise ConnectionError("Socket closed during message reception.")
                    data += chunk

                if len(data) != message_length:
                    raise ValueError("Incomplete message received.")

                if encrypted:
                    data = self.decrypt_aes_and_hmac(data, aes_key, hmac_key)
                return data
            except (ConnectionError, ValueError) as e:
                print(f"Error receiving data: {e}")
                return None
        return None
    
    def send(self, message:bytes, encrypted=True, client:Client=None) -> None:
        """Send a message to the client."""
        if not self.is_server and not self.is_client: # if not connected at all
            return
        
        if client is None:
            if self.is_server: # if server, send to the last client socket
                if len(self.clients) > 0:
                    client_socket = self.clients[-1].socket
                    aes_key, hmac_key = self.clients[-1].aes_key, self.clients[-1].hmac_key
                else:
                    print("No connected clients.")
                    return
            elif self.is_client: # if client, send to the server socket
                client_socket = self.socket
                aes_key, hmac_key = self.aes_key, self.hmac_key
        else:
            client_socket = client.socket
            aes_key, hmac_key = client.aes_key, client.hmac_key
        
        if client_socket:
            if encrypted:
                # Encrypt the message using AES and HMAC
                message = self.encrypt_aes_and_hmac(message, aes_key, hmac_key)
                header = len(message).to_bytes(4, 'big')
            else:
                header = len(message).to_bytes(4, 'big')
                
            client_socket.sendall(header + message)

        else:
            print("No connected.")

    def encrypt_rsa(self, message:bytes) -> bytes:
        """Encrypt a message using RSA public key."""
        if not self.public_key:
            raise ValueError("Public key is not available.")
        cipher = PKCS1_OAEP.new(self.public_key)
        encrypted_message = cipher.encrypt(message)
        return encrypted_message
    
    def decrypt_rsa(self, message:bytes) -> bytes:
        """Decrypt a message using RSA private key."""
        if not self.private_key:
            raise ValueError("Private key is not available.")
        cipher = PKCS1_OAEP.new(self.private_key)
        decrypted_message = cipher.decrypt(message)
        return decrypted_message

    def encrypt_aes_and_hmac(self, message:bytes, aes_key:bytes, hmac_key:bytes) -> bytes:
        """Encrypt a message using AES and HMAC."""
        if not aes_key or not hmac_key: 
            raise ValueError("AES key or HMAC key is not available.")
        
        # ---- AES encryption ----
        cipher = AES.new(aes_key, AES.MODE_CBC) # AES encryption
        iv = cipher.iv
        ciphertext = cipher.encrypt(pad(message, AES.block_size)) # AES encryption
        hmac = HMAC.new(hmac_key, ciphertext, SHA256).digest()
        #print(iv.hex(), ciphertext.hex(), hmac.hex())
        return iv + ciphertext + hmac

    def decrypt_aes_and_hmac(self, message:bytes, aes_key:bytes, hmac_key:bytes) -> bytes:
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



