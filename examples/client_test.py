from connection import SecureConnection
from time import sleep

socket = SecureConnection(host="localhost", port=43221, verbose=False) # Replace with your server's IP and port (verbose=True for debugging)
socket.connect() # connect to the server and and securely communicate a AES and HMAC keys
socket.send(b"Hello World") # send encrypted message
print(socket.recv()) # receive encrypted message
sleep(10)
socket.send(b"I have to go now, my planet needs me :-D") # send encrypted message
socket.disconnect() # disconnect from the server