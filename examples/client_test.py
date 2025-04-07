from connection import SecureConnection

socket = SecureConnection(host="localhost", port=43221, verbose=False) # Replace with your server's IP and port (verbose=True for debugging)
socket.connect() # connect to the server and and securely communicate a AES and HMAC keys
socket.send(b"Hello World") # send encrypted message
socket.send(b"Hello World", encrypted=False) # send unencrypted message
socket.disconnect() # disconnect from the server