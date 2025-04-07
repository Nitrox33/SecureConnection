from connection import SecureConnection

socket = SecureConnection(host="localhost", port=43221, verbose=True) # Replace with your server's IP and port
socket.start_server() # start the server
socket.accept_client() # wait for a client to connect
print(socket.recv()) # receive encrypted message
print(socket.recv(False)) # receive unencrypted message
socket.disconnect() # disconnect from the client