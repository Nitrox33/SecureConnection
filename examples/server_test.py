from connection import SecureConnection

socket = SecureConnection(host="localhost", port=43221, verbose=True) # Replace with your server's IP and port
socket.start_server() # start the server
socket.accept_client() # wait for a client to connect
socket.accept_client() # wait for a client to connect
for client in socket.clients:
    print(client) # print the client connection information
    socket.send(b"Hello World", client=client) # send encrypted message to all clients
socket.show()
# print(socket.recv()) # receive encrypted message
# print(socket.recv(encrypted=False)) # receive unencrypted message
# socket.disconnect() # disconnect from the client