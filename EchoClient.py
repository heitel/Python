import curses
import socket


HOST = "192.168.0.31"  # The server's hostname or IP address
PORT = 65432  # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True:
        print(f"Eingabe: ")
        ch = input()
        s.sendall(ch.encode())
        data = s.recv(1024)
        print(f"Received {data!r}")


