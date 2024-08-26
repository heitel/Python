import socket
import sys
import threading


class ChatWorker(threading.Thread):
    def __init__(self, server, socket, addr):
        super().__init__(daemon=True)
        self.server = server
        self.socket = socket
        self.addr = addr

    def run(self):
        with self.socket:
         #   print(f"Connected by {self.addr[0]}")
            while True:
                data = self.socket.recv(1024)
                if not data:
                    break
                text = data.decode()
                print(text)
                pos = text.find(":")
                posQ = text.find("q")
                clients = self.server.getClients()

                if pos + 2 == posQ:
                    print("Ende")
                    for i in range(len(clients)):
                        if clients[i][0] == self.socket:
                            clients.remove(clients[i])
                            self.socket.close()
                            break
                    break

                for c in clients:
                    if c[0] != self.socket:
                        c[0].sendall(data)
