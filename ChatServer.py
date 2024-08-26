import socket
from ChatWorker import ChatWorker


class ChatServer:
    def __init__(self, host, port):
        self.HOST = host
        self.PORT = port
        addr = ("", port)
        self.s = socket.create_server(addr, family=socket.AF_INET6, dualstack_ipv6=True)
        self.s.listen()
        self.clients = []
        print(f"Server is listening on port: {self.PORT}")

    def work(self):
        while True:
            acc = self.s.accept()
            worker = ChatWorker(self, acc[0], acc[1])
            worker.start()
            self.clients.append(acc)
            print(self.clients)

    def getClients(self):
        return self.clients


####################################################################
if __name__ == "__main__":
    #host = "2a02:8071:a86:75c0:400:d575:ed68:c4b0"
    host = "fe80::db9d:aa5d:f274:9349%5"
    port = 65432
    server = ChatServer(host, port)
    server.work()
