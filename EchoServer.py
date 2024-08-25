import socket
import EchoWorker


class EchoServer:
    def __init__(self):
        self.HOST = "192.168.0.31"  # Standard loopback interface address (localhost)
        self.PORT = 65432  # Port to listen on (non-privileged ports are > 1023)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((self.HOST, self.PORT))
        self.s.listen()
        self.clients = []
        print(f"Server is listening on port: {self.PORT}")

    def work(self):
        while True:
            acc = self.s.accept()
            worker = EchoWorker.EchoWorker(self, acc)
            worker.start()
            self.clients.append(acc)


####################################################################
if __name__ == "__main__":
    server = EchoServer()
    server.work()
