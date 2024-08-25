import threading


class EchoWorker(threading.Thread):
    def __init__(self, server, acc):
        super().__init__(daemon=True)
        self.server = server
        self.socket = acc[0]
        self.addr = acc[1]
        print(f"Socket: {self.socket} Address: {self.addr}")

    def run(self):
        with self.socket:
            print(f"Connected by {self.addr}")
            while True:
                data = self.socket.recv(1024)
                print(data.decode())
                if not data:
                    break
                self.socket.sendall(data)
