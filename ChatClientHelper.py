import sys
import threading


class ChatClientHelper(threading.Thread):
    def __init__(self, socket, name):
        super().__init__(daemon=True)
        self.socket = socket
        self.name = name

    def run(self):
        while True:
           # print(f"{self.name}: ", end="")
            ch = input()
            if len(ch) != 0:
                data = self.name + ": " + ch
                self.socket.sendall(data.encode())
                if ch[0] == "q":
                    sys.exit()
