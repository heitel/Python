import socket
import ChatClientHelper


class ChatClient:
    def __init__(self, name, host, port):
        self.name = name
        self.HOST = host
        self.PORT = port

    def work(self):
        if ":" in self.HOST:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.HOST, self.PORT))
        helper = ChatClientHelper.ChatClientHelper(s, self.name)
        helper.start()
        while True:
            data = s.recv(1024)
            if not data:
                break
            print(f"\n{data.decode()}")


if __name__ == "__main__":
    print(f"Name: ", end="")
    name = input()
  #  host = "2a02:8071:a86:75c0:400:d575:ed68:c4b0"
    host = "fe80::db9d:aa5d:f274:9349%5"
    port = 65432
    client = ChatClient(name, host, port)
    client.work()
