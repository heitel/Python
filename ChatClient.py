import socket
import ChatClientHelper


def represents_int(s):
    try:
        int(s)
    except ValueError:
        return False
    else:
        return True


class ChatClient:
    def __init__(self, name, host, port):
        self.name = name
        self.HOST = host
        self.PORT = port
        print(f"Connecting to {host}, port {port} as {name}")

    def work(self):
        if ":" in self.HOST:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            part = self.HOST.split("%")
            if len(part) == 1:
                s.connect((self.HOST, self.PORT))
            else:
                if represents_int(part[1]):
                    scope_id = 0
                else:
                    scope_id = socket.if_nametoindex(part[1])
                s.connect((self.HOST, self.PORT, 0, scope_id))
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
#   host = "2a02:8071:a86:75c0:400:d575:ed68:c4b0"
#   host = "2a02:8071:a86:75c0:a1f3:ce93:186a:2fef"
#   host = "fe80::db9d:aa5d:f274:9349%en0"
    print(f"Host: ", end="")
    host = input()
    port = 65432
    client = ChatClient(name, host, port)
    client.work()
