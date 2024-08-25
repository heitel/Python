import threading
import time


class Counter(threading.Thread):
    def __init__(self, nr):
        super().__init__(daemon=True)
        self.current = 0
        self.nr = nr

    def run(self):
        while self.current <= 10:
            print(f"Nr = {self.nr}, current = {self.current}")
            time.sleep(1)
            self.current += 1


####################################################################
if __name__ == "__main__":
    counter1 = Counter(1)
    counter1.start()
    counter2 = Counter(2)
    counter2.start()

    counter1.join()
    counter2.join()