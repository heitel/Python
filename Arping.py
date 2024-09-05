from scapy.all import *
from scapy.layers.l2 import arping

if __name__ == "__main__":
    t = AsyncSniffer(filter="arp and arp[7]==2", timeout=10)
    t.start()
    ans = arping("10.192.0.0/19", cache=False, verbose=1, timeout=10)[0]
    t.join()

    devices = []
    for p in t.results:
       # print(f"{p.psrc, p.hwsrc}")
        devices.append({'ip': p.psrc, 'mac': p.hwsrc})

    print(f"Gefunden: {len(devices)} IPv4 Devices", flush=True)