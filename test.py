import logging
import time

logging.getLogger("scapy").setLevel(logging.CRITICAL)

from scapy.config import conf
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.l2 import Ether
from scapy.sendrecv import send, sendp, srp, sniff, AsyncSniffer


if __name__ == "__main__":
    conf.use_pcap = True
    t = AsyncSniffer(filter="icmp6 and (ip6[40] == 128 or ip6[40] == 129)", iface=conf.iface, timeout=10, promisc=True)
    t.start()

    for i in range(1):
        icmpv6_request =  IPv6(dst="ff02::1") / ICMPv6EchoRequest(seq=i)
        send(icmpv6_request, iface=conf.iface, verbose=True)

    t.join()

    results = t.results
    print(len(results))
    for packet in results:
        print(f"Antwort von: {packet[IPv6].src} {packet[Ether].src}")
"""
    packets = sniff(filter="icmp6", iface=conf.iface, timeout=10, promisc=True)

    for packet in packets:
        print(f"Antwort von: {packet[IPv6].src} {packet[Ether].src}")
"""