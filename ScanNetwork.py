import logging
import netifaces

logging.getLogger("scapy").setLevel(logging.CRITICAL)

from scapy.all import *
from scapy.layers.inet6 import *
from scapy.layers.l2 import ARP, arping


def reverse_dns_lookup(ip_address: str):
    try:
        # Führt eine Rückwärts-DNS-Suche durch und gibt den Hostnamen zurück
        host_name, _, _ = socket.gethostbyaddr(ip_address)
        return host_name
    except socket.herror:
        return None


def scan_network(network_range: str):
    # Filter for ARP-Reply
    t = AsyncSniffer(filter="arp and arp[7]==2", timeout=5)
    t.start()
    #    arping(network_range, verbose=False, timeout=5)
    arp_request = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    srp(packet, timeout=5, verbose=0)
    t.join()

    devices = dict()
    for p in t.results:
        devices[p[Ether].src] = p[ARP].psrc
    print(f"Gefunden: {len(devices)} IPv4 Devices", flush=True)
    return devices


def send_icmpv6_multicast(iface):
    t = AsyncSniffer(filter="icmp6 and (ip6[40] == 128 or ip6[40] == 129)", iface=iface, timeout=10, promisc=True)
    t.start()
    icmpv6_request = IPv6(dst="ff02::1") / ICMPv6EchoRequest()
    send(icmpv6_request, iface=iface, verbose=False)
    t.join()

    erg = dict()
    for packet in t.results:
        erg[packet[Ether].src] = packet[IPv6].src

    return erg


if __name__ == "__main__":
    print("IPv4 Interfaces *****************************")
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        for addr in addrs.get(netifaces.AF_INET, []):
            print('%-8s %s' % (iface, addr['addr']))

    print("IPv6 Interfaces *****************************")
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        for addr in addrs.get(netifaces.AF_INET6, []):
            print('%-8s %s' % (iface, addr['addr']))
    #   print("Welches Interface soll gescannt werden? ", end="")
    #   interface = input()
    #   if interface == "":
    #       interface = "enp0s1"

    conf.use_pcap = True
    interface = conf.iface
    # interface = "Ethernet"
    print(f"Start scanning {interface}..................", flush=True)
    network_range = "192.168.0.0/24"
    #network_range = "10.192.0.0/19"
    devices = scan_network(network_range)
    erg = send_icmpv6_multicast(interface)

    # Ausgabe der gefundenen Geräte
    print("Gefundene Geräte im Netzwerk:")
    print("MAC-Adresse             IPv4-Adresse      IPv6-Adresse                 Hostname")
    print("-" * 100)

    i = 1
    for device in devices:
        hostname = reverse_dns_lookup(devices[device])
        try:
            ipv6 = erg[device]
        except:
            ipv6 = "n./a."
        print(f"{i}. {device}  {devices[device]: >16}    {ipv6: >25}    {hostname}")
        i += 1
