import logging
logging.getLogger("scapy").setLevel(logging.CRITICAL)

from scapy.all import *
from scapy.layers.inet6 import *
from scapy.layers.l2 import ARP


def reverse_dns_lookup(ip_address):
    try:
        # Führt eine Rückwärts-DNS-Suche durch und gibt den Hostnamen zurück
        host_name, _, _ = socket.gethostbyaddr(ip_address)
        return host_name
    except socket.herror:
        return None


def scan_network(network_range):
    arp_request = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    result = srp(packet, timeout=10, verbose=0)[0]

    devices = []
    # Verarbeitung der erhaltenen Antworten
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    print(f"Gefunden: {len(devices)} IPv4 Devices", flush=True)
    return devices

def sniff_icmpv6_responses(iface, timeout=10):
    # Sniff IPv6-Pakete auf dem Interface
    # ICMPv6 Request and Reply
    packets = sniff(filter="icmp6 and (ip6[40] == 128 or ip6[40] == 129)", iface=iface, timeout=timeout, promisc=True)

    erg = dict()
    for packet in packets:
        erg[packet[Ether].src] = packet[IPv6].src
            #print(f"Antwort von: {packet[IPv6].src} {packet[Ether].src}")

    return erg

def send_icmpv6_multicast(iface):
    for i in range(1):
        icmpv6_request = IPv6(dst="ff02::1") / ICMPv6EchoRequest(seq=i)
        send(icmpv6_request, iface=iface, verbose=False)


if __name__ == "__main__":
    conf.use_pcap = True
    interface = conf.iface
    print(f"Start scanning {interface}..................", flush=True)
    # Netzwerkrange, die gescannt werden soll, z.B. "192.168.0.0/24"
    network_range = "192.168.0.0/24"
    devices = scan_network(network_range)

    # Netzwerk-Interface, über das das Paket gesendet wird
    # win
    # interface = "WLAN"
    # macos
    # interface = "enp0s1"
    send_icmpv6_multicast(interface)
    erg = sniff_icmpv6_responses(interface)

    # Ausgabe der gefundenen Geräte
    print("Gefundene Geräte im Netzwerk:")
    print("MAC-Adresse             IPv4-Adresse      IPv6-Adresse                 Hostname")
    print("-" * 100)

    i = 1
    for device in devices:
        hostname = reverse_dns_lookup(device['ip'])
        try:
            ipv6 = erg[device['mac']]
        except:
            ipv6 = "n./a."
        print(f"{i}. {device['mac']}  {device['ip']: >16}    {ipv6: >25}    {hostname}")
        i += 1


