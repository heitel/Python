import logging
logging.getLogger("scapy").setLevel(logging.CRITICAL)

from scapy.all import *
from scapy.layers.inet6 import *


def reverse_dns_lookup(ip_address):
    try:
        # Führt eine Rückwärts-DNS-Suche durch und gibt den Hostnamen zurück
        host_name, _, _ = socket.gethostbyaddr(ip_address)
        return host_name
    except socket.herror:
        return None


def scan_network(network_range):
    # Erstellen eines ARP-Anfrage-Pakets
    arp_request = ARP(pdst=network_range)
    # Erstellen eines Ethernet-Frames, um die ARP-Anfrage zu senden
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    # Kombinieren des Ethernet-Frames und der ARP-Anfrage
    packet = ether / arp_request

    # Senden des Pakets und Empfangen der Antworten
    result = srp(packet, timeout=3, verbose=0)[0]

    # Leere Liste für die Geräte im Netzwerk
    devices = []

    # Verarbeitung der erhaltenen Antworten
    for sent, received in result:
        # IP- und MAC-Adresse der Antwort hinzufügen
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def sniff_icmpv6_responses(iface, timeout=10):
    # Sniff IPv6-Pakete auf dem Interface
    packets = sniff(iface=iface, timeout=timeout, promisc=True)

    erg = dict()
    # Zeige alle empfangenen ICMPv6-Pakete an
    for packet in packets:
        if ICMPv6EchoReply in packet:
            erg[packet[Ether].src] = packet[IPv6].src
            #print(f"Antwort von: {packet[IPv6].src} {packet[Ether].src}")

    return erg;

def send_icmpv6_multicast(iface):
    # Erstelle ein ICMPv6 Echo Request Paket (Ping)
    icmpv6_request = IPv6(dst="ff02::1") / ICMPv6EchoRequest()

    # Sende das ICMPv6 Echo Request Paket
    send(icmpv6_request, iface=iface, verbose=False)


if __name__ == "__main__":
    print("Start scanning....")
    # Netzwerkrange, die gescannt werden soll, z.B. "192.168.0.0/24"
    network_range = "192.168.0.0/24"
    devices = scan_network(network_range)

    # Netzwerk-Interface, über das das Paket gesendet wird
    interface = "en0"
    # Sende das ICMPv6 Echo Request Paket
    send_icmpv6_multicast(interface)
    # Sniffe die ICMPv6-Antworten
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


