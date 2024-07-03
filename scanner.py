#!/bin/python
import socket
import pyfiglet
import argparse
from datetime import datetime
import threading
from tqdm import tqdm
import struct
from scapy.all import ICMP, IP, sr1, conf
import ipaddress

ascii_banner = pyfiglet.figlet_format("Port Scanner with TTL")
print(ascii_banner)
open = []

TTL_VALUES = {
    "Windows": 128,
    "Linux/MacOS": 64, 
    "Network Device": 255
}

def ping_sweep(network):
    conf.verb = 0

    netv4 = ipaddress.ip_network(network, strict=False)

    for host in netv4.hosts():
        ip = str(host)
        pkt = IP(dst=ip)/ICMP()
        reply = sr1(pkt, timeout=1)

        if reply:
            print(f"{ip} is up")

def get_ttl_os(ttl):
    for os, ttl_value in TTL_VALUES.items():
        if ttl == ttl_value:
            return os
    return "Unknown"

def scan(IP, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)

    result = s.connect_ex((IP, port))
    if result == 0:
        open.append(port)
        try:
            ttl = struct.unpack("!B", s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1))[0]
            os_guess = get_ttl_os(ttl)
            open.append(os_guess)
        except Exception as e:
            print(f"Error getting TTL: {e}")

    s.close()

def scan_ports(IP):
    print(f"Scanning target: {IP}")
    start_time = datetime.now()

    try:
        thread = []
        port_range = range(1, 8000)
        with tqdm(total=len(port_range), desc="Scanning Ports") as pbar:
            for port in port_range:
                t = threading.Thread(target=scan, args=(IP, port))
                thread.append(t)
                t.start()
                pbar.update(1)
            
            for t in thread:
                t.join()
    except KeyboardInterrupt:
        print("\nExiting Program.")
        exit()
    except socket.gaierror:
        print("\nHostname could not be resolved")
        exit()
    except socket.error:
        print("\nServer not responding.")
        exit()
    
    end_time = datetime.now()
    total_time = end_time - start_time
    print(f"Scanning Completed {total_time}")



if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("-p", "--IP", help = "Specifies Target IP Address")

    parser.add_argument("-r", "--range", help = "Port Range, leave blank for 8000. Used to scan specific ports")

    parser.add_argument("-s", "--hosts", help = "Scans and displays available hosts")

    args = parser.parse_args()

    if args.IP:
        scan_ports(args.IP)
        print(open)
    if args.hosts:
        ping_sweep(args.hosts)
