# network_scanner
A simple network scanner written in Python

Required packages: Scapy (https://scapy.net/)

usage: net_scan.py [-h] [-t TARGET] [-m MODE] [-p PORT]

optional arguments:/n
  -h, --help            show this help message and exit/n
  -t TARGET, --target TARGET/n
                        Target IP, IP range to scan/n
  -m MODE, --mode MODE  Scanning mode. Options: ping: Ping sweep,arp: arp/n
                        ping,port: TCP port scan/n
  -p PORT, --port PORT  Port/s to scan. It can be a single port, or a list of/n
                        ports eg. 1,2-6,10/n
