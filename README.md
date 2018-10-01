# network_scanner
A simple network scanner written in Python

Required packages: Scapy (https://scapy.net/)
```
usage: net_scan.py [-h] [-t TARGET] [-m MODE] [-p PORT]

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target IP, IP range to scan
  -m MODE, --mode MODE  Scanning mode. Options: ping: Ping sweep,arp: arp
                        ping,port: TCP port scan
  -p PORT, --port PORT  Port/s to scan. It can be a single port, or a list of
                        ports eg. 1,2-6,10
```
