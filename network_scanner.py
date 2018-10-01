#!/usr/bin/env python

import scapy.all as scapy
import argparse, platform, os, threading, socket, sys
from netaddr import IPNetwork
from multiprocessing.pool import ThreadPool
import itertools, time


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP, IP range to scan")
    parser.add_argument("-m", "--mode", dest="mode", help="Scanning mode. Options: "
                                                          "ping: Ping sweep,"
                                                          "arp: arp ping,"
                                                          "port: TCP port scan")
    parser.add_argument("-p", "--port", dest="port", help="Port/s to scan. It can be a single port, "
                                                          "or a list of ports eg. 1,2-6,10")
    options = parser.parse_args()
    if not options.target:
        options.target = raw_input("Target :")
    if not options.mode:
        options.mode = raw_input("Scan mode :")
    if options.mode == "port":
        if not options.port:
            options.port = raw_input("Port range :")
            # Create a list of the requested ports
    if options.port:
        try:
            port_range = []
            for element in options.port.split(","):
                if "-" in element:
                    starting_port, ending_port = element.split("-")
                    starting_port, ending_port = int(starting_port), int(ending_port)
                    port_range.extend(range(starting_port, ending_port + 1))
                else:
                    starting_port = int(element)
                    port_range.append(starting_port)
            options.port = port_range
        except:
            print("[-] Wrong port range")
            print(parser.print_usage())
            exit(0)
    return options

def arp_ping(ip):
    clients = {}
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=0.5, verbose=False)[0]
    clients_list = []
    for element in answered_list:
        clients[element[1].psrc] = {"MAC": element[1].hwsrc}
    return clients


def ping(ip):
    op_system = platform.system()
    if op_system == "Windows":
        response = os.popen("ping -n 1 " + str(ip))
    elif op_system == "Linux":
        response = os.popen("ping -c 1 " + str(ip))
    else:
        response = os.popen("ping -c 1 " + str(ip))
    for line in response.readlines():
        if line.count("ttl") or line.count("TTL"):
            return ip



def ping_scan(ip):
    try:
        ip_list = [str(ip) for ip in IPNetwork(options.target)]
    except:
        print("[-] Wrong target")
        exit(0)
    # Create a multiprocessing pool
    pool = ThreadPool(processes=100)
    # Submit to the process pool as seperate tasks
    pool_outputs = pool.map(ping, ip_list)
    pool.close()
    pool.join()
    # Create the output dictionary of hosts that replied
    target_dict = {output: {} for output in pool_outputs if output}
    return target_dict


def connection_scan(ip_port):
    target_host, target_port = ip_port
    try:
        connection_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection_socket.connect((target_host, target_port))
        connection_socket.send("Hello\r\n")
        response = connection_socket.recv(50)
        socket.setdefaulttimeout(0.5)
        connection_socket.close()
        return (str(target_host), str(target_port), str(response).rstrip("\r\n"))
    except:
        pass

def port_scan(target, ports):
    target_dict = {}
    ip_list = [str(ip) for ip in IPNetwork(target)]
    combination = itertools.product(ip_list, ports)
    # Create a multiprocessing pool
    pool = ThreadPool(processes=100)
    pool_outputs = pool.map(connection_scan, combination)
    pool.close()
    pool.join()
    # Create the output dictionary of hosts that replied
    pool_outputs = [output for output in pool_outputs if output != None]
    for result in pool_outputs:
        target, port, response = result
        if target not in target_dict:
            target_dict[target] = {port: response}
        else:
            target_dict[target][port] = response
    return target_dict


def print_results(results):
    details_name = ""
    for target in results.keys():
        print("[+] Target alive :" + target)
        if results[target]:
            for header in results[target].keys():
                if header != "MAC":
                    details_name = "Port " + header
                else:
                    details_name = header
                print("\t" + details_name + ": " + str(results[target][header]))

def scan(options):
    target = options.target
    mode = options.mode
    port = options.port
    if mode == "ping":
        results = ping_scan(target)
    elif mode == "arp":
        results =arp_ping(target)
    elif mode == "port":
        results = port_scan(target, port)
    print_results(results)

options = get_arguments()
start_time = time.time()
scan(options)
print("Time passed: ", time.time() - start_time)
