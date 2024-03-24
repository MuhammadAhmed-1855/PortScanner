import os
import sys
import socket
from scapy.all import *

def draw_p():
    return [
        "$$$$$$  ",
        "$     $ ",
        "$     $ ",
        "$$$$$$  ",
        "$       ",
        "$       ",
        "$       "
    ]

def draw_o():
    return [
        " $$$$$  ",
        "$     $ ",
        "$     $ ",
        "$     $ ",
        "$     $ ",
        "$     $ ",
        " $$$$$  "
    ]

def draw_r():
    return [
        "$$$$$$  ",
        "$     $ ",
        "$     $ ",
        "$$$$$$  ",
        "$ $     ",
        "$  $    ",
        "$    $  "
    ]

def draw_t():
    return [
        "$$$$$$$$",
        "   $    ",
        "   $    ",
        "   $    ",
        "   $    ",
        "   $    ",
        "   $    "
    ]

def draw_s():
    return [
        " $$$$$  ",
        "$     $ ",
        "$       ",
        " $$$$$  ",
        "      $ ",
        "$     $ ",
        " $$$$$  "
    ]

def draw_c():
    return [
        "  $$$$  ",
        " $    $ ",
        "$       ",
        "$       ",
        "$       ",
        " $    $ ",
        "  $$$$  "
    ]

def draw_a():
    return [
        "   $    ",
        "  $ $   ",
        " $   $  ",
        "$$$$$$$ ",
        "$     $ ",
        "$     $ ",
        "$     $ "
    ]

def draw_n():
    return [
        "$     $",
        "$$    $",
        "$ $   $",
        "$  $  $",
        "$   $ $",
        "$    $$",
        "$     $"
    ]

def draw_e():
    return [
        "$$$$$$ ",
        "$      ",
        "$      ",
        "$$$$$$ ",
        "$      ",
        "$      ",
        "$$$$$$ "
    ]

def draw_r():
    return [
        "$$$$$$ ",
        "$     $",
        "$     $",
        "$$$$$$ ",
        "$  $   ",
        "$   $  ",
        "$    $ "
    ]
    
def draw_ra():
    return [
        "$$$$$$",
        "$     $",
        "$     $      $$$ $   $     $     $     $ $$   $$ $$$$$ $$$      ",
        "$$$$$$       $ $  $ $     $ $    $     $ $ $ $ $ $     $  $$   ",
        "$  $         $$    $     $   $   $$$$$$$ $  $  $ $$$   $   $  ",
        "$   $        $ $   $    $$$$$$$  $     $ $     $ $     $  $$   ",
        "$    $       $$$   $   $       $ $     $ $     $ $$$$$ $$$       "
    ]

# Function to perform ICMP Ping Scan
def icmp_ping_scan(target):
    ans, unans = sr(IP(dst=target)/ICMP(), timeout=2, verbose=False)
    for snd, rcv in ans:
        print(rcv.sprintf("ICMP Ping: %IP.src% is up"))

# Function to perform UDP Ping Scan
def udp_ping_scan(target):
    ans, unans = sr(IP(dst=target)/UDP(dport=1), timeout=2, verbose=False)
    if ans:
        for snd, rcv in ans:
            print(rcv.sprintf("UDP Ping: %IP.src% is up"))
    else:
        print("UDP Ping: No response received.")

# Function to process scan results
def process_results(ans, unans, open_ports, closed_ports):
    for snd, rcv in ans:
        if rcv.haslayer(TCP):
            if rcv[TCP].flags == 0x14:  # RST, ACK
                closed_ports.append(rcv.sport)
            elif rcv[TCP].flags == 0x12:  # SYN, ACK
                open_ports.append(rcv.sport)

    if unans:
        for snd in unans:
            closed_ports.append(snd.dport)

# Function to perform SYN Scan
def syn_scan(target, ports):
    open_ports = []
    closed_ports = []
    ans, unans = sr(IP(dst=target)/TCP(sport=RandShort(), dport=ports, flags="S"), timeout=2, verbose=False)
    for snd, rcv in ans:
        if rcv.haslayer(TCP) and rcv[TCP].flags == 0x12:  # SYN, ACK
            open_ports.append(rcv.sport)
    if unans:
        for snd in unans:
            closed_ports.append(snd.dport)  # Append unresponsive ports to closed_ports
    print_results(open_ports, closed_ports)

# Function to perform Stealth Scan (Half Open Scan)
def stealth_scan(target, ports):
    open_ports = []
    closed_ports = []
    ans, unans = sr(IP(dst=target)/TCP(sport=RandShort(), dport=ports, flags="S"), timeout=2, verbose=False)
    for snd, rcv in ans:
        if rcv.haslayer(TCP) and rcv[TCP].flags == 0x12:  # SYN, ACK
            open_ports.append(rcv.sport)
    if unans:
        for snd in unans:
            closed_ports.append(snd.dport)  # Append unresponsive ports to closed_ports
    print_results(open_ports, closed_ports)

# Function to perform FIN Scan
def fin_scan(target, ports):
    open_ports = []
    closed_ports = []
    ans, unans = sr(IP(dst=target)/TCP(dport=ports, flags="F"), timeout=2, verbose=False)
    for snd, rcv in ans:
        if rcv.haslayer(TCP) and rcv[TCP].flags == 0x14:  # RST, ACK
            closed_ports.append(rcv.sport)
    if unans:
        for snd in unans:
            open_ports.append(snd.dport)
    print_results(open_ports, closed_ports)

# Function to perform Null Scan
def null_scan(target, ports):
    open_ports = []
    closed_ports = []
    ans, unans = sr(IP(dst=target)/TCP(dport=ports, flags=""), timeout=2, verbose=False)
    for snd, rcv in ans:
        if rcv.haslayer(TCP) and rcv[TCP].flags == 0x14:  # RST, ACK
            closed_ports.append(rcv.sport)
    if unans:
        for snd in unans:
            open_ports.append(snd.dport)
    print_results(open_ports, closed_ports)

# Function to perform XMAS Scan
def xmas_scan(target, ports):
    open_ports = []
    closed_ports = []
    ans, unans = sr(IP(dst=target)/TCP(dport=ports, flags="FPU"), timeout=2, verbose=False)
    process_results(ans, unans, open_ports, closed_ports)
    print_results(open_ports, closed_ports)

# Function to perform Maimon Scan
def maimon_scan(target, ports):
    open_ports = []
    closed_ports = []
    ans, unans = sr(IP(dst=target)/TCP(dport=ports, flags="SA"), timeout=2, verbose=False)
    for snd, rcv in ans:
        if rcv.haslayer(TCP) and rcv[TCP].flags == 0x12:  # SYN, ACK
            open_ports.append(rcv.sport)
    if unans:
        for snd in unans:
            closed_ports.append(snd.dport)  # Append unresponsive ports to closed_ports
    print_results(open_ports, closed_ports)

# Function to perform ACK Flag Scan
def ack_flag_scan(target, ports):
    open_ports = []
    closed_ports = []
    ans, unans = sr(IP(dst=target)/TCP(sport=RandShort(), dport=ports, flags="A"), timeout=2, verbose=False)
    for snd, rcv in ans:
        if rcv.haslayer(TCP) and rcv[TCP].flags != 0x14:  # Not RST
            open_ports.append(rcv.sport)
    if unans:
        for snd in unans:
            closed_ports.append(snd.dport)  # Append unresponsive ports to closed_ports
    print_results(open_ports, closed_ports)

# Function to perform TTL Based Scan
def ttl_scan(target, ports):
    open_ttl = []
    for ttl_value in range(1, 256):  # Iterate over TTL values from 1 to 255
        ans, unans = sr(IP(dst=target, ttl=ttl_value)/ICMP(), timeout=2, verbose=False)
        if ans:
            open_ttl.append(ttl_value)
            print(f"TTL {ttl_value}: {target} is up")
    print("-"*50)
    print("Open TTLs:", open_ttl)

# Function to perform Window Scan
def window_scan(target, ports):
    open_ports = []
    closed_ports = []
    ans, unans = sr(IP(dst=target)/TCP(dport=ports, flags="A"), timeout=2, verbose=False)
    for snd, rcv in ans:
        if rcv[TCP].window != 8192:
            open_ports.append(rcv.sport)
            print(f"Port {rcv[TCP].sport} is open (Window: {rcv[TCP].window})")
    for snd in unans:  # Ports that didn't respond are assumed to be closed
        closed_ports.append(snd.dport)
    print_results(open_ports, closed_ports)

# Function to print results
def print_results(open_ports, closed_ports):
    print("-"*50)
    print("Open Ports:")
    for port in open_ports:
        print(f"Port {port} is open")

    print("\n")
    print("-"*50)
    print("Closed Ports:")
    for port in closed_ports:
        print(f"Port {port} is closed")

def main():
    print("#"*200)
    for line in zip(draw_p(), draw_o(), draw_r(), draw_t(), draw_s(), draw_c(), draw_a(), draw_n(), draw_n(), draw_e(), draw_ra()):
        print(" ".join(line))
    print("#"*200)
    
    target = input("Enter target IP address: ")

    while True:
        print("\nSelect port discovery technique:")
        print("1. ICMP Ping Scan")
        print("2. UDP Ping Scan")
        print("3. SYN Scan (Full Open Scan)")
        print("4. Stealth Scan (Half Open Scan) (May not work on Windows)")
        print("5. FIN Scan (May not work on Windows)")
        print("6. Null Scan (May not work on Windows)")
        print("7. XMAS Scan (Does not work on Windows)")
        print("8. Maimon Scan (May not work on Windows)")
        print("9. ACK Flag Scan")
        print("10. TTL Based Scan")
        print("11. Window Scan (May not work on Windows)")
        print("0. Exit")
        
        choice = input("\nEnter your choice: ")

        if choice == '0':
            print("Exiting...")
            break

        start_port = 0
        end_port = 0
        if choice in ['3', '4', '5', '6', '7', '8', '9', '11']:
            port_range = input("Enter port range (e.g., 1-100): ").split('-')
            if len(port_range) != 2:
                print("Invalid port range format. Please provide start and end ports separated by a hyphen.")
                continue
            start_port = int(port_range[0])
            end_port = int(port_range[1])

        print("\nScanning...")
        if choice == '1':
            icmp_ping_scan(target)
        elif choice == '2':
            udp_ping_scan(target)
        elif choice == '3':
            syn_scan(target, (start_port, end_port))
        elif choice == '4':
            stealth_scan(target, (start_port, end_port))
        elif choice == '5':
            fin_scan(target, (start_port, end_port))
        elif choice == '6':
            null_scan(target, (start_port, end_port))
        elif choice == '7':
            xmas_scan(target, (start_port, end_port))
        elif choice == '8':
            maimon_scan(target, (start_port, end_port))
        elif choice == '9':
            ack_flag_scan(target, (start_port, end_port))
        elif choice == '10':
            ttl_scan(target, range(start_port, end_port+1))
        elif choice == '11':
            window_scan(target, (start_port, end_port))
        else:
            print("Invalid choice")

        print("\nScan complete.\n")


if __name__ == "__main__":
    main()

