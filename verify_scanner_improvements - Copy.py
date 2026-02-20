import subprocess
import socket
import re
import threading
from concurrent.futures import ThreadPoolExecutor

def get_mac_from_arp(ip):
    """
    Retrieve MAC address for a given IP from the system ARP table.
    """
    try:
        # Run arp -a command
        output = subprocess.check_output(["arp", "-a", ip], stderr=subprocess.STDOUT).decode('utf-8', errors='ignore')
        
        # Parse logic for Windows arp -a output
        # Example output:
        # Interface: 192.168.1.100 --- 0x4
        #   Internet Address      Physical Address      Type
        #   192.168.1.1           a4-c3-f0-ed-c8-ca     dynamic
        
        # Regex to find MAC address (matches both - and :)
        mac_regex = r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"
        match = re.search(mac_regex, output)
        
        if match:
            return match.group(0).replace('-', ':').upper()
    except Exception as e:
        print(f"Error getting MAC for {ip}: {e}")
    
    return None

def get_netbios_name_windows(ip):
    """
    Try to get NetBIOS name using nbtstat (Windows only)
    """
    try:
        output = subprocess.check_output(["nbtstat", "-A", ip], stderr=subprocess.STDOUT, timeout=2).decode('utf-8', errors='ignore')
        # Look for the line with <00> UNIQUE which usually holds the hostname
        for line in output.split('\n'):
            if "<00>" in line and "UNIQUE" in line:
                parts = line.split()
                if len(parts) > 0:
                    return parts[0].strip()
    except:
        pass
    return None

def get_hostname(ip):
    """
    Try to resolve hostname using socket and NetBIOS
    """
    hostname = "Unknown"
    # Method 1: Reverse DNS
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except:
        pass
    
    # Method 2: NetBIOS (if first method failed or returned IP)
    if hostname == "Unknown" or hostname == ip:
        nb_name = get_netbios_name_windows(ip)
        if nb_name:
            hostname = nb_name
            
    return hostname

def ping_and_check(ip):
    try:
        # Ping to populate ARP cache
        subprocess.run(['ping', '-n', '1', '-w', '100', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Check if online (simple socket check)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        # Port 135 (RPC) or 445 (SMB) or 80 (HTTP) are good indicators
        if sock.connect_ex((ip, 445)) == 0 or sock.connect_ex((ip, 135)) == 0:
             sock.close()
             return True
        sock.close()
        
        # Retrieve ARP (if ping succeeded, ARP should be there)
        mac = get_mac_from_arp(ip)
        if mac:
            return True
            
    except:
        pass
    return False

def scan_subnet():
    # Get local IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 1))
    local_ip = s.getsockname()[0]
    s.close()
    
    print(f"Scanning subnet for {local_ip}...")
    base_ip = '.'.join(local_ip.split('.')[:3]) + '.'
    
    found_devices = []
    
    def check_ip(i):
        ip = base_ip + str(i)
        if ip == local_ip: return
        
        # Ping to populate ARP
        subprocess.run(['ping', '-n', '1', '-w', '50', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        mac = get_mac_from_arp(ip)
        if mac:
            hostname = get_hostname(ip)
            print(f"FOUND: IP={ip}, MAC={mac}, Hostname={hostname}")
            found_devices.append({'ip': ip, 'mac': mac, 'hostname': hostname})
            
    with ThreadPoolExecutor(max_workers=50) as executor:
        for i in range(1, 255):
            executor.submit(check_ip, i)

    print(f"\nScan complete. Found {len(found_devices)} devices.")

if __name__ == "__main__":
    scan_subnet()
