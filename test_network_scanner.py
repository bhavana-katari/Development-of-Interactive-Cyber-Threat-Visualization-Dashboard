#!/usr/bin/env python3
"""
Test script for Network Scanner functionality
Tests real network scanning capabilities
"""

import sys
import time
from network_scanner import RealNetworkScanner

def main():
    print("=" * 70)
    print("NETWORK SCANNER TEST - OPTIMIZED PARALLEL VERSION")
    print("=" * 70)
    
    # Initialize scanner
    scanner = RealNetworkScanner()
    
    # Test 1: Get local IP
    print("\n[TEST 1] Getting local IP address...")
    local_ip = scanner.get_local_ip()
    print(f"[OK] Local IP: {local_ip}")
    
    # Test 2: Get MAC address
    print("\n[TEST 2] Getting MAC address...")
    mac = scanner._get_mac_address()
    print(f"[OK] MAC Address: {mac}")
    
    # Test 3: Get network info
    print("\n[TEST 3] Getting network information...")
    network_info = scanner.get_network_info()
    print(f"[OK] Network Info Retrieved:")
    print(f"  - Bandwidth (Mbps): {network_info['stats']['speed_sent'] + network_info['stats']['speed_recv']}")
    print(f"  - Packets Sent: {network_info['stats']['packets_sent']}")
    print(f"  - Packets Received: {network_info['stats']['packets_recv']}")
    
    # Test 4: ARP scan with PARALLEL scanning (FAST!)
    print("\n[TEST 4] Performing FAST parallel network scan...")
    print("Using ThreadPoolExecutor with 15 parallel threads...")
    start_time = time.time()
    devices = scanner.scan_network_arp(force_scan=True)
    scan_duration = time.time() - start_time
    
    print(f"[OK] Found {len(devices)} device(s) in {scan_duration:.1f} seconds")
    
    # Test 5: Display discovered devices
    print("\n[TEST 5] Discovered Devices:")
    print("-" * 85)
    print(f"{'IP Address':<15} {'MAC Address':<20} {'Hostname':<20} {'Type':<15} {'Status':<10}")
    print("-" * 85)
    
    for device in devices:
        ip = device.get('ip', 'N/A')[:14]
        mac = device.get('mac', 'N/A')[:19]
        hostname = device.get('hostname', 'Unknown')[:19]
        dev_type = device.get('type', 'Unknown')[:14]
        status = device.get('status', 'Unknown')[:9]
        
        print(f"{ip:<15} {mac:<20} {hostname:<20} {dev_type:<15} {status:<10}")
    
    # Test 6: Get open ports on local machine
    print("\n[TEST 6] Scanning open ports on local machine...")
    start_time = time.time()
    ports = scanner.get_open_ports('127.0.0.1', timeout=0.2)
    port_duration = time.time() - start_time
    print(f"[OK] Found {len(ports)} open port(s) in {port_duration:.1f} seconds:")
    for port in ports:
        print(f"  - Port {port['port']}/{port['service']}")
    
    # Test 7: Force fresh scan
    print("\n[TEST 7] Testing fresh scan (force_scan=True)...")
    start_time = time.time()
    devices_fresh = scanner.scan_network_arp(force_scan=True)
    fresh_duration = time.time() - start_time
    print(f"[OK] Fresh scan found {len(devices_fresh)} device(s) in {fresh_duration:.1f} seconds")
    
    # Test 8: Cache test
    print("\n[TEST 8] Testing cache (should return immediately)...")
    start_time = time.time()
    devices_cached = scanner.scan_network_arp(force_scan=False)
    cache_duration = time.time() - start_time
    print(f"[OK] Cached scan returned {len(devices_cached)} device(s) in {cache_duration:.3f} seconds")
    
    print("\n" + "=" * 70)
    
    # Test 2: Get MAC address
    print("\n[TEST 2] Getting MAC address...")
    mac = scanner._get_mac_address()
    print(f"✓ MAC Address: {mac}")
    
    # Test 3: Get network info
    print("\n[TEST 3] Getting network information...")
    network_info = scanner.get_network_info()
    print(f"✓ Network Info Retrieved:")
    print(f"  - Bandwidth (Mbps): {network_info['stats']['speed_sent'] + network_info['stats']['speed_recv']}")
    print(f"  - Packets Sent: {network_info['stats']['packets_sent']}")
    print(f"  - Packets Received: {network_info['stats']['packets_recv']}")
    
    # Test 4: ARP scan
    print("\n[TEST 4] Performing network scan (ARP/Fallback)...")
    print("This may take 5-10 seconds depending on network size...")
    start_time = time.time()
    devices = scanner.scan_network_arp(force_scan=True)
    scan_duration = time.time() - start_time
    
    print(f"✓ Found {len(devices)} device(s) in {scan_duration:.1f} seconds")
    
    # Test 5: Display discovered devices
    print("\n[TEST 5] Discovered Devices:")
    print("-" * 70)
    print(f"{'IP Address':<15} {'MAC Address':<20} {'Hostname':<20} {'Type':<15} {'Status':<10}")
    print("-" * 70)
    
    for device in devices:
        ip = device.get('ip', 'N/A')[:14]
        mac = device.get('mac', 'N/A')[:19]
        hostname = device.get('hostname', 'Unknown')[:19]
        dev_type = device.get('type', 'Unknown')[:14]
        status = device.get('status', 'Unknown')[:9]
        
        print(f"{ip:<15} {mac:<20} {hostname:<20} {dev_type:<15} {status:<10}")
    
    # Test 6: Get open ports on local machine
    print("\n[TEST 6] Scanning open ports on local machine...")
    print("This may take 5-10 seconds...")
    ports = scanner.get_open_ports('127.0.0.1', timeout=0.5)
    print(f"✓ Found {len(ports)} open port(s):")
    for port in ports:
        print(f"  - Port {port['port']}/{port['service']}")
    
    # Test 7: Force fresh scan
    print("\n[TEST 7] Testing fresh scan (force_scan=True)...")
    devices_fresh = scanner.scan_network_arp(force_scan=True)
    print(f"✓ Fresh scan found {len(devices_fresh)} device(s)")
    
    # Test 8: Cache test
    print("\n[TEST 8] Testing cache (should return immediately)...")
    start_time = time.time()
    devices_cached = scanner.scan_network_arp(force_scan=False)
    cache_duration = time.time() - start_time
    print(f"✓ Cached scan returned {len(devices_cached)} device(s) in {cache_duration:.3f} seconds")
    
    print("\n" + "=" * 70)
    print("ALL TESTS COMPLETED SUCCESSFULLY!")
    print("=" * 70)
    print("\nNotes:")
    print("- Run this script with administrator privileges for best results")
    print("- ARP scan works better with scapy installed (pip install scapy)")
    print("- Fallback method will be used if scapy is not available")
    print("- Windows may require WinPcap or Npcap for advanced scanning")

if __name__ == '__main__':
    main()
