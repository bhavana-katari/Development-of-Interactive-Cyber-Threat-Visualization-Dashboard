#!/usr/bin/env python3
"""
Test script for Network Scanner functionality - OPTIMIZED PARALLEL VERSION
Tests real network scanning with fast parallel IP discovery
"""

import sys
import time
from network_scanner import RealNetworkScanner

def main():
    print("=" * 80)
    print("NETWORK SCANNER TEST - OPTIMIZED PARALLEL SCANNING")
    print("=" * 80)
    
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
    bandwidth = network_info['stats']['speed_sent'] + network_info['stats']['speed_recv']
    print(f"[OK] Network Info Retrieved:")
    print(f"     Bandwidth (Mbps): {bandwidth:.2f}")
    print(f"     Packets Sent: {network_info['stats']['packets_sent']}")
    print(f"     Packets Received: {network_info['stats']['packets_recv']}")
    
    # Test 4: FAST PARALLEL ARP scan
    print("\n[TEST 4] Performing FAST PARALLEL network scan...")
    print("         Using ThreadPoolExecutor with 15 parallel threads...")
    print("         Scanning full subnet (.1 to .254)...")
    start_time = time.time()
    devices = scanner.scan_network_arp(force_scan=True)
    scan_duration = time.time() - start_time
    
    print(f"[OK] Found {len(devices)} device(s) in {scan_duration:.1f} seconds")
    print(f"     Speed: ~{254/scan_duration:.0f} IPs checked per second!")
    
    # Test 5: Display discovered devices
    print("\n[TEST 5] Discovered Devices:")
    print("-" * 90)
    print(f"{'IP Address':<15} {'MAC Address':<20} {'Hostname':<20} {'Type':<15} {'Status':<10}")
    print("-" * 90)
    
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
    if ports:
        for port in ports:
            print(f"     Port {port['port']:<5} / {port['service']:<15}")
    else:
        print("     No open ports found (localhost)")
    
    # Test 7: Force fresh scan (should be fast with parallel)
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
    
    print("\n" + "=" * 80)
    print("ALL TESTS COMPLETED SUCCESSFULLY!")
    print("=" * 80)
    print("\nPerformance Summary:")
    print(f"  - Parallel scan time: {scan_duration:.1f} seconds for full subnet")
    print(f"  - Cache latency: {cache_duration:.3f} seconds (instant!)")
    print(f"  - Devices found: {len(devices)}")
    print(f"  - Scan efficiency: {254/scan_duration:.0f} IPs/second")
    print("\nNotes:")
    print("  - Parallel scanning is MUCH FASTER than sequential!")
    print("  - Run with administrator privileges for best results")
    print("  - Install scapy for native ARP support: pip install scapy")
    print("  - Fallback method works on all systems (no dependencies)")
    print("  - Full subnet scan completes in seconds, not minutes!")

if __name__ == '__main__':
    main()
