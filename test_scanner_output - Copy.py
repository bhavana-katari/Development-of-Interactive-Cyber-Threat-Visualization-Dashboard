from network_scanner import RealNetworkScanner
import json
import time

def test_scanner():
    print("Initializing scanner...")
    scanner = RealNetworkScanner()
    
    print("Starting force scan...")
    start_time = time.time()
    devices = scanner.scan_network_arp(force_scan=True)
    end_time = time.time()
    
    print(f"Scan completed in {end_time - start_time:.2f} seconds")
    print(f"Found {len(devices)} devices:")
    
    print(json.dumps(devices, indent=2))
    
    # Validation
    unknown_macs = sum(1 for d in devices if d['mac'] == 'Unknown')
    unknown_hosts = sum(1 for d in devices if d['hostname'] == 'Unknown')
    
    print(f"\nStats:")
    print(f"Total Devices: {len(devices)}")
    print(f"Unknown MACs: {unknown_macs}")
    print(f"Unknown Hostnames: {unknown_hosts}")
    
    if unknown_macs < len(devices):
        print("\nSUCCESS: Retrieved real MAC addresses!")
    else:
        print("\nWARNING: No MAC addresses found (all Unknown).")

if __name__ == "__main__":
    test_scanner()
