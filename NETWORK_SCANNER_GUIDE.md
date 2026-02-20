# Network Scanner Feature - Quick Start Guide

## Overview
The **Network Scanner** feature in the CyberShield SOC Dashboard allows you to discover and monitor devices on your local network in real-time.

## Features

✅ **Device Discovery**
- Scans your local network via ARP (Address Resolution Protocol)
- Falls back to ping-based discovery if ARP not available
- Shows IP Address, MAC Address, Hostname, Device Type, and Status

✅ **Device Classification**
- Automatically identifies device types: Router, Computer, Mobile, Printer, Smart TV, Camera, etc.
- Shows online/offline status
- Classifies suspicious devices

✅ **Open Port Detection**
- Scans for open ports on discovered devices
- Identifies running services
- Multi-threaded scanning for performance

✅ **Real-Time Updates**
- Network statistics update every 5 seconds
- Bandwidth monitoring
- Device count and suspicious device alerts

## How to Use

### Option 1: Using the Dashboard UI

1. **Navigate to Network Scanner Section**
   - Open the CyberShield SOC Dashboard
   - Scroll down to the "Network Scanner" section

2. **Start a Network Scan**
   - Click the **"🔍 Scan Network"** button
   - Wait for the scan to complete (5-30 seconds depending on network size)

3. **View Results**
   - Table shows all discovered devices with columns:
     - **IP Address**: Device's IP on the network
     - **MAC Address**: Physical address (hardware identifier)
     - **Hostname**: Device name (computer/router hostname)
     - **Type**: Device classification (Router, Computer, Mobile, etc.)
     - **Status**: Online/Offline/Suspicious

4. **Check Statistics**
   - **Total Devices**: Number of devices found
   - **Suspicious**: Count of devices flagged as suspicious
   - **Bandwidth Usage**: Network utilization
   - **Ports Open**: Total open ports across all devices

### Option 2: Testing with Command Line

Run the test script to verify network scanner works:

```bash
cd cyber-threat-dashboard
python test_network_scanner.py
```

This will:
- Get local IP address
- Retrieve MAC address
- Display network information
- Perform a full network scan
- List discovered devices
- Test port scanning
- Verify caching mechanism

## System Requirements

### Minimum Requirements
- **Python 3.7+**
- **Windows 7+** (for Windows users)
- **Administrator/Root privileges** (strongly recommended)

### Optional (For Enhanced Scanning)
- **scapy**: Better ARP scanning (install via `pip install scapy`)
- **WinPcap or Npcap**: Packet capturing on Windows

### Install Optional Dependencies
```bash
pip install scapy
```

## Technical Details

### Scanning Methods

**Method 1: ARP Scan (Primary)**
- Uses scapy library if available
- Sends ARP packets to /24 subnet
- Fastest and most reliable on Windows/Linux
- Requires: scapy library

**Method 2: Fallback Discovery**
- Uses socket connections to test IPs
- Tests ports 53 (DNS) and 80 (HTTP)
- Falls back to ICMP ping on Windows
- Works without any special libraries
- Slightly slower but always available

### Port Detection
- Scans 17 common ports: 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080, 8443, 5900
- Uses multi-threaded scanning for speed
- 0.5 second timeout per port

### Device Classification
Identifies devices by:
- IP address patterns (.1 for router, .255 for broadcast)
- Hostname matching (contains keywords: router, printer, camera, etc.)
- Response patterns and service detection

## Performance Notes

- **First Scan**: 5-30 seconds (depends on network size and scanning method)
- **Cached Results**: Returned immediately (within 30 seconds of previous scan)
- **Port Scan**: 5-10 seconds for a single device
- **Network Update**: Background refresh every 5 seconds

## Troubleshooting

### No devices found
**Solution 1**: Run as Administrator
```powershell
# Right-click PowerShell and select "Run as Administrator"
cd C:\Users\KUSUMA\Desktop\cyber-threat-dashboard
python -m app
```

**Solution 2**: Install scapy
```bash
pip install scapy
```

**Solution 3**: Check network connectivity
- Ensure you're connected to a network
- Run `ipconfig` to verify IP address
- Check if other devices are on the network

### Slow scanning
- This is normal for fallback mode (non-ARP)
- Install scapy for faster ARP-based scanning
- Run as administrator for better network access

### "Access Denied" errors
- Run the application with administrator privileges
- Windows: Right-click cmd/PowerShell → Run as Administrator
- Linux/Mac: Use `sudo`

### Scapy warnings
The warning "No libpcap provider available" is normal on Windows
- It means WinPcap/Npcap is not installed
- The scanner will still work using fallback method
- To get rid of warning, install: `pip install WinPcap` or download Npcap

## API Reference

### Using Network Scanner in Code

```python
from network_scanner import RealNetworkScanner

# Initialize scanner
scanner = RealNetworkScanner()

# Scan network (with caching)
devices = scanner.scan_network_arp()

# Force fresh scan (bypass cache)
devices = scanner.scan_network_arp(force_scan=True)

# Get network info
network_info = scanner.get_network_info()
# Returns: bytes_sent, bytes_recv, packets_sent, packets_recv, etc.

# Scan ports on specific IP
open_ports = scanner.get_open_ports('192.168.1.100')

# Get local IP
local_ip = scanner.get_local_ip()

# Get local MAC address
mac = scanner._get_mac_address()
```

## Device Output Example

```
IP Address      MAC Address          Hostname             Type            Status
192.168.1.100   A4:C3:F0:ED:C8:CA    Bhavana              This Device     Online
192.168.1.1     00:11:22:33:44:55    TP-Link-Router       Router          Online
192.168.1.50    D4:E6:B7:AC:1F:2A    iPhone-12            Mobile          Online
192.168.1.200   F8:D1:4A:B5:9C:3E    HP-Printer           Printer         Online
```

## Security Considerations

⚠️ **Important Notes:**
- Network scanning can take 5-30 seconds on larger networks
- Some devices may not respond to all scanning methods
- Router hostname may show as "Unknown" if not configured
- MAC addresses shown as "Unknown" for some devices on fallback scan
- Never scan networks you don't own/manage

## Best Practices

1. **Run as Administrator** for full scanning capability
2. **Schedule scans** during off-peak times on production networks
3. **Check results regularly** to monitor new devices
4. **Update device list** when adding new devices to network
5. **Review suspicious devices** promptly
6. **Keep scapy updated** for better compatibility

## Common Device Types

| Type | Typical Hostname Pattern | Common Ports |
|------|------------------------|--------------|
| Router | gateway, linksys, tp-link, netgear | 80, 443 |
| Computer | hostname, desktop, laptop | 135, 445, 3389 |
| Mobile | iphone, android, mobile | 5900 (screen share) |
| Printer | printer, hp, xerox, canon | 631, 9100 |
| Smart TV | chromecast, roku, samsung-tv | 8008, 8080 |
| Camera | camera, nvr, hikvision | 80, 8080, 8443 |
| Speaker | alexa, echo, google-home | 8008, 55443 |

## Support & Resources

- **Main Dashboard**: See Dashboard documentation
- **Python Version**: Requires Python 3.7+
- **Network Type**: Works on IPv4 networks, /24 subnet (255.255.255.0)
- **OS Support**: Windows, Linux, macOS

## Next Steps

1. ✅ Test network scanner with `python test_network_scanner.py`
2. ✅ Click "Scan Network" button in dashboard
3. ✅ Review discovered devices
4. ✅ Monitor suspicious devices alerts
5. ✅ Use in production monitoring workflow
