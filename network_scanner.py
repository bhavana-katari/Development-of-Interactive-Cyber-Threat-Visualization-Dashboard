"""
Real Network Scanner Module
"""
import psutil
import socket
import threading
import time
from datetime import datetime
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import re


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

try:
    from scapy.all import ARP, Ether, srp, conf
    import os
    if os.name == 'nt':
        # Use layer 3 sockets on Windows if WinPcap/Npcap is missing
        from scapy.arch.windows import WinPcapUtils
        try:
            # Check if WinPcap is available
            WinPcapUtils.get_if_list()
        except:
            # Fallback to L3
            conf.L3socket = conf.L3socket
            logger.info("WinPcap not found, scapy will use L3 sockets where possible")
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class RealNetworkScanner:
    def __init__(self):
        self.last_scan_time = 0
        self.cached_devices = []
        self.scan_interval = 30  # Scan every 30 seconds to avoid flooding
        # Initialize bandwidth tracking
        self.last_net_io = psutil.net_io_counters()
        self.last_time = time.time()
        
    def get_network_info(self):
        """Get real network bandwidth and connection stats using psutil"""
        info = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'connections': [],
            'stats': {}
        }
        
        try:
            # Calculate Bandwidth Speed (Bytes per second)
            current_net_io = psutil.net_io_counters()
            current_time = time.time()
            
            time_delta = current_time - self.last_time
            if time_delta < 0.1: time_delta = 0.1 # Avoid division by zero
            
            # Calculate delta (bytes since last check)
            bytes_sent_delta = current_net_io.bytes_sent - self.last_net_io.bytes_sent
            bytes_recv_delta = current_net_io.bytes_recv - self.last_net_io.bytes_recv
            
            # Calculate speed (bytes/sec)
            speed_sent = bytes_sent_delta / time_delta
            speed_recv = bytes_recv_delta / time_delta
            
            # Update last state
            self.last_net_io = current_net_io
            self.last_time = current_time
            
            info['stats'] = {
                'bytes_sent': current_net_io.bytes_sent,
                'bytes_recv': current_net_io.bytes_recv,
                'speed_sent': speed_sent,
                'speed_recv': speed_recv,
                'packets_sent': current_net_io.packets_sent,
                'packets_recv': current_net_io.packets_recv,
                'error_in': current_net_io.errin,
                'error_out': current_net_io.errout,
                'drop_in': current_net_io.dropin,
                'drop_out': current_net_io.dropout
            }
            
            # Get active network connections (top 10)
            try:
                connections = psutil.net_connections(kind='inet')
                # Filter for established connections
                active_conns = [c for c in connections if c.status == 'ESTABLISHED']
                
                for conn in active_conns[:10]:
                    if conn.laddr and conn.raddr:
                        conn_info = {
                            'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'status': conn.status,
                            'pid': conn.pid or 0
                        }
                        info['connections'].append(conn_info)
            except (psutil.AccessDenied, PermissionError):
                pass
                
        except Exception as e:
            logger.error(f"Error getting network info: {e}")
            info['error'] = str(e)
            # Return zero stats on error to prevent crashing
            info['stats'] = {k: 0 for k in ['bytes_sent', 'bytes_recv', 'packets_sent', 'packets_recv', 
                                          'error_in', 'error_out', 'drop_in', 'drop_out', 
                                          'speed_sent', 'speed_recv']}
        
        return info

    def get_local_ip(self):
        """Get the local IP address of the machine"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Doesn't need to be reachable
            s.connect(('8.8.8.8', 1))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return '127.0.0.1'

    def scan_network_arp(self, force_scan=False):
        """
        Perform a real ARP scan to find devices on the local network.
        Requires scapy and potentially admin privileges.
        """
        current_time = time.time()
        
        # Return cached results if scan was recent (unless force_scan is True)
        if not force_scan and self.cached_devices and (current_time - self.last_scan_time < self.scan_interval):
            return self.cached_devices

        devices = []
        
        try:
            local_ip = self.get_local_ip()
            
            if SCAPY_AVAILABLE:
                # Try ARP scan first
                devices = self._scan_with_arp(local_ip)
                if not devices:
                    # If ARP scan returns empty, use fallback
                    devices = self._scan_fallback()
            else:
                logger.warning("Scapy not available. Using network discovery checks.")
                devices = self._scan_fallback()
            
            # Add self if not found
            found_self = any(d['ip'] == local_ip for d in devices)
            if not found_self:
                devices.append({
                    'ip': local_ip,
                    'mac': self._get_mac_address(),
                    'hostname': socket.gethostname(),
                    'status': 'Online',
                    'type': 'This Device'
                })
            
            # Enrich device types
            devices = self._classify_devices(devices, local_ip)
                
            self.cached_devices = devices
            self.last_scan_time = current_time
            return devices
            
        except (Exception, RuntimeError) as e:
            logger.error(f"Network scan failed: {e}")
            return self._scan_fallback()
    
    def _scan_with_arp(self, local_ip):
        """Perform ARP scan specifically"""
        devices = []
        try:
            # Assuming /24 subnet for home networks
            ip_parts = local_ip.split('.')
            ip_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            logger.info(f"Scanning network range with ARP: {ip_range}")
            
            # Create ARP request packet
            arp = ARP(pdst=ip_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Send packet and get response - try multiple times for reliability
            try:
                # Increased timeout slightly for first packet, then retry
                result = srp(packet, timeout=2, verbose=0, retry=2)[0]
                
                for sent, received in result:
                    devices.append({
                        'ip': received.psrc,
                        'mac': received.hwsrc,
                        'hostname': self._get_hostname(received.psrc),
                        'status': 'Online',
                        'type': 'Unknown'
                    })
                
                logger.info(f"ARP scan found {len(devices)} devices")
            except Exception as e:
                logger.warning(f"L2 ARP scan failed: {e}")
                return []
            
            return devices
            
        except Exception as e:
            logger.error(f"ARP scan exception: {e}")
            return []

    def _scan_fallback(self):
        """Fallback method using PARALLEL socket/ping for fast network discovery"""
        logger.info("Starting FAST parallel network discovery...")
        devices = []
        local_ip = self.get_local_ip()
        base_ip = '.'.join(local_ip.split('.')[:3]) + '.'
        
        # Always add self first
        devices.append({
            'ip': local_ip,
            'mac': self._get_mac_address(),
            'hostname': socket.gethostname(),
            'status': 'Online',
            'type': 'This Device'
        })
        
        # Use ThreadPoolExecutor for MASSIVE PARALLEL scanning (100 threads = ultra fast!)
        logger.info(f"Scanning IP range (.1 to .254) based on {local_ip} - ULTRA PARALLEL MODE")
        found_devices = []
        
        # Create a list of IPs to scan
        ips_to_scan = [base_ip + str(i) for i in range(1, 255) if base_ip + str(i) != local_ip]
        
        # INCREASED WORKERS TO 100 FOR SPEED
        with ThreadPoolExecutor(max_workers=100) as executor:
            # Submit all ping tasks
            future_to_ip = {executor.submit(self._ping_device, ip): ip for ip in ips_to_scan}
            
            # Get results as they complete
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    is_online = future.result()
                    if is_online:
                        # Get reliable MAC from ARP table
                        mac_address = self._get_mac_from_arp_table(ip)
                        
                        # Get reliable Hostname
                        hostname = self._get_hostname(ip)
                        
                        # Enrich device info
                        vendor = self._get_vendor_from_mac(mac_address)
                        last_octet = int(ip.split('.')[-1])
                        device_type = self._identify_device_type(ip, last_octet)
                        
                        if vendor != "Unknown":
                            device_type = f"{vendor} Device"
                        
                        found_devices.append({
                            'ip': ip,
                            'mac': mac_address,
                            'hostname': hostname,
                            'status': 'Online',
                            'type': device_type,
                            'vendor': vendor
                        })
                        logger.info(f"✓ Found: {ip} ({hostname}) - {device_type}")
                except Exception as e:
                    logger.debug(f"Error scanning {ip}: {e}")
        
        # Add found devices to list
        devices.extend(found_devices)
        
        logger.info(f"✓ Parallel scan complete. Found {len(found_devices)} additional device(s). Total: {len(devices)}")
        return devices

    def _ping_device(self, ip):
        """Ping a device with multiple fast methods for reliability - returns True if online"""
        # Method 1: Ultra Fast TCP check - common management/web ports
        ports_to_check = [80, 443, 445, 135, 139, 53, 22]
        for port in ports_to_check:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.05) # Very short timeout for parallel waves
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return True
            except:
                pass
        
        # Method 2: ICMP ping (Windows) - last resort but very reliable
        try:
            # Use -w 50 for very fast response check
            result = subprocess.run(['ping', '-n', '1', '-w', '50', ip], 
                                  capture_output=True, timeout=0.2)
            if result.returncode == 0:
                return True
        except:
            pass
        
        return False

    def _identify_device_type(self, ip, last_octet):
        """Identify device type based on IP and common patterns"""
        if last_octet == 1:
            return 'Router'
        elif last_octet == 254 or last_octet == 255:
            return 'Broadcast'
        else:
            return 'Device'

    def _classify_devices(self, devices, local_ip):
        """Classify devices based on various hints"""
        for device in devices:
            ip = device['ip']
            
            # Router usually at .1
            if ip.endswith('.1'):
                device['type'] = 'Router'
            # Broadcast at .255
            elif ip.endswith('.255'):
                device['type'] = 'Broadcast'
            # Check if it's the local machine
            elif ip == local_ip:
                device['type'] = 'This Device'
            # Try to identify by hostname
            elif device['hostname'] and device['hostname'] != 'Unknown':
                hostname_lower = device['hostname'].lower()
                if any(x in hostname_lower for x in ['router', 'gateway', 'linksys', 'tp-link', 'netgear']):
                    device['type'] = 'Router'
                elif any(x in hostname_lower for x in ['phone', 'iphone', 'android', 'mobile']):
                    device['type'] = 'Mobile'
                elif any(x in hostname_lower for x in ['printer', 'print', 'xerox']):
                    device['type'] = 'Printer'
                elif any(x in hostname_lower for x in ['chromecast', 'roku', 'smarttv', 'tv']):
                    device['type'] = 'Smart TV'
                elif any(x in hostname_lower for x in ['alexa', 'echo', 'speaker']):
                    device['type'] = 'Smart Speaker'
                elif any(x in hostname_lower for x in ['camera', 'nvr', 'dvr']):
                    device['type'] = 'Camera'
                else:
                    device['type'] = 'Computer'
            else:
                device['type'] = 'Device'
        
        return devices

    def _get_hostname(self, ip):
        """Try to resolve hostname"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            # Fallback to NetBIOS
            nb_name = self._get_netbios_name(ip)
            if nb_name:
                return nb_name
            return "Unknown"

    def _get_mac_address(self):
        """Get local MAC address"""
        try:
            # This is a cross-platform way to get MAC address
            from uuid import getnode
            mac = getnode()
            return ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))
        except:
            return "00:00:00:00:00:00"

    def _get_mac_from_arp_table(self, ip):
        """
        Retrieve MAC address for a given IP from the system ARP table (Windows).
        """
        try:
            # Run arp -a command
            # This is reliable on Windows after a ping
            output = subprocess.check_output(["arp", "-a", ip], stderr=subprocess.STDOUT).decode('utf-8', errors='ignore')
            
            # Regex to find MAC address (matches both - and :)
            mac_regex = r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"
            match = re.search(mac_regex, output)
            
            if match:
                return match.group(0).replace('-', ':').upper()
        except Exception as e:
            logger.debug(f"Error getting MAC for {ip}: {e}")
        
        return "Unknown"

    def _get_netbios_name(self, ip):
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

    def _get_vendor_from_mac(self, mac):
        """
        Identify vendor from MAC address OUI (First 3 bytes)
        """
        if not mac or mac == "Unknown" or len(mac) < 8:
            return "Unknown"
        
        # Normalize MAC
        mac_prefix = mac.replace(':', '').replace('-', '').upper()[:6]
        
        # Common OUI Database (Simplified)
        vendors = {
            "000C29": "VMware", "005056": "VMware",
            "00155D": "Microsoft",
            "B827EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
            "001A11": "Google", "F4F5DB": "Google",
            "A4C3F0": "Xiaomi/Poco", "640980": "Xiaomi",
            "18D6C7": "TP-Link", "6032B1": "TP-Link",
            "BC9A78": "Huawei",
            "2C0E3D": "Samsung", "508569": "Samsung",
            "AC87A3": "Apple", "0017F2": "Apple",
            "F01898": "Apple", "7C6D62": "Apple",
        }
        
        # Check against common list or partials
        # Note: In a real app this would query an API or large DB
        return vendors.get(mac_prefix, "Unknown")


    def get_open_ports(self, ip, timeout=0.5):
        """Scan for open ports on a specific IP (with threading for speed)"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080, 8443, 5900]
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                if sock.connect_ex((ip, port)) == 0:
                    service = 'Unknown'
                    try:
                        service = socket.getservbyport(port)
                    except:
                        pass
                    
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'status': 'Open'
                    })
                sock.close()
            except:
                pass
        
        # Use threads for faster port scanning
        threads = []
        for port in common_ports:
            t = threading.Thread(target=check_port, args=(port,))
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Wait for all threads to complete (with timeout)
        for t in threads:
            t.join(timeout=2)
        
        return open_ports
