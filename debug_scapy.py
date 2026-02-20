try:
    from scapy.all import ARP, Ether, srp
    print("Scapy imported successfully")
except ImportError as e:
    print(f"ImportError: {e}")
except Exception as e:
    print(f"Error: {e}")
