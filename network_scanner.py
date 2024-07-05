import json
from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
    # Create an ARP request packet
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send the packet and receive responses
    result = srp(packet, timeout=3, verbose=0)[0]

    # Parse the results
    devices = []
    for sent, received in result:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return devices

def save_to_json(data, filename):
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)

if __name__ == "__main__":
    # Define the IP range to scan
    ip_range = "10.0.0.1/24"

    # Scan the network
    devices = scan_network(ip_range)

    # Print found devices
    print("Devices found:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")

    # Save to JSON file
    save_to_json(devices, "network_devices.json")
