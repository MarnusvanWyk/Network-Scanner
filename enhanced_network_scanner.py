import json
import socket
import os
import netifaces
from scapy.all import ARP, Ether, srp, sr1, DNS, DNSQR, IP, UDP

def get_interfaces_with_ips():
    interfaces = netifaces.interfaces()
    interfaces_with_ips = []

    for iface in interfaces:
        addresses = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addresses:
            ip_info = addresses[netifaces.AF_INET][0]
            ip = ip_info['addr']
            interfaces_with_ips.append((iface, ip))

    return interfaces_with_ips

def get_ip_range(interface):
    try:
        addresses = netifaces.ifaddresses(interface)
        ip_info = addresses[netifaces.AF_INET][0]
        ip = ip_info['addr']
        netmask = ip_info['netmask']
        return f"{ip}/{netmask_to_cidr(netmask)}"
    except KeyError:
        return None

def netmask_to_cidr(netmask):
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])

def get_vendor(mac_address):
    url = f"http://macvendors.co/api/{mac_address}"
    try:
        response = requests.get(url)
        vendor_info = response.json()
        return vendor_info['result']['company']
    except Exception as e:
        return "Unknown"

def get_hostname(ip):
    try:
        # Perform a reverse DNS lookup using scapy
        response = sr1(IP(dst="8.8.8.8")/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname=ip, qtype="PTR")), timeout=2, verbose=0)
        if response and response.haslayer(DNS) and response[DNS].ancount > 0:
            return response[DNS].an[0].rdata.decode('utf-8')
    except Exception as e:
        pass

    # Fallback to socket.gethostbyaddr
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None

def get_dns_name(ip):
    try:
        return socket.getfqdn(ip)
    except socket.herror:
        return None

def get_mdns_name(ip):
    # Implement mDNS query here if needed
    return None

def ping(ip):
    response = os.system(f"ping -c 1 {ip}")
    return response == 0

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
        ip = received.psrc
        mac = received.hwsrc
        hostname = get_hostname(ip) or ip
        devices.append({
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "ping": ping(ip),
            "vendor": get_vendor(mac),
            "dns_name": get_dns_name(ip),
            "mdns_name": get_mdns_name(ip),
        })

    return devices

def save_to_json(data, filename, mode):
    if mode in ['a', 'u'] and os.path.exists(filename):
        with open(filename, 'r+') as file:
            existing_data = json.load(file)
            for new_device in data:
                updated = False
                for existing_device in existing_data:
                    if existing_device['mac'] == new_device['mac']:
                        existing_device.update(new_device)
                        updated = True
                        break
                if not updated:
                    existing_data.append(new_device)
            file.seek(0)
            json.dump(existing_data, file, indent=4)
            file.truncate()
    else:
        with open(filename, 'w') as file:
            json.dump(data, file, indent=4)

def select_interface():
    interfaces = get_interfaces_with_ips()
    print("Available network interfaces with IPs:")
    for idx, (iface, ip) in enumerate(interfaces):
        print(f"{idx}: {iface} ({ip})")

    while True:
        try:
            choice = int(input("Select the interface to scan (by number): "))
            if 0 <= choice < len(interfaces):
                return interfaces[choice][0]
            else:
                print("Invalid choice, please try again.")
        except ValueError:
            print("Invalid input, please enter a number.")

def get_save_mode():
    while True:
        mode = input("Do you want to append, overwrite, or update the JSON file? (a/o/u): ").lower()
        if mode in ['a', 'o', 'u']:
            return mode
        else:
            print("Invalid choice, please enter 'a' to append, 'o' to overwrite, or 'u' to update.")

if __name__ == "__main__":
    # Select network interface
    interface = select_interface()
    ip_range = get_ip_range(interface)

    if ip_range is None:
        print(f"Could not determine IP range for interface {interface}.")
    else:
        print(f"Scanning IP range: {ip_range}")

        # Scan the network
        devices = scan_network(ip_range)

        # Print found devices
        print("Devices found:")
        for device in devices:
            print(f"IP: {device['ip']}, MAC: {device['mac']}, Hostname: {device['hostname']}, "
                  f"Ping: {device['ping']}, Vendor: {device['vendor']}, DNS Name: {device['dns_name']}, "
                  f"mDNS Name: {device['mdns_name']}")

        # Get save mode from user
        save_mode = get_save_mode()

        # Save to JSON file
        save_to_json(devices, "network_devices.json", save_mode)
