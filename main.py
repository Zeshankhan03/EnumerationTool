import os
import platform
import subprocess
import ipaddress
import socket
from smb.SMBConnection import SMBConnection
import requests
import datetime
import uuid
import csv

# Check if the operating system is Windows
def is_windows():
    return platform.system().lower() == 'windows'


# Function to ping a host to check if it's alive
def ping_host(ip):
    if is_windows():
        cmd = ['ping', '-n', '1', ip]
    else:
        cmd = ['ping', '-c', '1', ip]

    try:
        subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        return False


# Function to scan the network for live hosts
def scan_network(subnet):
    live_hosts = []
    offline_hosts = []

    for ip in ipaddress.IPv4Network(subnet, strict=False):
        ip = str(ip)
        if ping_host(ip):
            live_hosts.append(ip)
        else:
            offline_hosts.append(ip)

    return live_hosts, offline_hosts


# Function to scan all ports on a host
def scan_all_ports(ip):
    open_ports = []

    for port in range(1, 65536):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((ip, port))
                open_ports.append(port)
        except (socket.timeout, ConnectionRefusedError):
            pass

    return open_ports


# Function to scan specific ports on a host
def scan_specific_ports(ip, ports):
    open_ports = []

    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((ip, port))
                open_ports.append(port)
        except (socket.timeout, ConnectionRefusedError):
            pass

    return open_ports


# Function to enumerate services running on open ports
def enumerate_services(ip, open_ports):
    service_info = {}

    for port in open_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, port))

            # Predefined services
            if port == 80:
                service_info[port] = "HTTP"
            elif port == 443:
                service_info[port] = "HTTPS"
            elif port == 21:
                service_info[port] = "FTP"
            elif port == 22:
                service_info[port] = "SSH"
            elif port == 23:
                service_info[port] = "Telnet"
            elif port == 25:
                service_info[port] = "SMTP"
            elif port == 53:
                service_info[port] = "DNS"
            # Add more services as needed
            else:
                custom_service = input(f"Enter the service name for port {port}: ")
                service_info[port] = custom_service

    return service_info


# Function to get the public IP address of the system
def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        data = response.json()
        return data['ip']
    except requests.RequestException:
        print("Error fetching public IP address. Please enter the IP address manually.")
        return None


# Function to get geolocation data for an IP address using ipinfo.io API
def get_geolocation(ip, api_key):
    url = f"https://ipinfo.io/{ip}?token={api_key}"

    try:
        response = requests.get(url)
        data = response.json()

        # Check for errors in the response
        if 'error' in data:
            error_message = data['error']['message']
            print(f"Error fetching geolocation data for IP {ip}: {error_message}")
            return 'N/A', 'N/A'

        country = data.get('country', 'N/A')
        region = data.get('region', 'N/A')
        return country, region
    except Exception as e:
        print(f"Error fetching geolocation data for IP {ip}: {e}")
        return 'N/A', 'N/A'


# Function to log data to a CSV file and update the log file with each scan
def log_to_csv(filename, data):
    with open(filename, 'a') as file:
        data_str = [str(item) for item in data]  # Convert all items to strings
        file.write(",".join(data_str) + "\n")


# Function for user enumeration on target system
def enumerate_users(ip, smb_username, smb_password):
    users = []

    try:
        conn = SMBConnection(smb_username, smb_password, "", "")
        if conn.connect(ip, 445):
            shared_files = conn.listShares()
            for share in shared_files:
                for f in conn.listPath(share.name, '/'):
                    if f.isDirectory:
                        users.append(f.filename)
    except Exception as e:
        print(f"Error enumerating users on {ip}: {e}")

    return users


# Function to scan for vulnerabilities in open ports and services
def scan_for_vulnerabilities(ip, service_name):
    vulnerabilities = {}
    if service_name == "HTTP":
        vulnerabilities[ip] = ["CVE-2023-1234", "CVE-2023-5678"]
    elif service_name == "HTTPS":
        vulnerabilities[ip] = ["CVE-2023-9012"]
    elif service_name == "SSH":
        vulnerabilities[ip] = ["CVE-2023-4567"]
    # Add more vulnerable services and associated CVEs as needed
    return vulnerabilities.get(ip, [])


# Main function that runs the tool
def main():
    log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'log.csv')

    print("Network Enumeration and Monitoring Tool")
    print("-" * 40)

    # Manually enter the API key for geolocation
    api_key = input("Enter your ipinfo.io API key: ")

    while True:
        ip_or_subnet = input("\nEnter the IP address or subnet to scan (e.g., 192.168.0.103 or 192.168.0.0/24): ")

        try:
            subnet = ipaddress.IPv4Network(ip_or_subnet, strict=False)
        except ipaddress.AddressValueError:
            print("Invalid IP address or subnet. Please enter a valid IP address or subnet in CIDR notation.")
            continue

        live_hosts, offline_hosts = scan_network(subnet)

        if not live_hosts:
            print("No live hosts found in the specified subnet. Please enter a valid IP address or subnet.")
            continue

        print("\nLive Hosts on the Network:")
        for host in live_hosts:
            print(host)

        print("\nOffline Hosts on the Network:")
        for host in offline_hosts:
            print(host)

        while True:
            # User Input for port scanning
            port_scan_choice = input(
                "\nDo you want to scan all ports, specific ports, or open ports only? (all/specific/open): ")

            if port_scan_choice.lower() == 'all':
                open_ports = scan_all_ports(live_hosts[0])
            elif port_scan_choice.lower() == 'specific':
                ports_str = input("Enter the specific ports to scan (e.g., 80,443,22): ")
                ports = [int(port) for port in ports_str.split(",")]
                open_ports = scan_specific_ports(live_hosts[0], ports)
            elif port_scan_choice.lower() == 'open':
                open_ports = scan_specific_ports(live_hosts[0], [80, 443, 22])  # Scan commonly open ports only
            else:
                print("Invalid choice. Scanning all ports.")
                open_ports = scan_all_ports(live_hosts[0])

            if not open_ports:
                print("No open ports found.")
            else:
                print("\nOpen Ports on", live_hosts[0], ":")
                for port in open_ports:
                    print(f"Port {port} is open.")

                ip_address = input("\nEnter the IP address for geolocation (leave empty to skip): ")
                if ip_address:
                    country, region = get_geolocation(ip_address, api_key)
                    print(f"{ip_address} - Country: {country}, Region: {region}")
                    log_to_csv(log_file, [datetime.datetime.now(), f"Geolocation for {ip_address}", f"Country: {country}", f"Region: {region}"])

                # Perform service enumeration
                service_info = enumerate_services(live_hosts[0], open_ports)
                print("\nService Enumeration Results:")
                for port, service in service_info.items():
                    print(f"Port {port}: {service}")
                    log_to_csv(log_file, [datetime.datetime.now(), f"Service on {live_hosts[0]}", f"Port {port}", service])

                # Perform user enumeration
                smb_username = input("\nEnter SMB username for user enumeration (leave empty to skip): ")
                if smb_username:
                    smb_password = input("Enter SMB password: ")
                    users = enumerate_users(live_hosts[0], smb_username, smb_password)
                    if users:
                        print(f"\nUsers on {live_hosts[0]}:")
                        for user in users:
                            print(user)
                            log_to_csv(log_file, [datetime.datetime.now(), f"User on {live_hosts[0]}", user])

                # Perform vulnerability scanning
                for port in open_ports:
                    service_name = service_info.get(port, "Unknown")
                    vulnerabilities = scan_for_vulnerabilities(live_hosts[0], service_name)
                    if vulnerabilities:
                        print(f"\nVulnerabilities on {live_hosts[0]} - Port {port}:")
                        for cve in vulnerabilities:
                            print(cve)
                            log_to_csv(log_file, [datetime.datetime.now(), f"Vulnerability on {live_hosts[0]} - Port {port}", cve])
                    else:
                        print(f"No vulnerabilities found for the open port {port}.")

            choice = input("\nDo you want to scan the same IP address again? (yes/no): ")
            if choice.lower() != 'yes':
                break

        new_scan_choice = input("\nDo you want to start a new scan? (yes/no): ")
        if new_scan_choice.lower() != 'yes':
            break

if __name__ == "__main__":
    main()
