# Network Enumeration and Monitoring Tool

The Network Enumeration and Monitoring Tool is a Python script that allows users to perform network scanning and enumeration to discover live hosts, open ports, services running on those ports, and geolocation data for the hosts. It also provides the functionality to scan for vulnerabilities in the open ports and services found.

## Features

1. **Ping Host Check**: The tool can check if a host is live (responds to ping) to filter out offline hosts.

2. **Network Scanning**: It allows scanning a specified IP address or subnet to discover live hosts on the network.

3. **Port Scanning**: Users can choose to scan all ports, specific ports, or commonly open ports for live hosts.

4. **Service Enumeration**: The tool will enumerate services running on the open ports and allow the user to enter custom service names.

5. **Geolocation Data**: Users can fetch geolocation data for a specific IP address using the ipinfo.io API.

6. **User Enumeration**: It can perform user enumeration on target systems that support SMB.

7. **Vulnerability Scanning**: The tool can simulate vulnerability scanning for open ports and services.

8. **Logging to CSV**: All scan results, geolocation data, users, and vulnerabilities found are logged to a CSV file.

## Requirements

The tool requires the following to run:

- Python 3.x
- Requests library: Install using `pip install requests`
- The `smb` library: Install using `pip install pysmb`

## How to Use

1. Clone the repository and navigate to the project directory.

2. Install the required libraries using `pip` if not already installed.

3. Run the script using `python main.py`.

4. Enter your ipinfo.io API key when prompted to fetch geolocation data.

5. Input the IP address or subnet to scan.

6. Choose the port scanning option: all, specific, or open ports only.

7. The tool will display the live hosts and offline hosts on the network.

8. For each live host, it will display the open ports, services, and allow geolocation for specific IP addresses.

9. User enumeration can be performed by providing SMB credentials.

10. Vulnerability scanning will be simulated based on the service names and associated CVEs.

11. The results will be logged to a CSV file named `log.csv` in the project directory.

## Improvements and Customization

1. For more comprehensive vulnerability scanning, integrate specialized scanning tools like Nessus or Nmap.

2. Add more predefined services and associated CVEs in the `scan_for_vulnerabilities` function.

3. Enhance user enumeration by supporting additional protocols or authentication methods.

4. Customize the tool to suit your network scanning and monitoring needs.

5. Use a proper database or vulnerability API to obtain up-to-date CVE information.

6. Add error handling and input validation to improve the robustness of the tool.

7. Implement multithreading or asynchronous scanning to speed up the scanning process.

## Disclaimer

This tool is intended for educational and testing purposes only. Use it responsibly and with proper authorization. The authors of this tool are not responsible for any misuse or damage caused by its usage. Always seek proper authorization before performing network scanning and vulnerability assessment on any network or system.

## License

This project is licensed under the [MIT License](LICENSE). Feel free to use, modify, and distribute it as per the license terms.