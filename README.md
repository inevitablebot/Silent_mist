
# Silent Mist

**Silent Mist** is a Python tool designed for network reconnaissance and attack simulation, including subdomain enumeration and ARP (Address Resolution Protocol) Man-in-the-Middle (MITM) attacks. The tool is primarily used in the context of redteaming to test and validate network security.

## Features

1. **Subdomain Enumeration**:
   - Fetches subdomains for a given domain using `sublist3r`.
   - Checks which subdomains are alive.
   - Retrieves IP addresses for alive subdomains.

2. **ARP MITM Attack**:
   - Simulates an ARP MITM attack on a given network.
   - Monitors network traffic for DNS requests to capture data.

## Usage

### Prerequisites

- Python 3.x
- `sublist3r` package (for subdomain enumeration)
- `requests` package
- `scapy` library (for ARP MITM attacks)
- `colorama` for colored output
- `mac_vendor_lookup` to lookup MAC addresses

Install the required packages using:
```bash
pip install -r requirements.txt
```

### Running the Tool

1. **Subdomain Scan**:
   - Run the script and choose option 1.
   ```bash
   python main.py
   ```
   - Input the domain you want to scan when prompted.
   ```plaintext
   Enter subdomain to scan: example.com
   ```

2. **ARP MITM Attack**:
   - Run the script and choose option 2.
   ```bash
   python main.py
   ```
   - Input the router IP, network to scan, and network interface.
   ```plaintext
   Enter router IP: 192.168.1.1
   Enter network to scan (e.g., 192.168.0.0/24): 192.168.0.0/24
   Enter network interface (press enter for default): eth0
   ```

### Features Breakdown

- **Subdomain Info**:
  - Fetches subdomains for a given domain.
  - Checks which of those subdomains are alive.
  - Retrieves IPs for alive subdomains and saves them to a file.
  
- **ARP MITM**:
  - Manages ARP poisoning to intercept network traffic.
  - Captures DNS requests and displays them with timestamps.

### Files Overview

- `main.py`: Main entry point for the tool.
- `footprinting.py`: Handles subdomain enumeration.
- `dns_sniffer.py`: Manages ARP MITM and network sniffing.

### Future Enhancements

- **Improved Error Handling**: More robust error handling and logging.
- **Automated Reporting**: Implement functionality for automated reporting of findings.
- **Integration with GUI**: Develop a graphical user interface (GUI) for easier interaction.
- **Support for Additional Tools**: Integration with more security tools for enhanced functionalities.

## Contributing

Feel free to contribute to this project! Contributions can include bug fixes, new features, documentation, and improvements to existing functionality. Please follow the contribution guidelines in the project repository.

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For any inquiries or contributions, please contact:

- **Author**: [inevitablebot](https://github.com/inevitablebot)
- **Email**: [your_email@example.com]
