from footprinting import subdomain_info
import warnings
from dns_sniffer import Device
import argparse
from reveeng import memory_analysis


sub_info = subdomain_info()


def subdomain_scan():
    enter_subdomain = input("Enter subdomain to scan: ")
    sub_info.get_subdomains(enter_subdomain, threads=40, verbose=False)

    alive_sub = sub_info.check_alive_subdomain()
    print(f"Alive subdomains: {alive_sub}")
    alive_ips = sub_info.get_ip()
    alive_ips = sub_info.ports_open()

    domain_ip = sub_info.get_domain_ip(enter_subdomain)


def arp_mitm():
    routerip = input("Enter router IP: ")
    network = input("Enter network to scan (e.g., 192.168.0.0/24): ")
    interface = input("Enter network interface (press enter for default ): ")

    device = Device(routerip, network, interface)
    targetip = device.arp_scan(network, interface)
    device.targetip = targetip
    device.watch()


def memory_analysis_main():
    pid = int(input("Enter the PID of the process to analyze: "))
    try:
        
        memory_check = memory_analysis(pid)  
        memory_check.analyze_loaded_modules()
    except Exception as e:
        print(f"Error analyzing loaded modules: {e}")



def main():
    choice = input("Choose functionality:\n1. Subdomain Scan\n2. ARP MITM\n3. Memory Analysis\nEnter 1, 2, or 3: ")

    if choice == '1':
        subdomain_scan()
    elif choice == '2':
        arp_mitm()
    elif choice == '3':
        memory_analysis_main()
    else:
        print("Invalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()
