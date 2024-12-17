import sublist3r
import requests
import warnings
warnings.filterwarnings("ignore")
import logging
logging.getLogger("urllib3").setLevel(logging.CRITICAL)  
logging.getLogger("sublist3r").setLevel(logging.CRITICAL) 
import socket


class subdomain_info:
    def __init__(self):
        self.domain_ip=[]
        self.subdomains = []
        self.alive=[]
        self.sub_ip=[]
    def get_domain_ip(self,domain):
        try:
            self.domain_ip = socket.gethostbyname(domain)
            return self.domain_ip
        except Exception as e:
            print(f"Error: {e}")
        
    def get_subdomains(self,domain, threads=10, verbose=False):
        try:
            print(f"Fetching subdomains for: {domain}")

            self.subdomains = sublist3r.main(
                domain=domain,
                threads=threads,
                savefile=None,
                ports=None,
                silent=not verbose,
                verbose=verbose,
                enable_bruteforce=False,  
                engines=None              
            )
            with open("subdomains.txt", "w") as f:
                for subdomain in self.subdomains:
                    f.write(subdomain + "\n")
            print(f"Found {len(self.subdomains)} subdomains.")
            
            
        except Exception as e:
            print(f"Error fetching subdomains: {e}")

    def check_alive_subdomain(self):
        if not self.subdomains:
            print("No subdomains to check.")
            return []
        self.alive = []
        for sub in self.subdomains:
            url=f"http://{sub}"
            try:
                response = requests.head(url, timeout=5)
                if response.status_code <400:
                    self.alive.append(sub)
                    print(f"Subdomain {sub} is alive")
            except requests.ConnectionError:
                print(f"Connection error for subdomain: {sub}")
            except requests.Timeout:
                print(f"Timeout for subdomain: {sub}")
            except requests.RequestException as e:
                print(f"Error checking subdomain {sub}: {e}")                    

        with open("alive_subdomains.txt","w")as f:
                for sub in self.alive:
                    f.write(sub + "\n")
        return self.alive

    def get_ip(self):
        if not self.alive:
            print("no alive subdomains ")
            return []
        print("resolving ip for subdomains")
        self.sub_ip=[]
        for sub in self.alive:

            try:
                ip = socket.gethostbyname(sub)
                self.sub_ip.append((ip))

                print(f"IP for subdomain {sub} is {ip}")
                
            except Exception as e:
                print(e)
        with open("ip_gatherd.txt","w") as f:
            for ip in self.sub_ip:
                f.write(ip + "\n")
        return self.sub_ip