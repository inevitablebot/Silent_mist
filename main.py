from footprinting import subdomain_info
import warnings



sub_info=subdomain_info()

enter_subdomain=input("enter subdomain to scan ")
sub_info.get_subdomains(enter_subdomain,threads=40,verbose=False)
alive_sub=sub_info.check_alive_subdomain()
print(f"alive subdomains : {alive_sub}")
domain_ip=sub_info.get_domain_ip(enter_subdomain)
print(domain_ip)
sub_info.get_ip()
