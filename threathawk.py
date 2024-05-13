import socket
import sys
from modules.root import *
from modules.mxt_integration import *
from modules.kaspersky_integration import *
from modules.vt_integration import *
from modules.av_intergration import *
from modules.network_scanner import *
from modules.dns_info import *
from modules.validation_utils import *
from tabulate import tabulate
from modules.malware_db_integration import *

Banner.ThreatHawkCLI()

def main_menu():
    print(f"""[{c.Cyan}1{c.Reset}] IP Reputation
[{c.Cyan}2{c.Reset}] Domain Reputation
[{c.Cyan}3{c.Reset}] Hostname Reputation
[{c.Cyan}4{c.Reset}] URL Analysis
[{c.Cyan}5{c.Reset}] File Analysis (MD5/SHA256/SHA512)
[{c.Cyan}6{c.Reset}] Blacklist Check
[{c.Cyan}7{c.Reset}] WHOIS Info
[{c.Cyan}8{c.Reset}] SPF Check
[{c.Cyan}9{c.Reset}] DNS Info
[{c.Cyan}0{c.Reset}] Exit""")

def get_dns_resolution_ip(ip):
    virustotal_result = SecurityScan.check_ip_resolution(ip)
    alienvault_result = AlienVaultIntegration.resolve_ip(ip)
    shodan_result = NetworkScanner.resolve_ip_data(ip)

    results = []
    try:
        for x in virustotal_result:
            results.append(x)
    except:
        pass
   
    try:
        for x in alienvault_result:
            results.append(x)
    except:
        pass
    
    try:
        for x in shodan_result:
            results.append(x)
    except:
        pass
    

    header = ["Engine", "Hostname"]
    print(tabulate(results, header,  tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))

def get_dns_resolution_hostname(hostname):
    virustotal_result = SecurityScan.check_ip_resolution(ip)
    alienvault_result = AlienVaultIntegration.resolve_ip(ip)
    shodan_result = NetworkScanner.resolve_ip_data(ip)

    results = []
    for x in virustotal_result:
        results.append(x)
    for x in alienvault_result:
        results.append(x)
    for x in shodan_result:
        results.append(x)

    header = ["Engine", "Hostname"]
    print(tabulate(results, header,  tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))

while True:
    main_menu()
    option = input(f"{c.Cyan}👾 Enter your choice: {c.Reset}")

    if option == "0":
        sys.exit()
    elif option == "1": # IP Reputation
        ip = input(f"{c.Cyan}Enter IP: {c.Reset}")
        value = ip.replace(" ", "")
        if not Validator.validate_ip_address(value):
            print(f"{c.Red}Invalid IP address format! Please enter a valid IP address.{c.Reset}")
        else:
            KasperskyOpenTIP.check_ip_reputation(value)
            SecurityScan.check_ip_reputation(value)
            get_dns_resolution_ip(value)
            NetworkScanner.check_ports_vulnerabilities(value)

    elif option == "2": # Domain Reputation
        domain = input(f"{c.Cyan}Enter domain: {c.Reset}")
        value = domain.replace(" ", "")
        if not Validator.validate_domain(value):
            print(f"{c.Red}Invalid domain format! Please enter a valid domain.{c.Reset}")
        else:
            KasperskyOpenTIP.check_domain_reputation(value)
            SecurityScan.check_domain_reputation(value)

    elif option == "3": # Hostname Reputation
        hostname = input(f"{c.Cyan}Enter hostname: {c.Reset}")
        value = hostname.replace(" ", "")
        if not Validator.validate_hostname(value):
            print(f"{c.Red}Invalid hostname format! Please enter a valid hostname.{c.Reset}")
        else:
            KasperskyOpenTIP.check_domain_reputation(value)
            SecurityScan.check_hostname_reputation(value)
            NetworkScanner.check_ports_vulnerabilities(value)

    elif option == "4": # URL Analysis
        url = input(f"{c.Cyan}Enter URL: {c.Reset}")
        value = url.replace(" ", "")
        if not Validator.validate_url(value):
            print(f"{c.Red}Invalid URL format! Please enter a valid URL.{c.Reset}")
        else:
            KasperskyOpenTIP.check_url_analysis(value)
            SecurityScan.check_url_reputation(value)

    elif option == "5": # File Analysis
        hash_value = input(f"{c.Cyan}Enter hash (MD5/SHA256/SHA512): {c.Reset}")
        value = hash_value.replace(" ", "")
        if not Validator.validate_hash(value):
            pass
        else:
            KasperskyOpenTIP.check_file_reputation(value)
            SecurityScan.check_file_reputation(value)
            SecurityScan.check_contacted_urls(value)
            SecurityScan.check_contacted_domains(value)
            MalwareDatabase.lookup_hash(value)

    elif option == "6": # Blacklist Check
        domain_ip = input(f"{c.Cyan}Enter domain/IP: {c.Reset}")
        value = domain_ip.replace(" ", "")
        if Validator.validate_ip_address(value) or Validator.validate_domain(value):
            MXTReputation.check_blacklist(value)
        else:
            print(f"{c.Red}Invalid domain or IP address format! Please enter a valid domain or IP address.{c.Reset}")
            

    elif option == "7": # WHOIS Lookup
        domain_or_ip = input(f"{c.Cyan}Enter domain/IP: {c.Reset}")
        value = domain_or_ip.replace(" ", "")
        if Validator.validate_ip_address(value):
            KasperskyOpenTIP.ip_whois_analysis(value)
        elif Validator.validate_domain(value):
            KasperskyOpenTIP.domain_whois_analysis(value)
        else:
            print(f"{c.Red}Invalid domain or IP address format! Please enter a valid domain or IP address.{c.Reset}")

    elif option == "8": # SPF Check
        domain = input(f"{c.Cyan}Enter domain: {c.Reset}")
        value = domain.replace(" ", "")
        if not Validator.validate_domain(value):
            print(f"{c.Red}Invalid domain format! Please enter a valid domain.{c.Reset}")
        else:
            MXTReputation.check_spf(domain)
            
        
    elif option == "9":
        hostname_domain = input(f"{c.Cyan}Enter hostname/domain: {c.Reset}")
        value = hostname_domain.replace(" ", "")
        if Validator.validate_domain(value) or Validator.validate_hostname(hostname_domain):
            DNS_Info.show_info(value)
        else:
            print(f"{c.Red}Invalid domain format! Please enter a valid domain.{c.Reset}")
        
        
    else:
        print(f"{c.Red}Invalid input! Please enter a valid option.{c.Reset}")
