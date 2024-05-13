import socket
import requests
from modules.root import *
from fake_useragent import UserAgent
import dns.resolver
from tabulate import tabulate

class NetworkScanner:
    def resolve_ip_data(ip_address):
        try:
            print(f"\nObtaining IP resolution data from Shodan for {c.Orange}{ip_address}{c.Reset}")
            url_session = f"https://internetdb.shodan.io/{ip_address}"
            agent = UserAgent().random
            headers = {'User-Agent': agent}
            response = requests.get(url_session, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                analysis = data['hostnames']
                result = []

                for x in analysis:
                    row = ["Shodan", x]
                    result.append(row)

                return result

        except:
            print(f"{c.Red}Error encountered during IP resolution process with Shodan!{c.Reset}")
            pass

    def check_ports_vulnerabilities(domain_or_ip):
        try:
            print(f"\nChecking open ports and vulnerabilities data on Shodan for {c.Orange}{domain_or_ip}{c.Reset}")

            try:
                result = dns.resolver.resolve(domain_or_ip, 'A')
                for x in result:
                    print(f"IP address detected for {c.Orange}{domain_or_ip}{c.Reset} is {c.Orange}{x}{c.Reset}")
                    url_session = f"https://internetdb.shodan.io/{x}"
                    agent = UserAgent().random
                    headers = {'User-Agent': agent}
                    response = requests.get(url_session, headers=headers)
            
                    if response.status_code == 200:
                        data = response.json()
                        try:
                            ports = []
                            for port in data['ports']:
                                try:  
                                    print(f"Checking connection to port {c.Orange}{port}{c.Reset}")
                                    conn = socket.socket()  
                                    conn.settimeout(3)
                                    conn.connect((domain_or_ip, port))  
                                    banner = conn.recv(1024) 
                                    row = [port, banner.decode('utf-8')]
                                    ports.append(row)
                                except socket.timeout:
                                    print(f"Connection timeout for port {c.Orange}{port}{c.Reset}")
                                except:
                                    pass
                            
                            header = ["Port", "Banner"]
                            print(tabulate(ports, header, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))

                        except:
                            pass

                        try:
                            vulnerabilities = []
                            try:
                                for vuln in data['vulns']:
                                    row = [vuln]
                                    vulnerabilities.append(row)

                                header = ["Vulnerabilities"]
                                print(tabulate(vulnerabilities, header, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))
                            except:
                                pass        
                        except:
                            pass
            except:
                print(f"{c.Red}Error: No IP data detected!{c.Reset}")
                pass

        except:
            print(f"{c.Red}Error encountered during open ports detection process with Shodan!{c.Reset}")
            pass
