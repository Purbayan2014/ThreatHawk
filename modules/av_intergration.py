import requests
from modules.root import c
from fake_useragent import UserAgent

class AlienVaultIntegration:
    @staticmethod
    def resolve_ip(ip):
        try:
            print(f"\nPerforming IP resolution lookup on AlienVault for \033[33m{ip}\033[0m")
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns"
            agent = UserAgent().random
            headers = {'User-Agent': agent}
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json().get('passive_dns', [])
                result = [["AlienVault", x["hostname"]] for x in data]
                return result

        except Exception as e:
            print(f"\033[31mError occurred during IP resolution lookup on AlienVault!\033[0m")
            print(e)

    @staticmethod
    def enumerate_subdomains(domain):
        try:
            print(f"\nPerforming subdomain enumeration on AlienVault for domain \033[33m{domain}\033[0m")
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            agent = UserAgent().random
            headers = {'User-Agent': agent}
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json().get('passive_dns', [])
                result = [["AlienVault", x["hostname"]] for x in data]
                return result

        except Exception as e:
            print(f"\033[31mError occurred during subdomain enumeration on AlienVault!\033[0m")
            print(e)
