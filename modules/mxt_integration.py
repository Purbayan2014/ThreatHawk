import requests
from modules.root import *
from fake_useragent import UserAgent
from tabulate import tabulate

class MXTReputation:
    def check_blacklist(value):
        try:
            agent = UserAgent().random
            print(f"\nChecking domain/IP {c.Orange}{value}{c.Reset} for blacklist on MXTReputation...")
            headers = {"User-Agent": agent, "TempAuthorization": "27eea1cd-e644-4b7b-bebe-38010f55dab3"}
            response = requests.get(f"https://mxtoolbox.com/api/v1/Lookup?command=blacklist&argument={value}&resultindext=1&disableRhsbl=true&format=1", headers=headers)
            if response.status_code == 200:
                data = response.json()
                if data['ResultDS']:
                    result_ds = data['ResultDS']['SubActions']
                    header = ["Name", "Result"]
                    result_data = []
                    for item in result_ds:
                        verdict = item['Status']
                        result = ""
                        if verdict == "0":
                            result = f"{c.Green}Clean{c.Reset}"
                        elif verdict == "1":
                            result = f"{c.Yellow}Timeout{c.Reset}"
                        else:
                            result = f"{c.Red}Listed{c.Reset}"
                        name = item['Name']
                        result_data.append([name, result])
                    print(tabulate(result_data, header, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))
        except:
            print(f"{c.Red}Error during domain/IP reputation check on MXTReputation!{c.Reset}")
            pass

    def check_spf(domain):
        try:
            agent = UserAgent().random
            print(f"\nChecking SPF for domain {c.Orange}{domain}{c.Reset} on MXTReputation...")
            headers = {"User-Agent": agent, "TempAuthorization": "27eea1cd-e644-4b7b-bebe-38010f55dab3"}
            response = requests.get(f"https://mxtoolbox.com/api/v1/Lookup?command=spf&argument={domain}&resultindext=2&disableRhsbl=true&format=1", headers=headers)
            if response.status_code == 200:
                data = response.json()
                if data['ResultDS']:
                    result_ds = data['ResultDS']['SubActions']
                    spf_description = data['ResultDS']['Information'][0]['Description']
                    header = ["Module", "Result"]
                    result_data = []
                    for item in result_ds:
                        verdict = item['Status']
                        if verdict == "0":
                            result = f"{c.Green}{item['Response']}{c.Reset}"
                        elif verdict == "1":
                            result = f"{c.Yellow}{item['Response']}{c.Reset}"
                        else:
                            result = f"{c.Red}{item['Response']}{c.Reset}"
                        name = item['Name']
                        result_data.append([name, result])
                    print(f"\nSPF: {c.Orange}{spf_description}{c.Reset}\n")
                    print(tabulate(result_data, header, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))
        except:
            print(f"{c.Red}Error during SPF check on MXTReputation!{c.Reset}")
            pass
