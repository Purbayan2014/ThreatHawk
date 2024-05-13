from datetime import datetime
import requests
from modules.root import *
from fake_useragent import UserAgent
from tabulate import tabulate 

class KasperskyOpenTIPZones:
    zones = {
        "Red": {"threat_level": f"{c.Red}High{c.Reset}", "zone": f"{c.Red}Red{c.Reset}", "description": f"{c.Red}Dangerous{c.Reset}"},
        "Orange": {"threat_level": f"{c.Orange}Medium{c.Reset}", "zone": f"{c.Orange}Orange{c.Reset}", "description": f"{c.Orange}N/D *{c.Reset}"},
        "Grey": {"threat_level": f"{c.DarkGrey}Info{c.Reset}", "zone": f"{c.DarkGrey}Grey{c.Reset}", "description": f"{c.DarkGrey}Not categorized{c.Reset}"},
        "Yellow": {"threat_level": f"{c.Yellow}Medium{c.Reset}", "zone": f"{c.Yellow}Yellow{c.Reset}", "description": f"{c.Yellow}Adware and other{c.Reset}"},
        "Green": {"threat_level": f"{c.Green}Info{c.Reset}", "zone": f"{c.Green}Green{c.Reset}", "description": f"{c.Green}Clean / No threats detected{c.Reset}"}
    }

    @classmethod
    def zone_info(cls, zone):
        if zone in KasperskyOpenTIPZones.zones:
            zone_info = cls.zones[zone]
            data = [
                ["Zone", zone_info['zone']],
                ["Danger level", zone_info['threat_level']],
                ["Details", zone_info['description']]
            ]
            return data


class KasperskyOpenTIP:
    def check_ip_reputation(ip):
        try:
            print(f"\nChecking IP reputation on Kaspersky for {c.Orange}{ip}{c.Reset}")
            url_session = "https://opentip.kaspersky.com/ui/checksession"
            agent = UserAgent().random
            headers = {'User-Agent': agent}
            response = requests.get(url_session, headers=headers)
            session = response.headers["Cym9cgwjk"]

            url = 'https://opentip.kaspersky.com/ui/lookup'
            headers = {'User-Agent': agent, 'cym9cgwjk': session}
            data = {'query': ip, 'silent': False}

            response = requests.post(url, headers=headers, json=data)

            if response.status_code == 200:
                data = response.json()
                host = data["GeneralInfo"]["Ip"]
                zone = host["Zone"]
                json_data = KasperskyOpenTIPZones.zone_info(zone)
                header = ["Name", "Value"]
                print(tabulate(json_data, header, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))

        except:
            print(f"{c.Red}Error on IP analysis process for Kaspersky OpenTIP!{c.Reset}")
            pass

    def check_domain_reputation(domain):
        try:
            print(f"\nChecking reputation on Kaspersky for {c.Orange}{domain}{c.Reset}")
            url_session = "https://opentip.kaspersky.com/ui/checksession"
            agent = UserAgent().random
            headers = {'User-Agent': agent}
            response = requests.get(url_session, headers=headers)
            session = response.headers["Cym9cgwjk"]

            url = 'https://opentip.kaspersky.com/ui/lookup'
            headers = {'User-Agent': agent, 'cym9cgwjk': session}
            data = {'query': domain, 'silent': False}

            response = requests.post(url, headers=headers, json=data)

            if response.status_code == 200:
                data = response.json()
                host = data["GeneralInfo"]["Host"]
                zone = host["Zone"]
                json_data = KasperskyOpenTIPZones.zone_info(zone)
                header = ["Name", "Value"]
                print(tabulate(json_data, header, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))

        except:
            print(f"{c.Red}Error on reputation process for Kaspersky OpenTIP!{c.Reset}")
            pass

    def check_file_reputation(hash):
        try:
            print(f"\nChecking file reputation on Kaspersky for {c.Orange}{hash}{c.Reset}")
            url_session = "https://opentip.kaspersky.com/ui/checksession"
            agent = UserAgent().random
            headers = {'User-Agent': agent}
            response = requests.get(url_session, headers=headers)
            session = response.headers["Cym9cgwjk"]

            url = 'https://opentip.kaspersky.com/ui/lookup'
            headers = {'User-Agent': agent, 'cym9cgwjk': session}
            data = {'query': hash, 'silent': False}

            response = requests.post(url, headers=headers, json=data)

            if response.status_code == 200:
                data = response.json()
                host = data["GeneralInfo"]["Hash"]
                zone = host["Zone"]

                status = ["Status", host['Status']]
                type = ["Type", host['Type']]

                json_data = KasperskyOpenTIPZones.zone_info(zone)
                json_data.append(status)
                json_data.append(type)

                try:
                    threats = host['Threats']
                    for x in threats:
                        timestamp_seconds = int(x["LastDetectDate"]) / 1000.0
                        date = datetime.utcfromtimestamp(timestamp_seconds)
                        format_date = date.strftime('%Y-%m-%d %H:%M:%S')
                        LastDetectDate = ["LastDetectDate", format_date]

                        DescriptionUrl = ["DescriptionUrl", f'{c.Green}{x["DescriptionUrl"]}{c.Reset}']
                        Threat = ["Threat", f'{c.Red}{x["Threat"]}{c.Reset}']

                        json_data.append(LastDetectDate)
                        json_data.append(DescriptionUrl)
                        json_data.append(Threat)
                except:
                    pass

                header = ["Name", "Value"]
                print(tabulate(json_data, header, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))

        except:
            print(f"{c.Red}Error on file analysis process for Kaspersky OpenTIP!{c.Reset}")
            pass

    def check_url_analysis(malicious_url):
        try:
            print(f"\nURL analysis on Kaspersky for {c.Orange}{malicious_url}{c.Reset}")
            url_session = "https://opentip.kaspersky.com/ui/checksession"
            agent = UserAgent().random
            headers = {'User-Agent': agent}
            response = requests.get(url_session, headers=headers)
            session = response.headers["Cym9cgwjk"]

            url = 'https://opentip.kaspersky.com/ui/lookup'
            headers = {'User-Agent': agent, 'cym9cgwjk': session}

            data = {'query': malicious_url, 'silent': False}

            response = requests.post(url, headers=headers, json=data)

            if response.status_code == 200:
                data = response.json()
                try:
                    host = data["GeneralInfo"]["Url"]
                    category = ["Categories", data["GeneralInfo"]["Url"]["Categories"]]
                except:
                    host = data["GeneralInfo"]["Host"]
                    pass

                zone = host["Zone"]
                header = ["Name", "Value"]
                json_data = []
                json_data = KasperskyOpenTIPZones.zone_info(zone)
                try:
                    json_data.append(category)
                except:
                    pass
                print(tabulate(json_data, header, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))

        except:
            print(f"{c.Red}Error on URL analysis process for Kaspersky OpenTIP!{c.Reset}")
            pass

    def ip_whois_analysis(ip):
        try:
            url_session = "https://opentip.kaspersky.com/ui/checksession"
            agent = UserAgent().random
            headers = {'User-Agent': agent}
            response = requests.get(url_session, headers=headers)
            session = response.headers["Cym9cgwjk"]

            url = 'https://opentip.kaspersky.com/ui/lookup'
            headers = {'User-Agent': agent, 'cym9cgwjk': session}
            data = {'query': ip, 'silent': False, }

            response = requests.post(url, headers=headers, json=data)

            if response.status_code == 200:
                data = response.json()
                whois_result = data["GeneralInfo"]["Ip"]['IpWhois']

                results = []
                for x in whois_result:
                    if x == 'Contacts':
                        Contacts = whois_result['Contacts']
                        for contact in Contacts:
                            try:
                                for x in contact:
                                    row = [x, contact[x]]
                                    results.append(row)
                            except:
                                pass
                    else:
                        row = [x, whois_result[x]]
                        results.append(row)

                header = ["Name", "Value"]
                print(tabulate(results, header, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))

        except:
            print(f"{c.Red}Error on IP analysis process for Kaspersky OpenTIP!{c.Reset}")
            pass
      
    def domain_whois_analysis(domain):
        try:
            url_session = "https://opentip.kaspersky.com/ui/checksession"
            agent = UserAgent().random
            headers = {'User-Agent': agent}
            response = requests.get(url_session, headers=headers)
            session = response.headers["Cym9cgwjk"]

            url = 'https://opentip.kaspersky.com/ui/lookup'
            headers = {'User-Agent': agent, 'cym9cgwjk': session}
            data = {'query': domain, 'silent': False, }

            response = requests.post(url, headers=headers, json=data)

            if response.status_code == 200:
                data = response.json()
                whois_result = data["GeneralInfo"]["Host"]['DomainWhois']

                results = []
                for x in whois_result:
                    if x == 'Contacts':
                        Contacts = whois_result['Contacts']
                        for contact in Contacts:
                            try:
                                for x in contact:
                                    row = [x, contact[x]]
                                    results.append(row)
                                row = ["", ""]
                                results.append(row)
                            except:
                                pass
                    else:
                        row = [x, whois_result[x]]
                        results.append(row)

                header = ["Name", "Value"]
                print(tabulate(results, header, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))

        except:
            print(f"{c.Red}Error on domain analysis process for Kaspersky OpenTIP!{c.Reset}")
            pass
