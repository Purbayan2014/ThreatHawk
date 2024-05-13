from datetime import datetime
from urllib.parse import quote
import requests
from modules.root import *
from fake_useragent import UserAgent
from tabulate import tabulate

class SecurityScan:
    def check_ip_reputation(ip_address):
        try:
            print(f"\nAssessing IP reputation via SecurityScan for {c.Orange}{ip_address}{c.Reset}")
            url = f"https://www.virustotal.com/ui/ip_addresses/{ip_address}"
            agent = UserAgent().random
            headers = { 
                'User-Agent': agent, 
                'X-VT-Anti-Abuse-Header': 'MTI1MDc2MDQwMjAtWkc5dWRDQmlaU0JsZG1scy0xNzAzNDAwMDI4LjU3Nw==',
                'X-Tool': 'vt-ui-main',
                'Accept-Ianguage': 'en-US,en;q=0.9,es;q=0.8'
            }
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                last_analysis_stats = data['data']['attributes']['last_analysis_stats']

                result = []
                for key, value in last_analysis_stats.items():
                    row = [key, value]
                    result.append(row)

                header = ["Name", "Value"]
                print(tabulate(result, header, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))

                if last_analysis_stats['malicious'] > 0 or last_analysis_stats['suspicious'] > 0:
                    print(f"\nDetails for {c.Orange}{ip_address}{c.Reset}")
                    engines = []
                    last_analysis_results = data['data']['attributes']['last_analysis_results']
                    for engine, details in last_analysis_results.items():
                        category = details['category']
                        if category == "malicious":
                            row = [engine, f"{c.Red}malicious{c.Reset}"]
                            engines.append(row)
                        if category == "suspicious":
                            row = [engine, f"{c.Orange}suspicious{c.Reset}"]
                            engines.append(row)

                    header = ["Engine", "Result"]
                    print(tabulate(engines, header, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))
        except:
            print(f"{c.Red}Error occurred during IP reputation check via SecurityScan!{c.Reset}")
            pass
    
    def check_ip_resolution(ip_address):
        try:
            print(f"\nAnalyzing IP resolution data via SecurityScan for {c.Orange}{ip_address}{c.Reset}")
            url = f"https://www.virustotal.com/ui/ip_addresses/{ip_address}/resolutions"
            agent = UserAgent().random
            headers = { 
                'User-Agent': agent, 
                'X-VT-Anti-Abuse-Header': 'MTI1MDc2MDQwMjAtWkc5dWRDQmlaU0JsZG1scy0xNzAzNDAwMDI4LjU3Nw==',
                'X-Tool': 'vt-ui-main',
                'Accept-Ianguage': 'en-US,en;q=0.9,es;q=0.8'
            }
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                
                resolutions = data['data']
                result = []
                for entry in resolutions:
                    host_name = entry["attributes"]["host_name"]
                    row = ["SecurityScan", host_name]
                    result.append(row)

                return result

        except:
            print(f"{c.Red}Error occurred during IP resolution check via SecurityScan!{c.Reset}")
            pass
    
    def check_domain_reputation(domain):
        try:
            print(f"\nAssessing domain reputation via SecurityScan for {c.Orange}{domain}{c.Reset}")
            url = f"https://www.virustotal.com/ui/domains/{domain}"
            agent = UserAgent().random
            headers = { 
                'User-Agent': agent, 
                'X-VT-Anti-Abuse-Header': 'MTI1MDc2MDQwMjAtWkc5dWRDQmlaU0JsZG1scy0xNzAzNDAwMDI4LjU3Nw==',
                'X-Tool': 'vt-ui-main',
                'Accept-Ianguage': 'en-US,en;q=0.9,es;q=0.8'
            }
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                last_analysis_stats = data['data']['attributes']['last_analysis_stats']

                result = []
                for key, value in last_analysis_stats.items():
                    row = [key, value]
                    result.append(row)

                header = ["Name", "Value"]
                print(tabulate(result, header, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))

                if last_analysis_stats['malicious'] > 0 or last_analysis_stats['suspicious'] > 0:
                    print(f"\nDetails for {c.Orange}{domain}{c.Reset}")
                    engines = []
                    last_analysis_results = data['data']['attributes']['last_analysis_results']
                    for engine, details in last_analysis_results.items():
                        category = details['category']
                        if category == "malicious":
                            row = [engine, f"{c.Red}malicious{c.Reset}"]
                            engines.append(row)
                        if category == "suspicious":
                            row = [engine, f"{c.Orange}suspicious{c.Reset}"]
                            engines.append(row)

                    header = ["Engine", "Result"]
                    print(tabulate(engines, header, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))
                    SecurityScan.check_domain_communicating_files(domain)
                    
                SecurityScan.check_domain_ip_resolution(domain)
        except:
            print(f"{c.Red}Error occurred during domain reputation check via SecurityScan!{c.Reset}")
            pass


    def check_domain_communicating_files(domain):
        try:
            print(f"\nAnalyzing communicating files for domain {c.Orange}{domain}{c.Reset} via SecurityScan")
            url = f"https://www.virustotal.com/ui/domains/{domain}/communicating_files"
            agent = UserAgent().random
            headers = { 
                'User-Agent': agent, 
                'X-VT-Anti-Abuse-Header': 'MTI1MDc2MDQwMjAtWkc5dWRDQmlaU0JsZG1scy0xNzAzNDAwMDI4LjU3Nw==',
                'X-Tool': 'vt-ui-main',
                'Accept-Ianguage': 'en-US,en;q=0.9,es;q=0.8'
            }
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                results = data['data']

                jsondata = []

                try:
                    for entry in results:
                        last_analysis_stats = entry['attributes']['last_analysis_stats']

                        suspicious = f"{c.Orange}{last_analysis_stats['suspicious']}{c.Reset}"
                        malicious = f"{c.Red}{last_analysis_stats['malicious']}{c.Reset}"
                        harmless = f"{c.Green}{last_analysis_stats['harmless']}{c.Reset}"
                        undetected = f"{c.DarkGrey}{last_analysis_stats['undetected']}{c.Reset}"

                        meaningful_name = entry['attributes']['meaningful_name']
                        md5 = entry['attributes']['md5']
                        type_extension = entry['attributes']['type_extension']

                        row = [meaningful_name, type_extension, md5, harmless, malicious, suspicious, undetected]
                        jsondata.append(row)
                except:
                    pass

                header = ["Name", "Type", "MD5", "Harmless", "Malicious", "Suspicious", "Undetected"]
                print(tabulate(jsondata, header, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))

        except:
            print(f"{c.Red}Error occurred during communicating files analysis for domain {c.Orange}{domain}{c.Reset} via SecurityScan!")
            pass

    def check_domain_ip_resolution(domain):
        try:
            print(f"\nAnalyzing domain resolution IP history for {c.Orange}{domain}{c.Reset} via SecurityScan")
            url = f"https://www.virustotal.com/ui/domains/{domain}/resolutions"
            agent = UserAgent().random
            headers = { 
                'User-Agent': agent, 
                'X-VT-Anti-Abuse-Header': 'MTI1MDc2MDQwMjAtWkc5dWRDQmlaU0JsZG1scy0xNzAzNDAwMDI4LjU3Nw==',
                'X-Tool': 'vt-ui-main',
                'Accept-Ianguage': 'en-US,en;q=0.9,es;q=0.8'
            }
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                results = data['data']
                jsondata = []

                try:
                    for entry in results:
                        last_analysis_stats = entry['attributes']['ip_address_last_analysis_stats']

                        suspicious = f"{c.Orange}{last_analysis_stats['suspicious']}{c.Reset}"
                        malicious = f"{c.Red}{last_analysis_stats['malicious']}{c.Reset}"
                        harmless = f"{c.Green}{last_analysis_stats['harmless']}{c.Reset}"
                        undetected = f"{c.DarkGrey}{last_analysis_stats['undetected']}{c.Reset}"

                        ip_address = entry['attributes']['ip_address']
                        detected_date = entry['attributes']['date']
                        host_name = entry['attributes']['host_name']

                        dt_object = datetime.utcfromtimestamp(detected_date)
                        formatted_date_time = dt_object.strftime("%Y-%m-%d %H:%M:%S UTC")
                        row = [host_name, formatted_date_time, ip_address, harmless, malicious, suspicious, undetected]
                        jsondata.append(row)
                except:
                    pass

                header = ["Hostname", "Date", "IP", "Harmless", "Malicious", "Suspicious", "Undetected"]
                print(tabulate(jsondata, header, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))

        except:
            print(f"{c.Red}Error occurred during domain resolution IP analysis for {c.Orange}{domain}{c.Reset} via SecurityScan!")
            pass

    def enumerate_subdomains(domain):
        try:
            print(f"\nEnumerating subdomains for {c.Orange}{domain}{c.Reset} via SecurityScan")
            url = f"https://www.virustotal.com/ui/domains/{domain}/subdomains"
            agent = UserAgent().random
            headers = { 
                'User-Agent': agent, 
                'X-VT-Anti-Abuse-Header': 'MTI1MDc2MDQwMjAtWkc5dWRDQmlaU0JsZG1scy0xNzAzNDAwMDI4LjU3Nw==',
                'X-Tool': 'vt-ui-main',
                'Accept-Ianguage': 'en-US,en;q=0.9,es;q=0.8'
            }
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                results = data['data']
                jsondata = []

                try:
                    for entry in results:
                        row = ["SecurityScan", entry["id"]]
                        jsondata.append(row)
                except:
                    pass

                return jsondata

        except:
            print(f"{c.Red}Error occurred during subdomain enumeration for {c.Orange}{domain}{c.Reset} via SecurityScan!")
            pass

    def check_file_reputation(hash):
        try:
            print(f"\nAnalyzing file reputation for {c.Orange}{hash}{c.Reset} via SecurityScan")
            url = f"https://www.virustotal.com/ui/files/{hash}"
            agent = UserAgent().random
            headers = { 
                'User-Agent': agent, 
                'X-VT-Anti-Abuse-Header': 'MTI1MDc2MDQwMjAtWkc5dWRDQmlaU0JsZG1scy0xNzAzNDAwMDI4LjU3Nw==',
                'X-Tool': 'vt-ui-main',
                'Accept-Ianguage': 'en-US,en;q=0.9,es;q=0.8'
            }
            response = requests.get(url, headers=headers)

            if response.status_code==200:
                data=response.json()
                attributes=data['data']['attributes']

                jsondata=[]

                type_extension=["Type",attributes['type_extension']]
                meaningful_name=["Name",attributes['meaningful_name']]
                last_analysis_stats=attributes['last_analysis_stats']

                suspicious=["Suspicious",f"{c.Orange}{last_analysis_stats['suspicious']}{c.Reset}"]
                malicious=["Malicious",f"{c.Red}{last_analysis_stats['malicious']}{c.Reset}"]
                harmless=["Harmless",f"{c.Green}{last_analysis_stats['harmless']}{c.Reset}"]
                undetected=["Undetected",f"{c.DarkGrey}{last_analysis_stats['undetected']}{c.Reset}"]

                jsondata.append(meaningful_name)
                jsondata.append(type_extension)
                jsondata.append(suspicious)
                jsondata.append(malicious)
                jsondata.append(harmless)
                jsondata.append(undetected)

                header=["Module","Value"]
                print(tabulate(jsondata, header,  tablefmt="grid",numalign="left",showindex=True,floatfmt=".2f"))

                try:
                    if last_analysis_stats['malicious']>0 or last_analysis_stats['suspicious']>0 :
                        print(f"\nDetails for {c.Orange}{hash}{c.Reset}")
                        last_analysis_results=attributes['last_analysis_results']
                        engines=[]

                        for x in last_analysis_results:   
                            category=last_analysis_results[x]['category'] 
                            result=last_analysis_results[x]['result']
                            if category=="malicious":
                                row=[x,f"{c.Red}malicious{c.Reset}",result]
                                engines.append(row)
                            if category=="suspicious":
                                row=[x,f"{c.Orange}suspicious{c.Reset}",result]
                                engines.append(row)
                    header=["Engine","Result","Details"]
                    print(tabulate(engines, header,  tablefmt="grid",numalign="left",showindex=True,floatfmt=".2f"))
                except:
                    pass
        except:
            print(f"{c.Red}Error occurred during file reputation analysis for {c.Orange}{hash}{c.Reset} via SecurityScan!")
            pass

    def check_contacted_urls(hash):
        try:
            print(f"\nAnalyzing contacted URLs for {c.Orange}{hash}{c.Reset} via SecurityScan")
            url = f"https://www.virustotal.com/ui/files/{hash}/contacted_urls"
            agent = UserAgent().random
            headers = { 
                'User-Agent': agent, 
                'X-VT-Anti-Abuse-Header': 'MTI1MDc2MDQwMjAtWkc5dWRDQmlaU0JsZG1scy0xNzAzNDAwMDI4LjU3Nw==',
                'X-Tool': 'vt-ui-main',
                'Accept-Ianguage': 'en-US,en;q=0.9,es;q=0.8'
            }
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()

                contacted_urls = data['data']

                urls = []

                for url in contacted_urls:
                    url_detected = url['attributes']['url']
                    last_analysis_stats = url['attributes']['last_analysis_stats']

                    suspicious = f"{c.Orange}{last_analysis_stats['suspicious']}{c.Reset}"
                    malicious = f"{c.Red}{last_analysis_stats['malicious']}{c.Reset}"
                    harmless = f"{c.Green}{last_analysis_stats['harmless']}{c.Reset}"
                    undetected = f"{c.DarkGrey}{last_analysis_stats['undetected']}{c.Reset}"

                    row = [url_detected, harmless, malicious, suspicious, undetected]
                    urls.append(row)

               
                header = ["Url", "Harmless", "Malicious", "Suspicious", "Undetected"]
                print(tabulate(urls, header, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))

        except:
            print(f"{c.Red}Error occurred during contacted URLs analysis for {c.Orange}{hash}{c.Reset} via SecurityScan!")
            pass


    def check_contacted_domains(hash):
        try:
            print(f"\nAnalyzing contacted domains for {c.Orange}{hash}{c.Reset} via SecurityScan")
            url = f"https://www.virustotal.com/ui/files/{hash}/contacted_domains"
            agent = UserAgent().random
            headers = { 
                'User-Agent': agent, 
                'X-VT-Anti-Abuse-Header': 'MTI1MDc2MDQwMjAtWkc5dWRDQmlaU0JsZG1scy0xNzAzNDAwMDI4LjU3Nw==',
                'X-Tool': 'vt-ui-main',
                'Accept-Ianguage': 'en-US,en;q=0.9,es;q=0.8'
            }
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                
                contacted_domains = data['data']

                domains = []

                for domain in contacted_domains:

                    domain_detected = domain['id']
                    last_analysis_stats = domain['attributes']['last_analysis_stats']

                    suspicious = f"{c.Orange}{last_analysis_stats['suspicious']}{c.Reset}"
                    malicious = f"{c.Red}{last_analysis_stats['malicious']}{c.Reset}"
                    harmless = f"{c.Green}{last_analysis_stats['harmless']}{c.Reset}"
                    undetected = f"{c.DarkGrey}{last_analysis_stats['undetected']}{c.Reset}"

                    row = [domain_detected, harmless, malicious, suspicious, undetected]
                    domains.append(row)

               
                header = ["Domain", "Harmless", "Malicious", "Suspicious", "Undetected"]
                print(tabulate(domains, header, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))

        except:
            print(f"{c.Red}Error occurred during contacted domains analysis for {c.Orange}{hash}{c.Reset} via SecurityScan!")
            pass
    
    def check_url_reputation(url):
        try:
            print(f"\nAnalyzing URL reputation on VirusTotal for: {c.Orange}{url}{c.Reset}")
            url_encoded = quote(url, safe='')
            url_session = f"https://www.virustotal.com/ui/search?limit=20&relationships%5Bcomment%5D=author%2Citem&query={url_encoded}"
            agent = UserAgent().random
            headers = { 
                'User-Agent': agent, 
                'X-VT-Anti-Abuse-Header': 'MTI1MDc2MDQwMjAtWkc5dWRDQmlaU0JsZG1scy0xNzAzNDAwMDI4LjU3Nw==',
                'X-Tool': 'vt-ui-main',
                'Accept-Ianguage': 'en-US,en;q=0.9,es;q=0.8'
            }
            response = requests.get(url_session, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                jsondata = []

                last_analysis_stats = data['data'][0]['attributes']['last_analysis_stats']

                suspicious = ["Suspicious", f"{c.Orange}{last_analysis_stats['suspicious']}{c.Reset}"]
                malicious = ["Malicious", f"{c.Red}{last_analysis_stats['malicious']}{c.Reset}"]
                harmless = ["Harmless", f"{c.Green}{last_analysis_stats['harmless']}{c.Reset}"]
                undetected = ["Undetected", f"{c.DarkGrey}{last_analysis_stats['undetected']}{c.Reset}"]

                jsondata.append(suspicious)
                jsondata.append(malicious)
                jsondata.append(harmless)
                jsondata.append(undetected)

                header = ["Module", "Value"]
                print(tabulate(jsondata, header, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))

                try:
                    if last_analysis_stats['malicious'] > 0 or last_analysis_stats['suspicious'] > 0:
                        print(f"\nDetailed analysis for: {c.Orange}{url}{c.Reset}")
                        last_analysis_results = data['data'][0]['attributes']['last_analysis_results']
                        engines = []

                        for x in last_analysis_results:   
                            category = last_analysis_results[x]['category'] 
                            result = last_analysis_results[x]['result']
                            if category == "malicious":
                                row = [x, f"{c.Red}malicious{c.Reset}", result]
                                engines.append(row)
                            if category == "suspicious":
                                row = [x, f"{c.Orange}suspicious{c.Reset}", result]
                                engines.append(row)
                    header = ["Engine", "Result", "Details"]
                    print(tabulate(engines, header, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))
                except:
                    pass

        except:
            print(f"{c.Red}Error occurred during URL reputation analysis on VirusTotal!{c.Reset}")
            pass


    def check_hostname_reputation(domain):
        try:
            print(f"\nAnalyzing hostname reputation on VirusTotal for: {c.Orange}{domain}{c.Reset}")
            url_session = f"https://www.virustotal.com/ui/domains/{domain}"
            agent = UserAgent().random
            headers = { 
                'User-Agent': agent, 
                'X-VT-Anti-Abuse-Header': 'MTI1MDc2MDQwMjAtWkc5dWRDQmlaU0JsZG1scy0xNzAzNDAwMDI4LjU3Nw==',
                'X-Tool': 'vt-ui-main',
                'Accept-Ianguage': 'en-US,en;q=0.9,es;q=0.8'
            }
            response = requests.get(url_session, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                last_analysis_stats = data['data']['attributes']['last_analysis_stats']

                result = []
                for x in last_analysis_stats:
                    row = [x, last_analysis_stats[x]]
                    result.append(row)

                header = ["Name", "Value"]
                print(tabulate(result, header, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))

                if last_analysis_stats['malicious'] > 0 or last_analysis_stats['suspicious'] > 0:
                    print(f"\nDetailed analysis for: {c.Orange}{domain}{c.Reset}")
                    engines = []
                    last_analysis_results = data['data']['attributes']['last_analysis_results']
                    for e in last_analysis_results:
                        if last_analysis_results[e]['category'] == "malicious":
                            row = [e, f"{c.Red}malicious{c.Reset}"]
                            engines.append(row)
                        if last_analysis_results[e]['category'] == "suspicious":
                            row = [e, f"{c.Orange}suspicious{c.Reset}"]
                            engines.append(row)

                    header = ["Engine", "Result"]
                    print(tabulate(engines, header, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))
                    SecurityScan.check_domain_communicating_files(domain)
                    
                SecurityScan.check_domain_ip_resolution(domain)
                SecurityScan.check_hostname_siblings(domain)
        except:
            print(f"{c.Red}Error occurred during hostname reputation analysis on VirusTotal!{c.Reset}")
            pass


    def check_hostname_siblings(domain):
        try:
            print(f"\nChecking hostname siblings on VirusTotal for: {c.Orange}{domain}{c.Reset}")
            url_session = f"https://www.virustotal.com/ui/domains/{domain}/siblings"
            agent = UserAgent().random
            headers = { 
                'User-Agent': agent, 
                'X-VT-Anti-Abuse-Header': 'MTI1MDc2MDQwMjAtWkc5dWRDQmlaU0JsZG1scy0xNzAzNDAwMDI4LjU3Nw==',
                'X-Tool': 'vt-ui-main',
                'Accept-Ianguage': 'en-US,en;q=0.9,es;q=0.8'
            }
            response = requests.get(url_session, headers=headers)
            
            if response.status_code == 200:
                data = response.json()

                siblings = data['data']
                result = []

                for sibling in siblings:
                    hostname = sibling['id']
                    last_analysis_stats = sibling['attributes']['last_analysis_stats']

                    suspicious = f"{c.Orange}{last_analysis_stats['suspicious']}{c.Reset}"
                    malicious = f"{c.Red}{last_analysis_stats['malicious']}{c.Reset}"
                    harmless = f"{c.Green}{last_analysis_stats['harmless']}{c.Reset}"
                    undetected = f"{c.DarkGrey}{last_analysis_stats['undetected']}{c.Reset}"

                    row = [hostname, harmless, malicious, suspicious, undetected]
                    result.append(row)

                header = ["Hostname", "Harmless", "Malicious", "Suspicious", "Undetected"]
                print(tabulate(result, header, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))

        except:
            print(f"{c.Red}Error occurred during hostname siblings analysis on VirusTotal!{c.Reset}")
            pass

