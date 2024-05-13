import dns.resolver
from tabulate import tabulate
from modules.root import *
from modules.vt_integration import *
from modules.av_intergration import *

class DNS_Info:

    def show_info(hostname):
        type_a_records = DNS_Info.get_record_type_a(hostname)
        type_mx_records = DNS_Info.get_record_type_mx(hostname)
        type_txt_records = DNS_Info.get_record_type_txt(hostname)
        type_ns_records = DNS_Info.get_record_type_ns(hostname)
        type_soa_records = DNS_Info.get_record_type_soa(hostname)

        records = []
        try:
            for x in type_a_records:
                records.append(x)
        except:
            pass

        try:
            for x in type_mx_records:
                records.append(x)
        except:
            pass
        
        try:
            for x in type_txt_records:
                records.append(x)
        except:
            pass
        
        try:
            for x in type_ns_records:
                records.append(x)
        except:
            pass

        try:
            for x in type_soa_records:
                records.append(x)
        except:
            pass

        headers = ["Record Type", "Value"]
        print(tabulate(records, headers, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))

        vt_results = SecurityScan.enumerate_subdomains(hostname)
        av_results = AlienVaultIntegration.enumerate_subdomains(hostname)
        results = []
        try:
            for x in vt_results:
                results.append(x)
            for x in av_results:
                results.append(x)
        except:
            pass

        headers = ["Engine", "Hostname"]
        print(tabulate(results, headers, tablefmt="grid", numalign="left", showindex=True, floatfmt=".2f"))

    def get_record_type_a(hostname):
        try:
            result = dns.resolver.resolve(hostname, 'A')
            records = []
            for x in result:
                row = ["A", x]
                records.append(row)
            
            return records

        except:
            pass

    def get_record_type_mx(hostname):
        try:
            result = dns.resolver.resolve(hostname, 'MX')
            records = []
            for x in result:
                row = ["MX", x]
                records.append(row)
            return records

        except:
            pass

    def get_record_type_txt(hostname):
        try:
            result = dns.resolver.resolve(hostname, 'TXT')
            records = []
            for x in result:
                row = ["TXT", x]
                records.append(row)
            return records

        except:
            pass

    def get_record_type_ns(hostname):
        try:
            result = dns.resolver.resolve(hostname, 'NS')
            records = []
            for x in result:
                row = ["NS", x]
                records.append(row)
            return records

        except:
            pass

    def get_record_type_soa(hostname):
        try:
            result = dns.resolver.resolve(hostname, 'SOA')
            records = []
            for x in result:
                row = ["SOA", x]
                records.append(row)
            return records

        except:
            pass
