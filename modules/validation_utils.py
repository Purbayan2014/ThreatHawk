import re
import ipaddress
from modules.malware_db_integration import *

class Validator:

    def validate_domain(value):
        try:
            ipaddress.ip_address(value)
            return False
        except ValueError:
            domain_pattern = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$")
            return bool(domain_pattern.match(value))

    def validate_ip_address(value):
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def validate_url(value):
        try:
            url_pattern = re.compile(
                r'^(https?|ftp):\/\/'  
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
                r'localhost|'
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
                r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'
                r'(?::\d+)?'
                r'(?:/?|[/?]\S+)$', re.IGNORECASE
            )

            return bool(url_pattern.match(value))
        except:
            return False

    def validate_hostname(value):
        try:
            ipaddress.ip_address(value)
            return False
        except:
            hostname_pattern = re.compile(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$')
            return bool(hostname_pattern.match(value))

    def validate_hash(value):
        try:
            md5_pattern = re.compile(r'^[a-fA-F0-9]{32}$')
            sha256_pattern = re.compile(r'^[a-fA-F0-9]{64}$')
            sha512_pattern = re.compile(r'^[a-fA-F0-9]{128}$')
                
            if bool(md5_pattern.match(value)):
                MalwareDatabase.lookup_hash(value)
                return False
            if bool(sha256_pattern.match(value)):
                return True
            elif bool(sha512_pattern.match(value)):
                return True
            else:
                return False   
        except:
            print(f"{c.Red}Invalid hash!{c.Reset}")
            return False
