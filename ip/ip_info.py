#! /bin/python3

import sys
import dns.resolver
import requests
import json
import re
import subprocess

"""
Resources:
    - 

# find reverse ip lookup

For DNS query:
```
resolver = dns.resolver.Resolver()
resolver.nameserver = ['8.8.8.8']
resolver.resolve('nipg.faradars.org', 'a')

for ip in r: print(ip)
# 185.234.14.117
# 185.112.151.245
```

"""

class IPInfo:
    
    def __init__(self, target):
        self.ip_vhosts = {}
        self.ips , self.queries = self.dns_query(target)
        
        for target in self.ips:
            vhosts = self.find_vhosts(target)
            self.ip_vhosts.update({target: {"vhosts": vhosts}})

        # print(json.dumps(self.ip_vhosts, indent=4))
        # print(json.dumps(self.queries, indent=4))


    def new_dns_query(self, target):
        url = f"https://networkcalc.com/api/dns/lookup/{target}"
        res = requests.get(url).text
        res = json.loads(res)
        ips = []

        for a_rec in res["records"]["A"]:
            ips.append( a_rec["address"] )

        return ips, res


    # ["a", "aaaa", "cname", "ptr", "ns", "mx", "soa", "txt"]
    def dns_query(self, target, query_types=["A", "AAAA", "CNAME", "NS", "MX", "SOA", "TXT"]):
        ips = []
        queries = {}

        resolver = dns.resolver.Resolver()
        resolver.namespace = ["1.1.1.1", "8.8.8.8"]
        
        for q_type in query_types:
            try:
                result = resolver.resolve(target, q_type)
            except:
                result = False

            if result:
                l = []
                for i in result.rrset:
                    data = re.sub("\.$", "", str(i).replace('"', '') )
                    data = data.split(' ')[1] if q_type.lower() == "mx" else data
                    l.append(data)
                
                if q_type.lower() == "a":  ips = l
                queries.update( { q_type: l } )

        # print(ips)
        # print(queries)
        return ips, queries
    

    def find_vhosts(self, ip, mask=31):
        """
            Recommended bash script:
            #! /bin/bash

            curl -s "https://rapiddns.io/sameip/__IP__?full=1" |
            grep "<td>" |
            sed -E "s/<(\/)?td>/\n/g" |
            tr '<>' '\n' |
            sed -E '/^$/d' |
            grep -v "href=" |
            grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" -B1 |
            grep -vE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"  |
            grep -iE "^[0-9a-z]" |
            sed -E "s/,$//g"
        """
        cmd = r"""
        curl -s "https://rapiddns.io/sameip/__IP__?full=1" |
            grep "<td>" |
            sed -E "s/<(\/)?td>/\n/g" |
            tr '<>' '\n' |
            sed -E '/^$/d' |
            grep -v "href=" |
            grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" -B1 |
            grep -vE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"  |
            grep -iE "^[0-9a-z]" |
            sed -E "s/,$//g"
        """.replace("__IP__", ip)

        subs = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode('utf-8').split()
        return subs


        # url = f"https://sonar.omnisint.io/reverse/{ip}/{mask}"
        # res = requests.get(url)
        # if str(res.status_code) == "200": return res
        # else: return b'{}'


    @staticmethod
    def dns_dumpster(target):
    # def dns_dumpster(self, target):
        url = 'https://dnsdumpster.com'
        res = requests.get(url, verify=False)
        # print(res.text)
        csrfmiddlewaretoken = re.search('csrfmiddlewaretoken.*value=".*"', res.text).group().split('"')[-2]

        headers = {
            'Cookie': f"csrftoken={res.cookies.get('csrftoken')}",
            'Referer': url
        }
        data = {
            'csrfmiddlewaretoken':csrfmiddlewaretoken,
            'targetip': target,
            'user': 'free'
        }
        res = requests.post(url, headers=headers, data=data, verify=False)
        # print(res.request)
        # print(res.request.headers)
        # print(res.text)

        domain = re.sub('http(s)?:\/\/', '', target).replace('/', '')
        map_png_url = f'https://dnsdumpster.com/static/map/{domain}.png'
        xlsx_url = url + re.search('href=".*xlsx"', res.text).group().split('"')[-2]

        print(map_png_url)
        print(xlsx_url)


    
    @property
    def get_ips(self): return self.ips

    @property
    def get_queries(self): return self.queries

    @property
    def get_ip_vhosts(self): return self.ip_vhosts


def main():
    # ip = sys.argv[1]
    # IPInfo(ip)

    ip = sys.argv[1]
    IPInfo.dns_dumpster(ip)



if __name__ == "__main__":
    main()