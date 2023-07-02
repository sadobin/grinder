#! /bin/python3

import sys, os
import requests
import json
import logging
import re
from urllib.parse import urlparse
from collections import Counter
from itertools import chain
sys.path.append( f"{os.path.dirname(__file__)}/.." )

from .subdomains import Subdomain
from ip.ip_info import IPInfo 
import helper
from config import *


class Domain:

    def __init__(self, target):
        pass

        """
        self._recon = {}

        subs_obj = Subdomain(target, bruteforce=False)
        subs = subs_obj.get_subdomains
        ### Get all sources results
        subs = list(chain(*subs.values()))
        ### Refine result
        # subs = subs_obj.recursive_and_refiner(target, subs)
        #### make result unique
        subs = list(Counter(subs).keys())  
        self._recon.update({"subdomains": subs})
        # print(json.dumps(subs, indent=4))

        ### IP information
        ipinfo = IPInfo(target)
        self._recon.update({"DNS": ipinfo.get_queries})
        self._recon.update({"IPs": ipinfo.get_ip_vhosts})

        ### Find and update TLDs
        # self.tlds = self.get_tlds(target)
        # self._recon.update({"tlds": self.tlds})

        ### Find and update known URLs
        self.known_urls = self.get_known_urls(target)
        self._recon.update({"known-urls": self.known_urls})
        
        # print(self._recon)
        print(json.dumps(self._recon, indent=4))
        """

    # Service unavailable
    def get_tlds(self, target):
        url = f"https://sonar.omnisint.io/tlds/{target}"
        res = requests.get(url)
        logging.info(f"{ helper.get_colored('[+]', 'g') } Request to {url} (status: {res.status_code})")
        
        if res.text and res.status_code == 200:
            logging.info(f"{ helper.get_colored('[.]', 'c') } Parsing and appending 'tlds' output to the results")
            return json.loads(res.text)
        return {}


    # @staticmethod
    # def get_known_urls(target):
    def get_known_urls(self, target):
        data = {
            "name": "gau",
            "cmd": "./gau --providers wayback,commoncrawl,otx,urlscan --subs {target} --o {tmp_output} && cat {tmp_output} && rm {tmp_output}",
            "amass_subs": [],
            "tmp_output": f"{TOOLS_DIR}/gau.{target}",
            }
        urls = helper.execute_tool(target=target, **data)
        subs = list( re.sub(':80$', '', urlparse(domain).netloc) for domain in urls )
        return list(Counter(urls).keys()), subs


def main():
    target = sys.argv[1]
    Domain.get_known_urls(target)


if __name__ == "__main__":
    main()