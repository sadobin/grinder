#! /bin/python3

from multiprocessing import Process
from threading import Thread
from collections import Counter
from itertools import chain
import json
import sys, os
sys.path.append( os.path.dirname(os.path.abspath(__file__)) )

from domain.subdomains import Subdomain
from domain.domain import Domain
from ip.ip_info import IPInfo


class Grinder:

    def __init__(self, target):
        
        self._recon = {}  
        self.domain_result = []
        self.subdomain_result = []
        self.ipinfo_result = {}

        METHODS = [
            self.ipinfo_executer(target, self._recon),
            self.domain_executer(target, self._recon),
            self.subdomain_executer(target, self._recon),
        ]
       

        procs = []

        for method in METHODS:
            p = Process(target=method)
            procs.append(p)
            p.start()
        
        for p in procs: p.join()
        
        # print(json.dumps(self.domain_result, indent=4))
        # print(json.dumps(self.subdomain_result, indent=4))
        print(json.dumps(self._recon, indent=4))



    def domain_executer(self, target, _recon):
        """
            Domain Module
        """
        domain = Domain(target)
        ## Find and update TLDs
        # self.tlds = self.get_tlds(target)
        # self._recon.update({"tlds": self.tlds})
        
        ## Find and update known URLs (with domain which are found from gau)
        known_urls, subs = domain.get_known_urls(target)        
        _recon.update({"subdomains": subs})
        _recon.update({"known-urls": known_urls})


    def subdomain_executer(self, target, _recon):
        """
            Subdomain Module
        """
        subs_obj = Subdomain(target, bruteforce=False)
        subs = subs_obj.get_subdomains
        ## Get all sources results
        subs = list(chain(*subs.values()))
        subs += _recon.get('subdomains')
        ## Refine result
        # subs = subs_obj.recursive_and_refiner(target, subs)
        ## make result unique
        subs = list(Counter(subs).keys())  
        _recon.update({"subdomains": subs})
        # print(json.dumps(subs, indent=4))
        

    def ipinfo_executer(self, target, _recon):
        """
            IPInfo Module
        """
        ### IP information
        ipinfo = IPInfo(target)
        dns = {"DNS": ipinfo.get_queries}
        ip =  {"IPs": ipinfo.get_ip_vhosts}
        # self.ipinfo_result.update({"DNS": ipinfo.get_queries},{"IPs": ipinfo.get_ip_vhosts})
        # return ({"DNS": ipinfo.get_queries},{"IPs": ipinfo.get_ip_vhosts})
        _recon.update(dns)
        _recon.update(ip)
        



def main():
    target = sys.argv[1]
    Grinder(target)


if __name__ == "__main__":
    main()


