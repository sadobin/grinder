#! /usr/bin/python3

from collections import Counter
import random
import logging
from concurrent.futures.process import ProcessPoolExecutor
import subprocess
import requests
import time
import argparse
import sys
import re
import json
import os, shutil
sys.path.append( f"{os.path.dirname(__file__)}/.." )

import helper
from config import *


"""
    Ability:
        - Get list of domains 

    # Resources:
        + https://tls.bufferover.run/dns/?q=
        + https://crt.sh/?output=json&q=
        + https://chaos-data.projectdiscovery.io/{TARGET}.zip'
        - https://api.certspotter.com/v1/issuances?domain={TARGET}&include_subdomains=true&expand=dns_names&expand=cert
        - https://api.threatminer.org/v2/index.php
        - https://sonar.omnisint.io/subdomains/zarebin.ir

        tools:
            + gobuster
            + subfinder
            + amass
"""


SUBDOMAINS = []
IP = {}


class Subdomain:

    def __init__(self, target, **kwargs):
        logging.basicConfig(format="%(message)s", level=logging.INFO)

        # self.check_constructor_params(kwargs)
        self._opts = kwargs
        self.subdomains = {}
        
        # self.target = target
        self._sources = {
                    "urls": [
                        # self.bufferoverrun, 
                        self.crt_sh, 
                        # self.ominisint,
                        # self.projectdiscovery,
                        # self.rapiddns
                    ],
                    "tools": [
                        {
                            "name": "subfinder",
                            "cmd": "./subfinder -all -silent -nc -d {target}",
                            "subfinder_subs": [],
                            "tmp_output": "",
                        },
                        {
                            "name": "amass",
                            "cmd": "./amass enum -silent -d {target} -o {tmp_output} && cat {tmp_output} && rm {tmp_output}",
                            "amass_subs": [],
                            "tmp_output": f"{TOOLS_DIR}/amass.{target}",
                        },
                        # {
                        #     "name": "gobuster",     # brute-force subdomain
                        #     "cmd": "./gobuster dns -d {target} -w {wordlist} -z -q --no-error",
                        #     "gobuster_subs": [],
                        #     "tmp_output": "",
                        #     "wordlist": f"{PROJ_DIR}/wordlists/subs.meduim.txt",
                        # },
                    ]
                }
        
        self.runner(target)
        # print(self.subdomains)


    def check_constructor_params(self, kwargs):
        for k,v in kwargs.items():
            if k == "bruteforce" and v:
                for d in self._sources["tools"]:
                    if d["name"] == "gobuster":
                        pass


    def runner(self, target):
        results = {}

        workers = 8
        # with ProcessPoolExecutor(max_workers=workers) as executor:
        with ProcessPoolExecutor(max_workers=workers) as executor:
            for k,v in self._sources.items():
                if k == "urls":
                    for method in v:
                        e = executor.submit(method, target=target)
                        res = e.result() if not e.result() == None else []
                        # The method name is used for json key
                        name = method.__qualname__.split('.')[1]
                        results.update({ name: res })

                elif k == "tools":
                    for data in v:
                        if data["name"] == "gobuster" and not self._opts.get("bruteforce"): continue

                        e = executor.submit(helper.execute_tool, target=target, **data)
                        res = e.result() if not e.result() == None else []
                        results.update({data['name']: res})

        # self.ip_domain_relation(bufferoverrun_res)
        # self.recursive_and_refiner(target, results, refine=True)    # refiner
        # self.recursive_and_refiner(target)               # recursive check

        # print(json.dumps(results, indent=4))
        self.subdomains =  results


    def bufferoverrun(self, target):

        api_keys = [
            'BmxmnugMjy4uT9EaMVVoM1hGlFMQZVyj5GgkBznb', # fehej45650@seinfaq.com
            'vdhECNcdhW41TDPo6qmRvcOrgvxdovt8KXqQH5sf', # ponay57265@otodir.com
            '8ectV0KDUJa7D0JJiCREiT5DFY8Hp3y2ncVTPLAg', # jofihit265@lurenwu.com
            '6TaXNAK8CP207AIjRXTrf4q1r8WMizRa1XueufM4', # panav14359@rxcay.com
            'gm2StOWPLz4YZjrKudqIk8PQ2Ecl4FEa9bwoP7RN', # sohawep941@xitudy.com
        ]

        url = f"http://tls.bufferover.run/dns?q=.{target}"
        x_api_key = random.choise(api_keys)
        headers = {'x-api-key': x_api_key}
        res = requests.get(url, headers=headers).text
        logging.info(f"{ helper.get_colored('[+]', 'g') } Request to {url} (x-api-key: {x_api_key}) (status: {res.status_code})")

        res = json.loads(res)
        return  res['FDNS_A'] + \
                res['RDNS'] if res['RDNS'] else []


    def ip_domain_relation(self, bufferoverrun_res):
        for pair in bufferoverrun_res:
            ip, sub = pair.split(',')
            if re.match('^[0-9]+', ip):
                if ip not in IP:
                    IP.update( {ip: [sub]} )
                IP.get(ip).append(sub) if sub not in IP.get(ip) else []
            else:
                continue
            self.bufferoverrun_subs.append(sub)


    def rapiddns(self, target):
        cmd = """
            curl -s "https://rapiddns.io/s/__TARGET__?full=1" | \
            grep "<td>" | \
            sed -E "s/<(\/)?td>/\n/g" | \
            tr '<>' '\n' | \
            sed -E '/^$/d' | \
            grep -v "href=" | \
            grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" -B1 | \            
            grep -iE "__TARGET__" | \
            sed -E "s/(,|\.)$//g" | \
            sort -u 
        """.replace("__TARGET__", target)
        
        data = {
            "name": "rapiddns",
            "cmd": cmd,
            }
        
        urls = helper.execute_tool(target=target, **data)
        return list(Counter(urls).keys())


    def crt_sh(self, target):
        url = f"https://crt.sh/?q={target}&output=json"
        res = requests.get(url)
        status = str(res.status_code)

        count = 5
        while status != "200" and count > 0:
            try:
                res = requests.get(url)
                status = res.status_code
                count -= 1
                time.sleep(1)
            except Exception as e:
                print(e)

        logging.info(f"{ helper.get_colored('[+]', 'g') } Request to {url} (status: {res.status_code})")
        logging.info(f"{ helper.get_colored('[.]', 'c') } Parsing and appending 'crt.sh' output to the results")

        res = re.sub("(-|\"|\\\\n)", '\n', res.text.lower())
        subs = re.findall(f'.*\.{target}', res)
        subs = list(Counter(subs).keys())     # Uniq list

        return subs


    def recursive_and_refiner(self, target, subdomains, refine=False):
        tested = []
        subs = subdomains.copy()
        tested.append(target)

        for sub in subs:
            if sub.startswith('*.'):
                subs.remove(sub)
                sub = sub.replace('*.', '')
                subs.append(sub)

                if not tested.count(sub) and not refine: # sould be re-implemented (crt, bufferover, crobat)
                    tested.append(sub)
                    # subs = self.crt_sh(sub, recheck=True)
                    subs = self.crt_sh(sub)
                    if len(subs): subs.insert(-1, (s for s in subs) )
        
        return subs


    def projectdiscovery(self, target):
        target = target.rsplit('.', maxsplit=1)[0]
        url = f'https://chaos-data.projectdiscovery.io/{target}.zip'
        res = requests.get(url)

        logging.info(f"{ helper.get_colored('[+]', 'g') } Request to {url} (status: {res.status_code})")

        if res.status_code == '200':
            dir = f'/tmp/gath/{target}'
            path = f'{dir}/{target}.zip'
            logging.debug(f"{ helper.get_colored('[.]', 'y') } Creating {dir} directory")
            os.mkdir(dir)
            
            helper.write_zip_file(res.content, path)
            helper.unzip_file(path)

            logging.info(f"{ helper.get_colored('[.]', 'c') } Parsing and appending 'projectdiscovery' output to the results")

            subs = subprocess.check_output(f'cat {dir}/*{target}*', stderr=subprocess.STDOUT, shell=True).split()

            logging.debug(f"{ helper.get_colored('[.]', 'y') } Removing {dir} directory")
            os.rmdir(dir)

            return subs


    def ominisint(self, target):
        try:
            url = f'https://sonar.omnisint.io/subdomains/{target}'
            res = requests.get(url)
            logging.info(f"{ helper.get_colored('[+]', 'g') } Request to {url} (status: {res.status_code})")

            if res.status_code == 200:
                subs = json.loads(res.text)
                logging.info(f"{ helper.get_colored('[.]', 'c') } Appending the 'Omnisint' output to the results")
                return subs
        except Exception as e:
            logging.warning(f"{ helper.get_colored('[!]', 'r') } Exception: {e}")


    @property
    def get_subdomains(self): return self.subdomains



if __name__ == "__main__":
    try:
        target = sys.argv[1]
        SUBDOMAINS = Subdomain(target, bruteforce=False)
        # SUBDOMAINS = Subdomain(target).get_subdomains
        # SUBDOMAINS = list(Counter(SUBDOMAINS).keys())   # Uniqe list
        # print( json.dumps(SUBDOMAINS, indent=4) )
    except Exception as e:
        logging.error(f"{ helper.get_colored('[!]', 'r') } Exception: {e}")
