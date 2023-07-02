#! /usr/bin/python3

import requests
import json
import logging
import helper
import re
import os, sys, stat, shutil
from config import *

"""
    - Install subfinder
    - Install amass
    - Install gobuster
    - Install gau
"""

logging.basicConfig(format="%(message)s", level=logging.INFO)

TOOLS_DIR = "/tmp/tools" if os.path.exists("/tmp/tools") else os.makedirs("/tmp/tools")
TEMP_TOOLS_DIR = f'{TOOLS_DIR}/temp'


tools_releases = {
    "subfinder": {
        "url": "https://api.github.com/repos/projectdiscovery/subfinder/releases/latest",
        "prev_dir": f"{TEMP_TOOLS_DIR}/subfinder",
        },
    "amass": {
        "url": "https://api.github.com/repos/OWASP/Amass/releases/latest",
        "prev_dir": f"{TEMP_TOOLS_DIR}/amass_Linux_amd64/amass",
    },
    "gobuster": {
        "url": "https://api.github.com/repos/OJ/gobuster/releases/latest",
        "prev_dir": f"{TEMP_TOOLS_DIR}/gobuster",
    },
    "gau": {
        "url": "https://api.github.com/repos/lc/gau/releases/latest",
        "prev_dir": ""f"{TEMP_TOOLS_DIR}/gau",
    },
}

def install_tools():
    tools_url = []

    check_tools_installation()

    try:
        os.makedirs(TEMP_TOOLS_DIR, exist_ok=True)
    except:
        logging.error( helper.get_colored('[!]', 'r') + f" Creating directory {TEMP_TOOLS_DIR} failed" )
        sys.exit(-1)

    # Fetch downloadable URL
    assets = []
    for tool_name, tool_detail in tools_releases.items():
        url = tool_detail["url"]
        try:
            headers = {'Accept': 'application/vnd.github+json'}
            res = requests.get(url, headers=headers)
            logging.info(f"{ helper.get_colored('[+]', 'g')} Requested for {tool_name} (Status: {res.status_code}, url: {url})")
            assets = json.loads(res.text)['assets']
        except Exception as e:
            logging.warning(f"{ helper.get_colored('[!]', 'r') } Exception: {e}")

        
        # Fetch downloadable URL
        for a in assets:
            if re.search('linux(_|-)(amd64|x86_64)\.(zip|7z|tar|tgz)(\.gz)?', a['name'].lower()):
                tools_url.append(a['browser_download_url'])
                break


    # Download tools and extract them into the tools directory
    for url in tools_url:
        res = requests.get(url)
        logging.info(f"{ helper.get_colored('[+]', 'g')} Requested {url} (Status: {res.status_code})")
        tool_path = TEMP_TOOLS_DIR + '/' + url.rsplit('/', maxsplit=1)[-1]
        helper.write_archive_file(res.content, tool_path)
        helper.unarchive_file(tool_path)

    # Move each tools into the tools directory 
    for tool_name, tool_detail in tools_releases.items():
        os.chmod( tool_detail["prev_dir"], stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR )
        shutil.move(tool_detail["prev_dir"], TOOLS_DIR)

    shutil.rmtree(TEMP_TOOLS_DIR)


def check_tools_installation():
    try:
        existed_tools = list(os.listdir(TOOLS_DIR))
        tools_name = tools_releases.copy().keys()
        for name in tools_name:
            if name in existed_tools:
                tools_releases.pop(name)
                logging.info(f"{ helper.get_colored('[.]', 'c') } {name} tool has been found.")
    except Exception as e:
        logging.error(f"{ helper.get_colored('[!]', 'r') } Check installed tools exception: {e}")


def main():
    install_tools()
    # check_tools_installation()


if __name__ == "__main__":
    main()
