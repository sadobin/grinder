#! /bin/python3

from colorama import Fore
import logging
import pyunpack
import os, sys, subprocess
import functools
import re

from config import *
import helper

logging.basicConfig(format="%(message)s", level=logging.INFO)

def get_colored(text, color):
    c = color.lower()
    if   c in ["red", "r"]:     return Fore.RED + text + Fore.RESET
    elif c in ["blue", "b"]:    return Fore.BLUE + text + Fore.RESET
    elif c in ["green", "g"]:   return Fore.GREEN + text + Fore.RESET
    elif c in ["cyan", "c"]:    return Fore.CYAN + text + Fore.RESET
    elif c in ["magenta", "m"]: return Fore.MAGENTA + text + Fore.RESET
    elif c in ["yellow", "y"]:  return Fore.YELLOW + text + Fore.RESET


def write_archive_file(data, path):
    with open(path, 'wb') as f:
        logging.info(f"{ get_colored('[.]', 'y') } Writing data to {path}")
        f.write(data)
        return True


def unarchive_file(path):
    # with zipfile.ZipFile(path, 'r') as zip:
    try:
        dir = path.rsplit('/', maxsplit=1)[0]
        pyunpack.Archive(path).extractall(dir)
        logging.info(f"{ get_colored('[.]', 'y') } Unarchiving archive file to {dir}")
    
    except Exception as e:
        logging.warning(f"{ get_colored('[!]', 'r') } Exception: {e}")


def check_neccessary_params(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        params = ['cmd', 'target']
        for key in kwargs.keys():
            if key in params and not kwargs.get(key):
                raise Exception(f"{helper.get_colored('[!]','r')} Exception: {key} parameter must not be empty")
        return f(*args, **kwargs)
    return wrapper


@check_neccessary_params
def execute_tool(*args, **kwargs):
# def execute_tool(name, cmd, target, **kwargs):
    try:
        name = kwargs.get("name") if kwargs.get("name") else ""
        cmd = kwargs.get("cmd") if kwargs.get("cmd") else ""
        target = kwargs.get("target") if kwargs.get("target") else ""
        tmp_output = kwargs.get("tmp_output") if kwargs.get("tmp_output") else ""
        wordlist = kwargs.get("wordlist") if kwargs.get("wordlist") else ""
        
        if "rapiddns" not in name:
            cmd = cmd.format(target=target, tmp_output=tmp_output, wordlist=wordlist)   # formatting command
        main_cmd = cmd.split(' &&')[0].replace('./', '')
        cmd =  f"cd {TOOLS_DIR} && " + cmd
        
        logging.info(f"{ helper.get_colored('[+]', 'g') } Running command '{main_cmd}'")
        
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode('utf-8').replace("Found: ", "").split()
        logging.info(f"{ helper.get_colored('[.]', 'y') } Running '{name}' is completed")
        # print(f"####### {main_cmd} ##########")
        # print(result)
        # print("#################")
        return result
    except Exception as e:
        logging.warning(f"{ helper.get_colored('[!]', 'r') } Running '{name}' error: {e}")


def tool_existence(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        tool_path = kwargs.get('tool_path')

        if not os.path.exists(tool_path):
            raise Exception(f"{get_colored('[!]', 'r') } Tool {tool_path} not found")
        # os.chmod(tool_path, stat.S_)
        return f(*args, **kwargs)
    return wrapper