#! /bin/python3
import os

#TOOLS_DIR = "/opt/tools" if os.path.exists("/opt/tools") else os.makedirs("/opt/tools")
TOOLS_DIR = "/tmp/tools" if os.path.exists("/tmp/tools") else os.makedirs("/tmp/tools")
PROJ_DIR = os.path.dirname(os.getcwd())
