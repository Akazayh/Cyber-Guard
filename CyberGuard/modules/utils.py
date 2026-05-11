#!/usr/bin/env python3

import subprocess
import ipaddress
import re
from pathlib import Path

def run_command_safe(cmd, timeout=30):
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout"
    except Exception as e:
        return -1, "", str(e)

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_ip_network(network):
    try:
        ipaddress.ip_network(network, strict=False)
        return True
    except ValueError:
        return False

def validate_port(port):
    try:
        p = int(port)
        return 1 <= p <= 65535
    except ValueError:
        return False

def validate_filename(name):
    if not name or len(name) > 100:
        return False
    if re.search(r'[\\/:\*\?"<>\|]|\.\.', name):
        return False
    return True
def validate_protocol(protocol):
    return protocol.lower() in ['tcp', 'udp', 'icmp']

def ensure_directories():
    for d in ['Detected_Attack', 'Archives_IDS', 'Archives_Nmap']:
        Path(d).mkdir(exist_ok=True)
