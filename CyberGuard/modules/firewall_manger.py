from utils import run_command_safe, validate_ip, validate_port, validate_protocol
import os
import sys
import time
import subprocess
from colorama import Fore, Style, init
import logging
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

init(autoreset=True)
logging.basicConfig(filename='ids_tool.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
os.system("clear")

def block_ip():
    print(Fore.YELLOW + "[1] - Block IP")
    print(Fore.YELLOW + "[2] - Unblock IP")
    print(Fore.YELLOW + "[3] - List Blocked IPs")
    print(Fore.YELLOW + "[4] - Back to Main Menu")
    choice = input(Fore.WHITE + "Enter your choice (1-4): ")
    if choice == "1":
        ip = input(Fore.RED + "Enter IP to block: ").strip()
        if block_ip_implementation(ip, "block"):
            print(Fore.GREEN + f"Successfully blocked IP: {ip}")
        else:
            print(Fore.RED + f"Failed to block IP: {ip}")
        input(Fore.YELLOW + "Press Enter to continue...")
    elif choice == "2":
        ip = input(Fore.GREEN + "Enter IP to unblock: ").strip()
        if block_ip_implementation(ip, "unblock"):
            print(Fore.GREEN + f"Successfully unblocked IP: {ip}")
        else:
            print(Fore.RED + f"Failed to unblock IP: {ip}")
        input(Fore.YELLOW + "Press Enter to continue...")
    elif choice == "3":
        list_blocked_ips()
        input(Fore.YELLOW + "Press Enter to continue...")
    elif choice == "4":
        return
    else:
        print(Fore.RED + "Invalid choice!")
        time.sleep(1)

def block_port():
    print(Fore.YELLOW + "[1] - Block Port")
    print(Fore.YELLOW + "[2] - Unblock Port")
    print(Fore.YELLOW + "[3] - Block Port Range")
    print(Fore.YELLOW + "[4] - List Blocked Ports")
    print(Fore.YELLOW + "[5] - Back to Main Menu")
    choice = input(Fore.WHITE + "Enter your choice (1-5): ")
    if choice == "1":
        port = input(Fore.RED + "Enter port to block: ").strip()
        protocol = input(Fore.BLUE + "Enter protocol (tcp/udp) [default: tcp]: ").strip().lower()
        if not protocol:
            protocol = "tcp"
        if block_port_implementation(port, protocol, "block"):
            print(Fore.GREEN + f"Successfully blocked port: {port}/{protocol.upper()}")
        else:
            print(Fore.RED + f"Failed to block port: {port}/{protocol.upper()}")
        input(Fore.YELLOW + "Press Enter to continue...")
    elif choice == "2":
        port = input(Fore.GREEN + "Enter port to unblock: ").strip()
        protocol = input(Fore.BLUE + "Enter protocol (tcp/udp) [default: tcp]: ").strip().lower()
        if not protocol:
            protocol = "tcp"
        if block_port_implementation(port, protocol, "unblock"):
            print(Fore.GREEN + f"Successfully unblocked port: {port}/{protocol.upper()}")
        else:
            print(Fore.RED + f"Failed to unblock port: {port}/{protocol.upper()}")
        input(Fore.YELLOW + "Press Enter to continue...")
    elif choice == "3":
        start_port = input(Fore.RED + "Enter start port: ").strip()
        end_port = input(Fore.RED + "Enter end port: ").strip()
        protocol = input(Fore.BLUE + "Enter protocol (tcp/udp) [default: tcp]: ").strip().lower()
        if not protocol:
            protocol = "tcp"
        if block_port_range_implementation(start_port, end_port, protocol, "block"):
            print(Fore.GREEN + f"Successfully blocked port range: {start_port}-{end_port}/{protocol.upper()}")
        else:
            print(Fore.RED + f"Failed to block port range: {start_port}-{end_port}/{protocol.upper()}")
        input(Fore.YELLOW + "Press Enter to continue...")
    elif choice == "4":
        list_blocked_ports()
        input(Fore.YELLOW + "Press Enter to continue...")
    elif choice == "5":
        return
    else:
        print(Fore.RED + "Invalid choice!")
        time.sleep(1)

def block_protocol():
    print(Fore.YELLOW + "[1] - Block Protocol")
    print(Fore.YELLOW + "[2] - Unblock Protocol")
    print(Fore.YELLOW + "[3] - Back to Main Menu")
    choice = input(Fore.WHITE + "Enter your choice (1-3): ")
    if choice == "1":
        protocol = input(Fore.RED + "Enter protocol to block (tcp/udp/icmp): ").strip().lower()
        if block_protocol_implementation(protocol, "block"):
            print(Fore.GREEN + f"Successfully blocked protocol: {protocol.upper()}")
        else:
            print(Fore.RED + f"Failed to block protocol: {protocol.upper()}")
        input(Fore.YELLOW + "Press Enter to continue...")
    elif choice == "2":
        protocol = input(Fore.GREEN + "Enter protocol to unblock (tcp/udp/icmp): ").strip().lower()
        if block_protocol_implementation(protocol, "unblock"):
            print(Fore.GREEN + f"Successfully unblocked protocol: {protocol.upper()}")
        else:
            print(Fore.RED + f"Failed to unblock protocol: {protocol.upper()}")
        input(Fore.YELLOW + "Press Enter to continue...")
    elif choice == "3":
        return
    else:
        print(Fore.RED + "Invalid choice!")
        time.sleep(1)

def block_ip_implementation(ip, action):
    if not validate_ip(ip):
        print(Fore.RED + "Invalid IP")
        return False
    if action == "block":
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    else:
        cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
    ret, _, stderr = run_command_safe(cmd)
    if ret != 0:
        print(Fore.RED + f"iptables error: {stderr}")
    return ret == 0

def block_port_implementation(port, protocol, action):
    if not validate_port(port) or not validate_protocol(protocol):
        print(Fore.RED + "Invalid port or protocol")
        return False
    if action == "block":
        cmd = ["sudo", "iptables", "-A", "INPUT", "-p", protocol, "--dport", str(port), "-j", "DROP"]
    else:
        cmd = ["sudo", "iptables", "-D", "INPUT", "-p", protocol, "--dport", str(port), "-j", "DROP"]
    ret, _, stderr = run_command_safe(cmd)
    if ret != 0:
        print(Fore.RED + f"iptables error: {stderr}")
    return ret == 0

def block_port_range_implementation(start_port, end_port, protocol, action):
    if not (validate_port(start_port) and validate_port(end_port)):
        print(Fore.RED + "Invalid port range")
        return False
    if action == "block":
        cmd = ["sudo", "iptables", "-A", "INPUT", "-p", protocol, "--dport", f"{start_port}:{end_port}", "-j", "DROP"]
    else:
        cmd = ["sudo", "iptables", "-D", "INPUT", "-p", protocol, "--dport", f"{start_port}:{end_port}", "-j", "DROP"]
    ret, _, stderr = run_command_safe(cmd)
    if ret != 0:
        print(Fore.RED + f"iptables error: {stderr}")
    return ret == 0

def block_protocol_implementation(protocol, action):
    if not validate_protocol(protocol):
        print(Fore.RED + "Invalid protocol")
        return False
    if action == "block":
        cmd = ["sudo", "iptables", "-A", "INPUT", "-p", protocol, "-j", "DROP"]
    else:
        cmd = ["sudo", "iptables", "-D", "INPUT", "-p", protocol, "-j", "DROP"]
    ret, _, stderr = run_command_safe(cmd)
    if ret != 0:
        print(Fore.RED + f"iptables error: {stderr}")
    return ret == 0

def list_blocked_ips():
    ret, stdout, _ = run_command_safe(["sudo", "iptables", "-L", "INPUT", "-n"])
    if ret == 0:
        for line in stdout.split('\n'):
            if 'DROP' in line:
                print(Fore.YELLOW + line)
    else:
        print(Fore.RED + "Error listing rules")

def list_blocked_ports():
    ret, stdout, _ = run_command_safe(["sudo", "iptables", "-L", "INPUT", "-n"])
    if ret == 0:
        for line in stdout.split('\n'):
            if 'dpt:' in line.lower():
                print(Fore.YELLOW + line)
    else:
        print(Fore.RED + "Error listing rules")

logo =(Fore.YELLOW + r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣆⢳⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣾⣷⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠠⣄⠀⢠⣿⣿⣿⣿⡎⢻⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢸⣧⢸⣿⣿⣿⣿⡇⠀⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣾⣿⣿⣿⣿⠃⠀⢸⣿⣿⣿⣿⣿⣿⠀⣄⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⠏⠀⠀⣸⣿⣿⣿⣿⣿⡿⢀⣿⡆⠀
⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⣿⣿⣿⣿⣿⣿⠇⣼⣿⣿⡄
⠀⢰⠀⠀⣴⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⢠⣿⣿⣿⣿⣿⡟⣼⣿⣿⣿⣧
⠀⣿⡀⢸⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⣸⡿⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿
⠀⣿⣷⣼⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⢹⠃⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿
⡄⢻⣿⣿⣿⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⠇
⢳⣌⢿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣿⣿⣿⣿⠏⠀
⠀⢿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⠋⣠⠀
⠀⠈⢻⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣵⣿⠃⠀
⠀⠀⠀⠙⢿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⡿⠃⠀⠀
⠀⠀⠀⠀⠀⠙⢿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⡿⠋⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠛⠿⣿⣦⣀⠀⠀⠀⠀⢀⣴⠿⠛⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠓⠂⠀⠈⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""+ Style.RESET_ALL)
def show_logo():
    for line in logo.split("\n"):
        print(Fore.YELLOW+ line)
        time.sleep(0.15)
    time.sleep(1.5)  
    os.system('clear')
show_logo()
def banner():
	print(Fore.YELLOW + Style.BRIGHT +  r"""
  █████▒██▓ ██▀███  ▓█████     █     █░ ▄▄▄       ██▓     ██▓        ███▄ ▄███▓ ▄▄▄       ███▄    █  ▄▄▄        ▄████ ▓█████  ██▀███  
▓██   ▒▓██▒▓██ ▒ ██▒▓█   ▀    ▓█░ █ ░█░▒████▄    ▓██▒    ▓██▒       ▓██▒▀█▀ ██▒▒████▄     ██ ▀█   █ ▒████▄     ██▒ ▀█▒▓█   ▀ ▓██ ▒ ██▒
▒████ ░▒██▒▓██ ░▄█ ▒▒███      ▒█░ █ ░█ ▒██  ▀█▄  ▒██░    ▒██░       ▓██    ▓██░▒██  ▀█▄  ▓██  ▀█ ██▒▒██  ▀█▄  ▒██░▄▄▄░▒███   ▓██ ░▄█ ▒
░▓█▒  ░░██░▒██▀▀█▄  ▒▓█  ▄    ░█░ █ ░█ ░██▄▄▄▄██ ▒██░    ▒██░       ▒██    ▒██ ░██▄▄▄▄██ ▓██▒  ▐▌██▒░██▄▄▄▄██ ░▓█  ██▓▒▓█  ▄ ▒██▀▀█▄  
░▒█░   ░██░░██▓ ▒██▒░▒████▒   ░░██▒██▓  ▓█   ▓██▒░██████▒░██████▒   ▒██▒   ░██▒ ▓█   ▓██▒▒██░   ▓██░ ▓█   ▓██▒░▒▓███▀▒░▒████▒░██▓ ▒██▒
 ▒ ░   ░▓  ░ ▒▓ ░▒▓░░░ ▒░ ░   ░ ▓░▒ ▒   ▒▒   ▓▒█░░ ▒░▓  ░░ ▒░▓  ░   ░ ▒░   ░  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒  ▒▒   ▓▒█░ ░▒   ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░
 ░      ▒ ░  ░▒ ░ ▒░ ░ ░  ░     ▒ ░ ░    ▒   ▒▒ ░░ ░ ▒  ░░ ░ ▒  ░   ░  ░      ░  ▒   ▒▒ ░░ ░░   ░ ▒░  ▒   ▒▒ ░  ░   ░  ░ ░  ░  ░▒ ░ ▒░
 ░ ░    ▒ ░  ░░   ░    ░        ░   ░    ░   ▒     ░ ░     ░ ░      ░      ░     ░   ▒      ░   ░ ░   ░   ▒   ░ ░   ░    ░     ░░   ░ 
        ░     ░        ░  ░       ░          ░  ░    ░  ░    ░  ░          ░         ░  ░         ░       ░  ░      ░    ░  ░   ░     


[1] - Allow or block specific IP addresses						   

[2] - Allow or block specific ports

[3] - Allow or block specific protocols (such as TCP, UDP, ICMP)

[99] - Help

[0] - Exit

""" + Style.RESET_ALL)
while True:
	os.system("clear")
	banner()
	choice=input(Fore.YELLOW + Style.BRIGHT + "Enter your choice==========> :" + Style.RESET_ALL)
	if choice == "1":
		block_ip()
	elif choice == "2":
		block_port()
	elif choice == "3":
		block_protocol()
	elif choice=="99":
		print(Fore.YELLOW + Style.BRIGHT + """
╔══════════════════════════════════════════════════════════════════╗
║                   HELP - FIREWALL MANAGER                        ║
╠══════════════════════════════════════════════════════════════════╣
║ [1] Allow or block specific IP addresses                         ║
║     ➤ Block/Unblock individual IPs                              ║
║     ➤ List currently blocked IPs                                ║
║     ➤ Uses iptables for implementation                          ║
║                                                                  ║
║ [2] Allow or block specific ports                                ║
║     ➤ Block/Unblock individual ports                            ║
║     ➤ Block/Unblock port ranges                                 ║
║     ➤ Support for TCP/UDP protocols                             ║
║     ➤ List currently blocked ports                              ║
║                                                                  ║
║ [3] Allow or block specific protocols                            ║
║     ➤ Block/Unblock entire protocols                            ║
║     ➤ Supported: TCP, UDP, ICMP                                 ║
║                                                                  ║
║ [0] Exit                                                         ║
║     ➤ Exit with option to save rules                            ║
║                                                                  ║
║ IMPORTANT NOTES:                                                 ║
║ • Requires sudo privileges                                       ║
║ • Changes are temporary unless saved                             ║
║ • Saving rules persists after reboot                             ║
║ • Use carefully to avoid locking yourself out                    ║
╚══════════════════════════════════════════════════════════════════╝
""" + Style.RESET_ALL)
		input(Fore.YELLOW + "\nPress Enter to continue..." + Style.RESET_ALL)
	elif choice == "0":
		save=input(Fore.YELLOW + Style.BRIGHT + "Do you want to save the rules (y=yes/n=non)  :" + Style.RESET_ALL).strip().lower()
		if save=="y":
			run_command_safe("sudo iptables-save | sudo tee /etc/iptables/rules.v4", shell=True)
			time.sleep(10)
		print(Fore.YELLOW + "Thank you for using Kali Linux Firewall Manager! Goodbye!")
		break
	else:
		print(Fore.RED + " Invalid choice! Please try again.")
		time.sleep(1)
