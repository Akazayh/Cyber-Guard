import os
import sys
import time
import subprocess
from colorama import Fore, Style, init
init(autoreset=True)
import ipaddress
os.system("clear")
logo =Fore.BLUE  + Style.BRIGHT + r"""
				                                                                                                            
                                                                                                            
NNNNNNNN        NNNNNNNNMMMMMMMM               MMMMMMMM               AAA               PPPPPPPPPPPPPPPPP   
N:::::::N       N::::::NM:::::::M             M:::::::M              A:::A              P::::::::::::::::P  
N::::::::N      N::::::NM::::::::M           M::::::::M             A:::::A             P::::::PPPPPP:::::P 
N:::::::::N     N::::::NM:::::::::M         M:::::::::M            A:::::::A            PP:::::P     P:::::P
N::::::::::N    N::::::NM::::::::::M       M::::::::::M           A:::::::::A             P::::P     P:::::P
N:::::::::::N   N::::::NM:::::::::::M     M:::::::::::M          A:::::A:::::A            P::::P     P:::::P
N:::::::N::::N  N::::::NM:::::::M::::M   M::::M:::::::M         A:::::A A:::::A           P::::PPPPPP:::::P 
N::::::N N::::N N::::::NM::::::M M::::M M::::M M::::::M        A:::::A   A:::::A          P:::::::::::::PP  
N::::::N  N::::N:::::::NM::::::M  M::::M::::M  M::::::M       A:::::A     A:::::A         P::::PPPPPPPPP    
N::::::N   N:::::::::::NM::::::M   M:::::::M   M::::::M      A:::::AAAAAAAAA:::::A        P::::P            
N::::::N    N::::::::::NM::::::M    M:::::M    M::::::M     A:::::::::::::::::::::A       P::::P            
N::::::N     N:::::::::NM::::::M     MMMMM     M::::::M    A:::::AAAAAAAAAAAAA:::::A      P::::P            
N::::::N      N::::::::NM::::::M               M::::::M   A:::::A             A:::::A   PP::::::PP          
N::::::N       N:::::::NM::::::M               M::::::M  A:::::A               A:::::A  P::::::::P          
N::::::N        N::::::NM::::::M               M::::::M A:::::A                 A:::::A P::::::::P          
NNNNNNNN         NNNNNNNMMMMMMMM               MMMMMMMMAAAAAAA                   AAAAAAAPPPPPPPPPP          
                                                                                                            
                                                                                                            
                                                                                                            
                                                                                                            
                                                                                                            
                                                                                                            
                                                                                                            
"""
def show_logo():
    for line in logo.split("\n"):
        print(Fore.BLUE + line)
        time.sleep(0.15)
    time.sleep(1.5)  
    os.system('clear')
show_logo()
def get_ip(prompt=Fore.BLUE + "Enter Target IP:"):
	while True:
		value=input(prompt).strip()
		if value=="":
			print(Fore.RED + Style.BRIGHT + """IP cant by empty!!!""")
			continue
		try:
			if "/" in value:
				ipaddress.ip_network(value)
				return value
			else:
				ipaddress.ip_address(value)
				return value
		except ValueError:
				print(Fore.RED +  Style.BRIGHT + """Invalid IP or Network Address!!!""")
def get_ports():
	while True:
		value=input(Fore.BLUE + "Enter ports ex:( 80,433 or 80-100 ):").strip()
		if value=="":
			print(Fore.RED + Style.BRIGHT +  """Port cant by empty!!!""")
			continue
		valid=True
		for char in value:
			if not (char.isdigit() or char in "-,"):
				print(Fore.RED + Style.BRIGHT +  """Invalid caracters in ports!!!""")
				valid=False
				break
		if valid:
			return value
def get_fake_ip(prompt=Fore.BLUE + "Enter Fake IP:"):
	while True:
		value=input(prompt).strip()
		if value=="":
			print(Fore.RED + Style.BRIGHT + """IP cant by empty!!!""")
			continue
		try:
			if "/" in value:
				ipaddress.ip_network(value)
				return value
			else:
				ipaddress.ip_address(value)
				return value
		except ValueError:
				print(Fore.RED + Style.BRIGHT +  """Invalid IP or Network Address!!!""")
def ensure_archives_dir():
	"""Create Archives_Nmap directory if it doesn't exist"""
	if not os.path.exists("Archives_Nmap"):
		os.makedirs("Archives_Nmap")
		print(Fore.GREEN + "✓ Created Archives_Nmap directory")
os.system("clear")
def banner():
	print(Fore.BLUE + Style.BRIGHT +  r"""
.__   _.   .__  __.       ___      ._____   
|  \ |  | |   \/   |     /   \     |   _  \  
|   \|  | |  \  /  |    /  ^  \    |  |_)  | 
|  . `  | |  |\/|  |   /  /_\  \   |   ___/  
|  |\   | |  |  |  |  /  _____  \  |  |      
|__| \__| |__|  |__| /__/     \__\ |__|
------------------------------------------------------------------------|                              
(1) Scan Single Host		   |(11) Stealth Scan (SYN)		|
(2) Scan Entire Network		   |(12) Fast Detailed Scan		|
(3) Ping Scan (Active Hosts)	   |(13) Fragmented Packets Scan	|
(4) Scan Specific Ports	  	   |(14) Scan Without Host Discovery    |
(5) Full Port Scan	           |(15) UDP Scan			|
(6) Scan Common Ports (Top Ports)  |(16) IPv6 Scan			|
(7) Detect Services & Versions	   |(17) IP Spoofing			|
(8) Detect OS			   |(18) MAC Spoofing			|
(9) Aggressive Scan		   |(19) Use Decoys (Fake Devices)	|
(10) Vulnerability Scan (Script)   |					|
------------------------------------------------------------------------|

(99) Help
(00) Exit
--------------------------------------------------------------------------
""" + Style.RESET_ALL)
while True:
	os.system("clear")
	banner()
	choix = input(Fore.BLUE + Style.BRIGHT + "Enter your choice==========> :" + Style.RESET_ALL)
	
	if choix == "1":
		target_ip = get_ip()
		rep = input("Do you want to save the results? (y=Yes/n=No):").strip().upper()
		if rep == "Y":
			fil = input("Give a name to the file (without extension): ").strip()
			if not fil:
				fil = f"scan_{target_ip.replace('/', '')}{int(time.time())}"
			ensure_archives_dir()
			filepath = os.path.join("Archives_Nmap", fil + ".txt")
			if target_ip:
				subprocess.run(["nmap", target_ip, "-oN", filepath])
				print(Fore.GREEN + f"✓ Results saved to: {filepath}")
				input("\nPress Enter to go back to the menu")
		else:
			if target_ip:
				subprocess.run(["nmap", target_ip])
				input("\nPress Enter to go back to the menu")

	elif choix == "2":
		target_ip = get_ip()
		rep = input("Do you want to save the results? (y=Yes/n=No):").strip().upper()
		if rep == "Y":
			fil = input("Give a name to the file (without extension): ").strip()
			if not fil:
				fil = f"network_scan_{target_ip.replace('/', '')}{int(time.time())}"
			ensure_archives_dir()
			filepath1 = os.path.join("Archives_Nmap", fil + "_discovery.txt")
			filepath2 = os.path.join("Archives_Nmap", fil + "_fullscan.txt")
			if target_ip:
				subprocess.run(["nmap", "-sn", target_ip, "-oN", filepath1])
				print(Fore.GREEN + f"✓ Host discovery saved to: {filepath1}")
				input("\nPress Enter to scan all hosts")
				subprocess.run(["nmap", target_ip, "-oN", filepath2])
				print(Fore.GREEN + f"✓ Full scan saved to: {filepath2}")
				input("\nPress Enter to go back to the menu")
		else:
			if target_ip:
				subprocess.run(["nmap", "-sn", target_ip])
				input("\nPress Enter to scan all hosts")
				subprocess.run(["nmap", target_ip])
				input("\nPress Enter to go back to the menu")

	elif choix == "3":
		target_ip = get_ip()
		rep = input("Do you want to save the results? (y=Yes/n=No):").strip().upper()
		if rep == "Y":
			fil = input("Give a name to the file (without extension): ").strip()
			if not fil:
				fil = f"ping_scan_{target_ip.replace('/', '')}{int(time.time())}"
			ensure_archives_dir()
			filepath = os.path.join("Archives_Nmap", fil + ".txt")
			if target_ip:
				subprocess.run(["nmap", "-sn", target_ip, "-oN", filepath])
				print(Fore.GREEN + f"✓ Results saved to: {filepath}")
				input("\nPress Enter to go back to the menu")
		else:
			if target_ip:
				subprocess.run(["nmap", "-sn", target_ip])
				input("\nPress Enter to go back to the menu")

	elif choix == "4":
		target_ip = get_ip()
		port = get_ports()
		rep = input("Do you want to save the results? (y=Yes/n=No):").strip().upper()
		if rep == "Y":
			fil = input("Give a name to the file (without extension): ").strip()
			if not fil:
				fil = f"port_scan_{target_ip.replace('/', '')}{int(time.time())}"
			ensure_archives_dir()
			filepath = os.path.join("Archives_Nmap", fil + ".txt")
			if port and target_ip:
				subprocess.run(["nmap", "-p", port, target_ip, "-oN", filepath])
				print(Fore.GREEN + f"✓ Results saved to: {filepath}")
				input("\nPress Enter to go back to the menu")
		else:
			if port and target_ip:
				subprocess.run(["nmap", "-p", port, target_ip])
				input("\nPress Enter to go back to the menu")

	elif choix == "5":
		print(Fore.RED + """[!] Warning: Full Ports scan can take a long time. Use only if necessary""")
		reponse = input("Do you want to continue? (y/n):").upper()
		if reponse == "Y":
			target_ip = get_ip()
			rep = input("Do you want to save the results? (y=Yes/n=No):").strip().upper()
			if rep == "Y":
				fil = input("Give a name to the file (without extension): ").strip()
				if not fil:
					fil = f"full_port_scan_{target_ip.replace('/', '')}{int(time.time())}"
				ensure_archives_dir()
				filepath = os.path.join("Archives_Nmap", fil + ".txt")
				if target_ip:
					subprocess.run(["nmap", "-p-", target_ip, "-oN", filepath])
					print(Fore.GREEN + f"✓ Results saved to: {filepath}")
					input("\nPress Enter to go back to the menu")
			else:
				if target_ip:
					subprocess.run(["nmap", "-p-", target_ip])
					input("\nPress Enter to go back to the menu")
		else:
			print("Cancelled by user")
			time.sleep(1.5)
	elif choix == "6":
		print(Fore.YELLOW + """
		Scanning the following common ports:
		21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 80 (HTTP), 110 (POP3), 143 (IMAP), 443 (HTTPS), 3306 (MySQL), 3389 (RDP)
		""")
		target_ip = get_ip()
		ports = "21,22,23,25,53,80,110,143,443,3306,3389"
		rep = input("Do you want to save the results? (y=Yes/n=No):").strip().upper()
		if rep == "Y":
			fil = input("Give a name to the file (without extension): ").strip()
			if not fil:
				fil = f"common_ports_{target_ip.replace('/', '')}{int(time.time())}"
			ensure_archives_dir()
			filepath = os.path.join("Archives_Nmap", fil + ".txt")
			if target_ip:
				subprocess.run(["nmap", "-p", ports, target_ip, "-oN", filepath])
				print(Fore.GREEN + f"✓ Results saved to: {filepath}")
				input("\nPress Enter to go back to the menu")
		else:
			if target_ip:
				subprocess.run(["nmap", "-p", ports, target_ip])
				input("\nPress Enter to go back to the menu")

	elif choix == "7":
		target_ip = get_ip()
		rep = input("Do you want to save the results? (y=Yes/n=No):").strip().upper()
		if rep == "Y":
			fil = input("Give a name to the file (without extension): ").strip()
			if not fil:
				fil = f"service_scan_{target_ip.replace('/', '')}{int(time.time())}"
			ensure_archives_dir()
			filepath = os.path.join("Archives_Nmap", fil + ".txt")
			if target_ip:
				subprocess.run(["nmap", "-sV", target_ip, "-oN", filepath])
				print(Fore.GREEN + f"✓ Results saved to: {filepath}")
				input("\nPress Enter to go back to the menu")
		else:
			if target_ip:
				subprocess.run(["nmap", "-sV", target_ip])
				input("\nPress Enter to go back to the menu")

	elif choix == "8":
		target_ip = get_ip()
		rep = input("Do you want to save the results? (y=Yes/n=No):").strip().upper()
		if rep == "Y":
			fil = input("Give a name to the file (without extension): ").strip()
			if not fil:
				fil = f"os_scan_{target_ip.replace('/', '')}{int(time.time())}"
			ensure_archives_dir()
			filepath = os.path.join("Archives_Nmap", fil + ".txt")
			if target_ip:
				subprocess.run(["nmap", "-O", target_ip, "-oN", filepath])
				print(Fore.GREEN + f"✓ Results saved to: {filepath}")
				input("\nPress Enter to go back to the menu")
		else:
			if target_ip:
				subprocess.run(["nmap", "-O", target_ip])
				input("\nPress Enter to go back to the menu")

	elif choix == "9":
		print(Fore.RED + "[!] Warning: This aggressive scan may trigger security systems or get your IP blocked!")
		reponse = input("Do you want to continue? (y/n):").upper()
		if reponse == "Y":
			target_ip = get_ip()
			rep = input("Do you want to save the results? (y=Yes/n=No):").strip().upper()
			if rep == "Y":
				fil = input("Give a name to the file (without extension): ").strip()
				if not fil:
					fil = f"aggressive_scan_{target_ip.replace('/', '')}{int(time.time())}"
				ensure_archives_dir()
				filepath = os.path.join("Archives_Nmap", fil + ".txt")
				if target_ip:
					subprocess.run(["nmap", "-A", target_ip, "-oN", filepath])
					print(Fore.GREEN + f"✓ Results saved to: {filepath}")
					input("\nPress Enter to go back to the menu")
			else:
				if target_ip:
					subprocess.run(["nmap", "-A", target_ip])
					input("\nPress Enter to go back to the menu")
		else:
			print("Cancelled by user")
			time.sleep(1.5)
	elif choix == "10":
		while True:
			print(Fore.BLUE + """
			-----------------------------------------------------
			(1) Full Vulnerability Scan (vuln)
			(2) HTTP Vulnerability CVE-2006-3392
			(3) SMB Vulnerability MS17-010
			(4) FTP Anonymous Access
			(5) SSH Brute Force
			(0) Back to main menu
			-----------------------------------------------------
			""")
			script = input(Fore.BLUE + "Which script do you want:")
			if script == "1":
				target_ip = get_ip()
				rep = input("Do you want to save the results? (y=Yes/n=No):").strip().upper()
				if rep == "Y":
					fil = input("Give a name to the file (without extension): ").strip()
					if not fil:
						fil = f"vuln_scan_{target_ip.replace('/', '')}{int(time.time())}"
					ensure_archives_dir()
					filepath = os.path.join("Archives_Nmap", fil + ".txt")
					if target_ip:
						subprocess.run(["nmap", "--script", "vuln", target_ip, "-oN", filepath])
						print(Fore.GREEN + f"✓ Results saved to: {filepath}")
						input("\nPress Enter to go back to the menu")
				else:
					if target_ip:
						subprocess.run(["nmap", "--script", "vuln", target_ip])
						input("\nPress Enter to go back to the menu")
			elif script == "2":
				target_ip = get_ip()
				rep = input("Do you want to save the results? (y=Yes/n=No):").strip().upper()
				if rep == "Y":
					fil = input("Give a name to the file (without extension): ").strip()
					if not fil:
						fil = f"http_vuln_{target_ip.replace('/', '')}{int(time.time())}"
					ensure_archives_dir()
					filepath = os.path.join("Archives_Nmap", fil + ".txt")
					if target_ip:
						subprocess.run(["nmap", "--script", "http-vuln-cve2006-3392", target_ip, "-oN", filepath])
						print(Fore.GREEN + f"✓ Results saved to: {filepath}")
						input("\nPress Enter to go back to the menu")
				else:
					if target_ip:
						subprocess.run(["nmap", "--script", "http-vuln-cve2006-3392", target_ip])
						input("\nPress Enter to go back to the menu")
			elif script == "3":
				target_ip = get_ip()
				rep = input("Do you want to save the results? (y=Yes/n=No):").strip().upper()
				if rep == "Y":
					fil = input("Give a name to the file (without extension): ").strip()
					if not fil:
						fil = f"smb_vuln_{target_ip.replace('/', '')}{int(time.time())}"
					ensure_archives_dir()
					filepath = os.path.join("Archives_Nmap", fil + ".txt")
					if target_ip:
						subprocess.run(["nmap", "--script", "smb-vuln-ms17-010", target_ip, "-oN", filepath])
						print(Fore.GREEN + f"✓ Results saved to: {filepath}")
						input("\nPress Enter to go back to the menu")
				else:
					if target_ip:
						subprocess.run(["nmap", "--script", "smb-vuln-ms17-010", target_ip])
						input("\nPress Enter to go back to the menu")
			elif script == "4":
				target_ip = get_ip()
				rep = input("Do you want to save the results? (y=Yes/n=No):").strip().upper()
				if rep == "Y":
					fil = input("Give a name to the file (without extension): ").strip()
					if not fil:
						fil = f"ftp_anon_{target_ip.replace('/', '')}{int(time.time())}"
					ensure_archives_dir()
					filepath = os.path.join("Archives_Nmap", fil + ".txt")
					if target_ip:
						subprocess.run(["nmap", "--script", "ftp-anon", target_ip, "-oN", filepath])
						print(Fore.GREEN + f"✓ Results saved to: {filepath}")
						input("\nPress Enter to go back to the menu")
				else:
					if target_ip:
						subprocess.run(["nmap", "--script", "ftp-anon", target_ip])
						input("\nPress Enter to go back to the menu")
			elif script == "5":
				target_ip = get_ip()
				rep = input("Do you want to save the results? (y=Yes/n=No):").strip().upper()
				if rep == "Y":
					fil = input("Give a name to the file (without extension): ").strip()
					if not fil:
						fil = f"ssh_brute_{target_ip.replace('/', '')}{int(time.time())}"
					ensure_archives_dir()
					filepath = os.path.join("Archives_Nmap", fil + ".txt")
					if target_ip:
						subprocess.run(["nmap", "--script", "ssh-brute", target_ip, "-oN", filepath])
						print(Fore.GREEN + f"✓ Results saved to: {filepath}")
						input("\nPress Enter to go back to the menu")
				else:
					if target_ip:
						subprocess.run(["nmap", "--script", "ssh-brute", target_ip])
						input("\nPress Enter to go back to the menu")
			elif script == "0":
				break       
			else:
				print(" invalid script !")
				input("\nPress Enter to go back to the menu")
	elif choix == "11":    
		target_ip = get_ip()
		rep = input("Do you want to save the results? (y=Yes/n=No):").strip().upper()
		if rep == "Y":
			fil = input("Give a name to the file (without extension): ").strip()
			if not fil:
				fil = f"stealth_scan_{target_ip.replace('/', '')}{int(time.time())}"
			ensure_archives_dir()
			filepath = os.path.join("Archives_Nmap", fil + ".txt")
			if target_ip:
				subprocess.run(["nmap", "-sS", target_ip, "-oN", filepath])
				print(Fore.GREEN + f"✓ Results saved to: {filepath}")
				input("\nPress Enter to go back to the menu")
		else:
			if target_ip:
				subprocess.run(["nmap", "-sS", target_ip])
				input("\nPress Enter to go back to the menu")

	elif choix == "12":
		target_ip = get_ip()
		rep = input("Do you want to save the results? (y=Yes/n=No):").strip().upper()
		if rep == "Y":
			fil = input("Give a name to the file (without extension): ").strip()
			if not fil:
				fil = f"fast_detailed_{target_ip.replace('/', '')}{int(time.time())}"
			ensure_archives_dir()
			filepath = os.path.join("Archives_Nmap", fil + ".txt")
			if target_ip:
				subprocess.run(["nmap", "-T4", "-A", "-v", target_ip, "-oN", filepath])
				print(Fore.GREEN + f"✓ Results saved to: {filepath}")
				input("\nPress Enter to go back to the menu")
		else:
			if target_ip:
				subprocess.run(["nmap", "-T4", "-A", "-v", target_ip])
				input("\nPress Enter to go back to the menu")

	elif choix == "13":
		target_ip = get_ip()
		rep = input("Do you want to save the results? (y=Yes/n=No):").strip().upper()
		if rep == "Y":
			fil = input("Give a name to the file (without extension): ").strip()
			if not fil:
				fil = f"fragmented_{target_ip.replace('/', '')}{int(time.time())}"
			ensure_archives_dir()
			filepath = os.path.join("Archives_Nmap", fil + ".txt")
			if target_ip:
				subprocess.run(["nmap", "-f", target_ip, "-oN", filepath])
				print(Fore.GREEN + f"✓ Results saved to: {filepath}")
				input("\nPress Enter to go back to the menu")
		else:
			if target_ip:
				subprocess.run(["nmap", "-f", target_ip])
				input("\nPress Enter to go back to the menu")

	elif choix == "14":
		target_ip = get_ip()
		rep = input("Do you want to save the results? (y=Yes/n=No):").strip().upper()
		if rep == "Y":
			fil = input("Give a name to the file (without extension): ").strip()
			if not fil:
				fil = f"no_discovery_{target_ip.replace('/', '')}{int(time.time())}"
			ensure_archives_dir()
			filepath = os.path.join("Archives_Nmap", fil + ".txt")
			if target_ip:
				subprocess.run(["nmap", "-Pn", target_ip, "-oN", filepath])
				print(Fore.GREEN + f"✓ Results saved to: {filepath}")
				input("\nPress Enter to go back to the menu")
		else:
			if target_ip:
				subprocess.run(["nmap", "-Pn", target_ip])
				input("\nPress Enter to go back to the menu")

	elif choix == "15":
		print(Fore.RED + """[!] Warning: UDP Scan can take a long time. Use only if necessary""")
		reponse = input("Do you want to continue? (y/n):").upper()
		if reponse == "Y":
			target_ip = get_ip()
			rep = input("Do you want to save the results? (y=Yes/n=No):").strip().upper()
			if rep == "Y":
				fil = input("Give a name to the file (without extension): ").strip()
				if not fil:
					fil = f"udp_scan_{target_ip.replace('/', '')}{int(time.time())}"
				ensure_archives_dir()
				filepath = os.path.join("Archives_Nmap", fil + ".txt")
				if target_ip:
					subprocess.run(["nmap", "-sU", target_ip, "-oN", filepath])
					print(Fore.GREEN + f"✓ Results saved to: {filepath}")
					input("\nPress Enter to go back to the menu")
			else:
				if target_ip:
					subprocess.run(["nmap", "-sU", target_ip])
					input("\nPress Enter to go back to the menu")
		else:
			print("Cancelled by user")
			time.sleep(1.5)

	elif choix == "16":
		target_ip = get_ip()
		rep = input("Do you want to save the results? (y=Yes/n=No):").strip().upper()
		if rep == "Y":
			fil = input("Give a name to the file (without extension): ").strip()
			if not fil:
				fil = f"ipv6_scan_{target_ip.replace('/', '')}{int(time.time())}"
			ensure_archives_dir()
			filepath = os.path.join("Archives_Nmap", fil + ".txt")
			if target_ip:
				subprocess.run(["nmap", "-6", target_ip, "-oN", filepath])
				print(Fore.GREEN + f"✓ Results saved to: {filepath}")
				input("\nPress Enter to go back to the menu")
		else:
			if target_ip:
				subprocess.run(["nmap", "-6", target_ip])
				input("\nPress Enter to go back to the menu")

	elif choix == "17":
		target_ip = get_ip()
		fake_ip = get_fake_ip()
		rep = input("Do you want to save the results? (y=Yes/n=No):").strip().upper()
		if rep == "Y":
			fil = input("Give a name to the file (without extension): ").strip()
			if not fil:
				fil = f"ip_spoof_{target_ip.replace('/', '')}{int(time.time())}"
			ensure_archives_dir()
			filepath = os.path.join("Archives_Nmap", fil + ".txt")
			if target_ip:
				subprocess.run(["nmap", "-S", fake_ip, "-e", "eth0", "-Pn", target_ip, "-oN", filepath])
				print(Fore.GREEN + f"✓ Results saved to: {filepath}")
				input("\nPress Enter to go back to the menu")
		else:
			if target_ip:
				subprocess.run(["nmap", "-S", fake_ip, target_ip])
				input("\nPress Enter to go back to the menu")

	elif choix == "18":
		target_ip = get_ip()
		rep = input("Do you want to save the results? (y=Yes/n=No):").strip().upper()
		if rep == "Y":
			fil = input("Give a name to the file (without extension): ").strip()
			if not fil:
				fil = f"mac_spoof_{target_ip.replace('/', '')}{int(time.time())}"
			ensure_archives_dir()
			filepath = os.path.join("Archives_Nmap", fil + ".txt")
			if target_ip:
				subprocess.run(["nmap", target_ip, "--spoof-mac", "0", "-oN", filepath])
				print(Fore.GREEN + f"✓ Results saved to: {filepath}")
				input("\nPress Enter to go back to the menu")
		else:
			if target_ip:
				subprocess.run(["nmap", target_ip, "--spoof-mac", "0"])
				input("\nPress Enter to go back to the menu")

	elif choix == "19":
		target_ip = get_ip()
		rep = input("Do you want to save the results? (y=Yes/n=No):").strip().upper()
		if rep == "Y":
			fil = input("Give a name to the file (without extension): ").strip()
			if not fil:
				fil = f"decoy_scan_{target_ip.replace('/', '')}{int(time.time())}"
			ensure_archives_dir()
			filepath = os.path.join("Archives_Nmap", fil + ".txt")
			if target_ip:
				subprocess.run(["nmap", "-D", "RND:10", target_ip, "-oN", filepath])
				print(Fore.GREEN + f"✓ Results saved to: {filepath}")
				input("\nPress Enter to go back to the menu")
		else:
			if target_ip:
				subprocess.run(["nmap", "-D", "RND:10", target_ip])
				input("\nPress Enter to go back to the menu")
	elif choix=="99":
		os.system("clear")
		print(Fore.WHITE + """
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<HELP MENU>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

(1)  Scan Single Host
     ➤ Perform a basic scan on a single target host to detect open ports.

(2)  Scan Entire Network
     ➤ Scan a whole subnet (e.g., 192.168.1.0/24) to discover all connected devices.

(3)  Ping Scan (Active Hosts)
     ➤ Detect live hosts without scanning ports. Useful for network discovery.

(4)  Scan Specific Ports
     ➤ Scan user-defined ports (e.g., 80,443 or 20-100) on the target host.
     
(5)  Full Port Scan
     ➤ Scan all 65,535 TCP ports on the target host.

(6)  Scan Common Ports
     ➤ Quickly scan the most popular ports (FTP, SSH, HTTP, etc.).

(7)  Detect Services & Versions
     ➤ Identify running services and their versions on open ports (-sV option).

(8)  Detect OS
     ➤ Attempt to determine the operating system of the target host (-O option).
     
(9)  Aggressive Scan
     ➤ Enable OS detection, version detection, script scanning, and traceroute (-A option).

(10) Vulnerability Scan (Scripts)
     ➤ Use Nmap scripts to check for common vulnerabilities on the target.

(11) Stealth Scan (SYN)
     ➤ Perform a SYN scan that avoids full TCP handshake for stealthiness (-sS).

(12) Fast Detailed Scan
     ➤ Perform a faster scan with more details (-T4 -A -v options).

(13) Fragmented Packets Scan
     ➤ Send fragmented packets to bypass certain firewalls (-f option).

(14) Scan Without Host Discovery
     ➤ Skip host discovery and scan the target directly (-Pn).
     
(15) UDP Scan
     ➤ Scan for open UDP ports on the target host (-sU option). 
       Note: UDP scans are slower than TCP scans and may take more time.
       
(16) IPv6 Scan
     ➤ Perform a scan on an IPv6 address using Nmap (-6 option).
     
(17) Fake IP Scan
     ➤ Use a fake source IP address for the scan (-S option).
       Useful to hide the real source IP or test spoofing scenarios.
       Note: May require root privileges and may not work on all networks.

(18) MAC Address Spoofing
     ➤ Change the MAC address to a random one during the scan (--spoof-mac random).
       Helps hide your device identity on the network.
       Note: May require root privileges.

(19) Decoy Scan
     ➤ Send scan packets from multiple decoy IPs along with your real IP (-D RND:10).
       Makes it hard for the target to identify the real source of the scan.
       Note: Requires root privileges and can slow down the scan.

(99) Help
     ➤ Display this help menu.

(00) Exit
     ➤ Exit the program.
    """)
		input("\nPress Enter to go back to the menu")
	elif choix=="00":
		break
	else:
		print(" invalid choice!!!")
		time.sleep(1.5)
		input("\nPress Enter to go back to the menu")
