import os
import sys,time
import subprocess
from colorama import Fore, Style, init
init(autoreset=True)
folders = ['Detected_Attack', 'Archives_IDS', 'Archives_Nmap']
for folder in folders:
	os.makedirs(folder,exist_ok=True)
if os.geteuid() != 0:
	print(Fore.RED + "Error: Run with sudo!")
	sys.exit(1)
os.system("clear")
def banner():
	print(Fore.CYAN + Style.BRIGHT + """
-----------------------------------------------------------------------------------------------------
 ██████╗██╗   ██╗██████╗ ███████╗██████╗        ██████╗  ██╗   ██╗ █████╗ ██████╗ ██████╗ 	     |
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗      ██╔════╝  ██║   ██║██╔══██╗██╔══██╗██╔══██╗	     |
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝█████╗██║  ███╗ ██║   ██║███████║██████╔╝██║  ██║           |
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════╝██║   ██║ ██║   ██║██╔══██║██╔══██╗██║  ██║           |
╚██████╗   ██║   ███████╗███████╗██║  ██║      ╚██████╔╝ ╚██████╔╝██║  ██║██║  ██║██████╔╝           |
 ╚═════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝        ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝            |
 												     |
								Coded By Ezzhar Yahya	Version:1    | 
-----------------------------------------------------------------------------------------------------
		 _______________________________________________________
		|_______________________________________________________|
							     	 	
		[1]      ==>     Network Scan (Nmap)   
								      	                     
		[2]      ==>     Monitor Traffic   
								     	                      
		[3]      ==>     Analyze Logs
								     	                       
		[4]      ==>     Firewall Manger 
								     	                            	                     
		[0]      ==>     Exit        
							      		
		  ________________________________________________________
		 |________________________________________________________|
			
	
	""" + Style.RESET_ALL)
while True:
	os.system("clear")
	banner()
	choix=input(Fore.CYAN + Style.BRIGHT + "\n\nEnter your choice==============> :" + Style.RESET_ALL)
	if choix =="1":
	   subprocess.run(["python3", "modules/network_scaner.py"], check=True)
	elif choix =="2":
	     subprocess.run(["python3", "modules/ids.py"], check=True)
	elif choix =="3":
		subprocess.run(["python3", "modules/analyze_logs.py"], check=True)
	elif choix =="4":
	     subprocess.run(["python3", "modules/firewall_manger.py"], check=True)
	elif choix =="5":
	    subprocess.run(["python3", " modules/vpn_setup.py"], check=True)
	elif choix =="0":
	     os.system("clear")
	     break
	else :
	     print("Invalid Choice!")
	     time.sleep(1.5)
	     os.system("clear")
	     continue
