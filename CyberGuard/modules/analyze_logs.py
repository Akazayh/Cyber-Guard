#!/usr/bin/env python3
# analyze_logs.py
# Standalone log analyzer for IDS logs.
# Works with Archives_IDS and Detected_Attack folders, only .log files.
import sys
import os
import re
from collections import Counter
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)
LOG_DIRS = {
	"1": ("Archives_IDS", "Session archives (Archives_IDS)"),
	"2": ("Detected_Attack", "Detected attacks (Detected_Attack)")
}

RE_TIMESTAMP_ISO = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})')
RE_SESSION_LINE = re.compile(r'(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \| (?P<proto>[A-Z]+) \| (?P<src>[^ ]+) -> (?P<dst>[^ ]+)')
RE_IP = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
# protocols short match (also catch IPv6-ish or custom)
PROT_KEYWORDS = ["TCP", "UDP", "DNS", "ICMP", "RAW", "WLAN", "HTTPS"]

ATTACK_KEYWORDS = {
	"ARP_Spoof": ["arp spoof", "arp_spoof", "arp spoofing"],
	"DNS_Spoof": ["dns spoof", "dns_spoof", "dns spoofing"],
	"SYN_Flood": ["syn flood", "syn_flood"],
	"UDP_Flood": ["udp flood", "udp_flood"],
	"ICMP_Flood": ["icmp flood", "icmp_flood"],
	"Port_Scan": ["port scan", "port_scan"],
	"Deauth": ["deauth", "deauthentication"],
	"BeaconFlood": ["beacon flood", "beaconflood", "fake ap"],
	"ProbeFlood": ["probe request flood", "probeflood"],
	"WPA_Handshake": ["wpa handshake", "wpa_handshake"],
	"KRACK_Attack": ["krack", "krack_attack"]
}

MAX_SEARCH_SHOW = 200

def list_logs_in_dir(directory):
	try:
		os.makedirs(directory, exist_ok=True)
		entries = sorted([f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f)) and f.lower().endswith('.log')])
		return entries
	except Exception as e:
		print(Fore.RED + f"Error listing {directory}: {e}")
		return []

def safe_basename(name):
	name = name.strip()
	if not name:
		return None
	# disallow path separators/traversal
	if '/' in name or '\\' in name or '..' in name:
		return None
	if not name.lower().endswith('.log'):
		name += '.log'
	return name

def parse_ts_from_line(line):
	m = RE_TIMESTAMP_ISO.search(line)
	if m:
		try:
			return datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S')
		except:
			return None
	return None

def detect_attacks_in_line(line):
	found = []
	l = line.lower()
	for k, keys in ATTACK_KEYWORDS.items():
		for kw in keys:
			if kw in l:
				found.append(k)
				break
	return found

def quick_detect_protocol(line):
	# try to find protocol keyword in line
	for p in PROT_KEYWORDS:
		if p.lower() in line.lower():
			return p
	# fallback: try session line regex
	m = RE_SESSION_LINE.search(line)
	if m:
		return m.group('proto').upper()
	return None

def analyze_file(path):
	summary = {
		"file": path,
		"total_lines": 0,
		"session_entries": 0,
		"protocols": Counter(),
		"attack_types": Counter(),
		"ips": Counter(),
		"pcap_refs": [],
		"first_ts": None,
		"last_ts": None,
		"sample_lines": []
	}
	try:
		with open(path, 'r', encoding='utf-8', errors='ignore') as f:
			for lineno, raw in enumerate(f, start=1):
				line = raw.rstrip('\n')
				if not line.strip():
					continue
				summary["total_lines"] += 1

				# timestamps
				ts = parse_ts_from_line(line)
				if ts:
					if not summary["first_ts"] or ts < summary["first_ts"]:
						summary["first_ts"] = ts
					if not summary["last_ts"] or ts > summary["last_ts"]:
						summary["last_ts"] = ts

				# session-like entries
				m = RE_SESSION_LINE.search(line)
				if m:
					summary["session_entries"] += 1
					proto = (m.group('proto') or "").upper()
					if proto:
						summary["protocols"][proto] += 1

				# protocol heuristic
				else:
					p = quick_detect_protocol(line)
					if p:
						summary["protocols"][p] += 1

				# attacks
				attacks = detect_attacks_in_line(line)
				for a in attacks:
					summary["attack_types"][a] += 1

				# ips
				for ip in RE_IP.findall(line):
					summary["ips"][ip] += 1

				# pcap refs
				if '.pcap' in line.lower():
					summary["pcap_refs"].append((lineno, line))

				if len(summary["sample_lines"]) < 10:
					summary["sample_lines"].append((lineno, line))

	except Exception as e:
		print(Fore.RED + f"Error reading file {path}: {e}")
		return None
	return summary

def print_comprehensive(summary):
	if not summary:
		print(Fore.RED + "No summary to show.")
		return
	print(Style.BRIGHT + Fore.CYAN + "\n=== Comprehensive Statistics ===\n")
	print(Fore.GREEN + f"File: {summary['file']}")
	print(Fore.WHITE + f"Total non-empty lines: {summary['total_lines']}")
	print(Fore.WHITE + f"Detected session-like entries: {summary['session_entries']}")
	if summary['first_ts']:
		print(Fore.WHITE + f"Time range: {summary['first_ts'].isoformat(' ')} -> {summary['last_ts'].isoformat(' ')}")
	print("\n" + Fore.WHITE + "Top protocols:")
	if summary['protocols']:
		for proto, cnt in summary['protocols'].most_common(12):
			print(f"  {proto}: {cnt}")
	else:
		print("  (no protocols detected)")

	print("\n" + Fore.WHITE + "Detected attack types:")
	if summary['attack_types']:
		for atk, cnt in summary['attack_types'].most_common():
			print(f"  {atk}: {cnt}")
	else:
		print("  (no attack keywords detected)")

	print("\n" + Fore.WHITE + "Top IPs:")
	if summary['ips']:
		for ip, cnt in summary['ips'].most_common(10):
			print(f"  {ip}: {cnt}")
	else:
		print("  (no IPs detected)")

	if summary['pcap_refs']:
		print("\n" + Fore.WHITE + "PCAP references (showing up to 10):")
		for lineno, ln in summary['pcap_refs'][:10]:
			print(f"  [line {lineno}] {ln}")
	print("\n" + Fore.WHITE + "Sample lines:")
	for lineno, ln in summary['sample_lines']:
		print(f"  [{lineno}] {ln}")
	print(Style.BRIGHT + Fore.WHITE + "\n=== End of Summary ===\n")

def search_in_file(path, keyword):
	keyword_l = keyword.lower()
	matches = []
	try:
		with open(path, 'r', encoding='utf-8', errors='ignore') as f:
			for lineno, raw in enumerate(f, start=1):
				line = raw.rstrip('\n')
				if keyword_l in line.lower():
					matches.append((lineno, line))
					if len(matches) >= MAX_SEARCH_SHOW:
						break
	except Exception as e:
		print(Fore.RED + f"Error searching file {path}: {e}")
		return []
	return matches

def detect_anomalies(path):
	# we'll scan and output suspicious lines + counters
	anomalies = {
		"attack_lines": [],
		"attack_counts": Counter(),
		"suspicious_ips": Counter()
	}
	try:
		with open(path, 'r', encoding='utf-8', errors='ignore') as f:
			for lineno, raw in enumerate(f, start=1):
				line = raw.rstrip('\n')
				if not line:
					continue
				attacks = detect_attacks_in_line(line)
				if attacks:
					anomalies["attack_lines"].append((lineno, line, attacks))
					for a in attacks:
						anomalies["attack_counts"][a] += 1
				# heuristics: many SYN/ICMP/UDP packets lines might contain keywords
				# collect any IPs on lines with suspicious words
				lower = line.lower()
				if any(x in lower for x in ["syn flood", "icmp flood", "udp flood", "port scan", "deauth", "beacon flood", "probe request"]):
					for ip in RE_IP.findall(line):
						anomalies["suspicious_ips"][ip] += 1
	except Exception as e:
		print(Fore.RED + f"Error detecting anomalies in {path}: {e}")
	return anomalies

def export_report(summary, anomalies, outpath):
	try:
		with open(outpath, 'w', encoding='utf-8') as out:
			out.write(f"Analysis of {summary['file']}\n")
			out.write(f"Total lines: {summary['total_lines']}\n")
			out.write(f"Session entries: {summary['session_entries']}\n")
			if summary['first_ts']:
				out.write(f"Time range: {summary['first_ts'].isoformat(' ')} -> {summary['last_ts'].isoformat(' ')}\n")
			out.write("\nProtocols:\n")
			for proto, cnt in summary['protocols'].most_common():
				out.write(f"{proto}: {cnt}\n")
			out.write("\nAttack types:\n")
			for atk, cnt in summary['attack_types'].most_common():
				out.write(f"{atk}: {cnt}\n")
			out.write("\nTop IPs:\n")
			for ip, cnt in summary['ips'].most_common(50):
				out.write(f"{ip}: {cnt}\n")
			out.write("\nAnomalies summary:\n")
			for a, cnt in anomalies['attack_counts'].most_common():
				out.write(f"{a}: {cnt}\n")
			out.write("\nSuspicious IPs:\n")
			for ip, cnt in anomalies['suspicious_ips'].most_common(50):
				out.write(f"{ip}: {cnt}\n")
			out.write("\nSample suspicious lines (up to 200):\n")
			for ln, line, attacks in anomalies['attack_lines'][:200]:
				out.write(f"[{ln}] {attacks} -> {line}\n")
		return True
	except Exception as e:
		print(Fore.RED + f"Error exporting report: {e}")
		return False
def choose_directory():
	sys.stdout.flush()
	print(Style.BRIGHT + Fore.WHITE + "\nChoose source directory:")
	for k, v in LOG_DIRS.items():
		print(Style.BRIGHT + Fore.WHITE + f"  {k}. {v[0]} - {v[1]}")
	print(Style.BRIGHT + Fore.WHITE + "  3.  Help")
	print(Style.BRIGHT + Fore.WHITE + "  00. Return to previous menu")  
	sys.stdout.flush()
	choice = input(Style.BRIGHT + Fore.WHITE + "Enter your choice====>:").strip()
	
	if choice=="3":
		os.system("clear")
		print(Fore.WHITE + Style.BRIGHT + """
╔══════════════════════════════════════════════════════════════════╗
║                    HELP - LOG ANALYZER                           ║
╠══════════════════════════════════════════════════════════════════╣
║ [1] Show Comprehensive Statistics                                ║
║     ➤ Display detailed analysis of log file                     ║
║     - Total lines, session entries, protocols                    ║
║     - Attack types, IP addresses, time range                     ║
║                                                                  ║
║ [2] Search Log Entries                                           ║
║     ➤ Search for specific keywords in log file                  ║
║     - Case-insensitive search                                    ║
║     - Shows matching lines with line numbers                     ║
║                                                                  ║
║ [3] Detect Anomalies & Security Issues                           ║
║     ➤ Identify security threats and anomalies                   ║
║     - Attack keyword detection                                   ║
║     - Suspicious IP addresses                                    ║
║     - Sample attack lines                                        ║
║                                                                  ║
║ [4] Export Analysis Report                                       ║
║     ➤ Generate comprehensive report file                        ║
║     - Protocols and attack statistics                            ║
║     - IP addresses and anomalies summary                         ║
║                                                                  ║
║ [5] Change File                                                  ║
║     ➤ Select different log file to analyze                      ║
║                                                                  ║
║ SUPPORTED LOG TYPES:                                             ║
║ • Archives_IDS/ - Session archives                               ║ 
║ • Detected_Attack/ - Security incident logs                      ║
║ • Only .log files are supported                                  ║
╚══════════════════════════════════════════════════════════════════╝
""" + Style.RESET_ALL)
		input(Fore.WHITE + "\nPress Enter to continue..." + Style.RESET_ALL)
		os.system("clear")
	elif choice == "00":
		return "BACK" 
	if choice in LOG_DIRS:
		return LOG_DIRS[choice][0]
	
	print(Style.BRIGHT + Fore.RED + "Invalid choice.")
	return

def choose_file_from_dir(directory):
	files = list_logs_in_dir(directory)
	if not files:
		print(Fore.WHITE + f"No .log files found in {directory}.")
		return None
	print(Style.BRIGHT + Fore.WHITE + f"\nFiles in {directory}:")
	for idx, fn in enumerate(files, start=1):
		print(f"  [{idx}] {fn}")
	print(Style.BRIGHT + Fore.WHITE +"\nYou can enter the index number or the exact filename.")
	choice = input(Style.BRIGHT + Fore.WHITE + "Your choice: ").strip()
	target = None
	if choice.isdigit():
		i = int(choice) - 1
		if 0 <= i < len(files):
			target = os.path.join(directory, files[i])
	else:
		bn = safe_basename(choice)
		if bn and bn in files:
			target = os.path.join(directory, bn)
	if not target:
		print(Fore.RED + "File not found or invalid selection.")
	return target

def main_menu():
	sys.stdout.flush()
	print(Style.BRIGHT + Fore.WHITE + "\n=== IDS Log Analyzer ===")
	print(Style.BRIGHT + Fore.WHITE + "This tool analyzes .log files inside Archives_IDS or Detected_Attack.")
	current_dir = None
	current_file = None
	summary = None
	anomalies = None
	os.system("clear")
	print(Fore.WHITE + Style.BRIGHT +  r"""                                            
    ##                         ####                                              ##                                               
   ####                          ##                                              ##                                               
   ####    ##.####    :####      ##      ##    ##  ########   .####:             ##         .####.    :###:##   :#####.           
  :#  #:   #######    ######     ##      :##  ##   ########  .######:            ##        .######.  .#######  ########           
   #::#    ###  :##   #:  :##    ##       ##: ##.      :##:  ##:  :##            ##        ###  ###  ###  ###  ##:  .:#           
  ##  ##   ##    ##    :#####    ##       ###:##      :##:   ########            ##        ##.  .##  ##.  .##  ##### .            
  ######   ##    ##  .#######    ##       .## #      :##:    ########            ##        ##    ##  ##    ##  .######:           
 .######.  ##    ##  ## .  ##    ##        ####.    :##:     ##                  ##        ##.  .##  ##.  .##     .: ##           
 :##  ##:  ##    ##  ##:  ###    ##:       :###    :##:      ###.  :#            ##        ###  ###  ###  ###  #:.  :##           
 ###  ###  ##    ##  ########    #####      ##     ########  .#######            ########  .######.  .#######  ########           
 ##:  :##  ##    ##    ###.##    .####      ##.    ########   .#####:            ########   .####.    :###:##  . ####             
                                           :##                                                        #.  :##                     
                                          ###:                                                        ######                      
                                          ###                                                         :####:
""" + Style.RESET_ALL)
	while True:
		if not current_file:
			print(Style.BRIGHT + Fore.WHITE + "\nPlease select source directory and file to analyze first.")
			d = choose_directory()
			if d == "BACK": 
				return 
			if not d:
				continue
			current_dir = d
			fpath = choose_file_from_dir(current_dir)
			if not fpath:
				continue
			current_file = fpath
			print(Fore.GREEN + f"Selected file: {current_file}")
			summary = analyze_file(current_file)
			anomalies = None

		# interactive menu for the chosen file
		print("\n"  + Style.BRIGHT + Fore.WHITE +  " 1 - Show Comprehensive Statistics")
		print(Style.BRIGHT + Fore.WHITE + " 2 - Search Log Entries")
		print(Style.BRIGHT + Fore.WHITE +  " 3 - Detect Anomalies & Security Issues")
		print(Style.BRIGHT + Fore.WHITE +  " 4 - Export Analysis Report")
		print(Style.BRIGHT + Fore.WHITE + " 5 - Change File")
		print(Style.BRIGHT + Fore.WHITE + " 0 - Return / Exit")
		ch = input(Style.BRIGHT + Fore.WHITE + "\nEnter choice: ").strip()

		if ch == "1":
			# show stats (recompute summary if file changed)
			summary = analyze_file(current_file)
			print_comprehensive(summary)

		elif ch == "2":
			kw = input(Style.BRIGHT + Fore.WHITE + "Enter search keyword (case-insensitive): ").strip()
			if not kw:
				print(Fore.WHITE + "Empty keyword.")
				continue
			matches = search_in_file(current_file, kw)
			if not matches:
				print(Fore.WHITE + "No matches found.")
			else:
				print(Fore.CYAN + f"Found {len(matches)} match(es) (showing up to {MAX_SEARCH_SHOW}):")
				for ln, text in matches:
					print(Fore.WHITE + f"[{ln}] " + Style.RESET_ALL + text)

		elif ch == "3":
			anomalies = detect_anomalies(current_file)
			print(Style.BRIGHT + Fore.CYAN + "\n=== Anomalies & Security Issues ===")
			if anomalies["attack_counts"]:
				print(Fore.WHITE + "Attack keywords found:")
				for a, cnt in anomalies["attack_counts"].most_common():
					print(f"  {a}: {cnt}")
				print("\nSample attack lines (up to 20):")
				for ln, line, attacks in anomalies["attack_lines"][:20]:
					print(Fore.RED + f"[{ln}] {attacks} -> " + Style.RESET_ALL + line)
			else:
				print(Fore.GREEN + "No attack keywords found in file.")

			if anomalies["suspicious_ips"]:
				print("\nSuspicious IPs (heuristic):")
				for ip, cnt in anomalies["suspicious_ips"].most_common(20):
					print(f"  {ip}: {cnt}")

		elif ch == "4":
			# export option
			if not summary:
				summary = analyze_file(current_file)
			if not anomalies:
				anomalies = detect_anomalies(current_file)
			default_name = os.path.basename(current_file) + ".analysis.log"
			out = input(f"Enter output filename (saved to current dir) [{default_name}]: ").strip()
			if not out:
				out = default_name
			out_bn = safe_basename(out)
			if not out_bn:
				print(Fore.RED + "Invalid filename.")
				continue
			outpath = os.path.join(".", out_bn)
			ok = export_report(summary, anomalies, outpath)
			if ok:
				print(Fore.GREEN + f"Report exported to {outpath}")

		elif ch == "5":
			# change file
			current_dir = None
			current_file = None
			summary = None
			anomalies = None
			continue

		elif ch == "0":
			print(Fore.GREEN + "Exiting analyzer.")
			break
		
		else:
			print(Fore.WHITE + "Unknown choice. Try again.")

if __name__ == "__main__":
	sys.stdout.flush()
	try:
		main_menu()
	except KeyboardInterrupt:
		print("\n" + Fore.WHITE + "Interrupted. Bye.")
