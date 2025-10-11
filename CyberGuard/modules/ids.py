from scapy.all import *
from datetime import datetime
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.l2 import ARP
from scapy.packet import Raw
from scapy.config import conf
from scapy.all import AsyncSniffer, wrpcap
from threading import Thread
from datetime import datetime
from colorama import Fore, Style, init
from threading import Lock
from scapy.layers.dot11 import RadioTap, Dot11, Dot11ProbeReq, Dot11ProbeResp, Dot11Beacon
from scapy.layers.dot11 import Dot11AssoReq, Dot11ReassoReq, Dot11Auth, Dot11Deauth,Dot11Elt
from scapy.layers.eap import EAPOL
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from collections import deque
from rich.live import Live
from rich import box
import threading
import queue
import shutil
import os
os.environ["SCAPY_COLORED"] = "0"
import time
import psutil
import sys
import warnings
import contextlib
warnings.filterwarnings("ignore")

init(autoreset=True)
os.system("clear")

# Constants
packet_buffer = deque(maxlen=1000)
alerts = []
alerts_shown = set()
alert_sound = "alert.wav"
last_alert_time = 0
MAX_ROWS=30
MAX_BUFFER_SIZE=1000
MAX_PAYLOAD_DISPLAY=50
MAX_SEEN_PACKETS=1000
SYN_FLOOD_THRESHOLD = 100
UDP_FLOOD_THRESHOLD = 1000
ICMP_FLOOD_THRESHOLD = 100
PORT_SCAN_THRESHOLD = 20
dns_cache = {}
DNS_CACHE_TTL = 300 
CONFLICT_WINDOW = 60
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

# Global variables
console = Console()
lock=threading.Lock()
mock=Lock()
krack_monitor = {}
evil_twin_detections = {}
flows = {}
target_bssid = None
target_ssid = None
associated_clients = set()
tcp_count=0
udp_count=0
arp_count=0
icmp_count=0
raw_count=0
dns_count=0
https_count=0
wlan_count=0
total_count=0
stop_stats=False
last_alert_time = 0.0
write_queue=queue.Queue()
pcap_queue = queue.Queue()
save_pcap_session = False
sniffer=None
stop_sniff=False
summary=""
filename=""
conf.use_pcap=True
conf.verb=0
seen_packets=set()
save_session=False
session_file=None

packets_data = []
captured_packets=[]
arp_table = {}
dns_cache = {}
syn_packets = {}
udp_packets = {}
icmp_packets = {}
scan_attempts = {}
tcp_sessions = {}
beacon_cache = {}
probe_count = {}
handshake_count = {}
trusted_aps = {}
stats = {'total':0,'tcp':0,'udp':0,'icmp':0,'arp':0,"dns":0,"https":0,'wlan':0}
last_syn_alert_time = {} 
monitoring_type = 'local'
ALERT_COOLDOWN = 5
def start_sniffing(iface_name):
	global sniffer,stop_sniff,packet_buffer,filename,save_session,stop_stats,tcp_count, udp_count, arp_count, icmp_count,https_count, raw_count, dns_count, total_count,wlan_count,monitoring_type,target_bssid,target_ssid
	suppress_scapy_warnings()
	with lock:
		packets_data.clear()
	seen_packets.clear()
	packet_buffer.clear()
	tcp_count = udp_count = arp_count = icmp_count = raw_count = dns_count = total_count = 0
	stats.update({'total':0, 'tcp':0, 'udp':0, 'icmp':0, 'arp':0, 'dns':0,'wlan':0})
	stop_stats=False
	stop_sniff=False
	if iface_name.startswith(('wlan', 'wlp', 'wlx')):
		if not enable_monitor_mode(iface_name):
			print(Fore.RED + Style.BRIGHT + "Cannot start without monitor mode!")
			choice = input(Fore.YELLOW + Style.BRIGHT + "Continue in managed mode? [y/N]: ").lower()
			if choice != 'y':
				return 
		monitoring_type = 'wireless'
	else:
		monitoring_type ='local'
	try:
		if monitoring_type == 'wireless':
			a_filter = "type mgt or type ctl or type data"
			if target_bssid:
				a_filter = f"wlan addr1 {target_bssid} or wlan addr2 {target_bssid} or wlan addr3 {target_bssid}"
			elif target_ssid:
				a_filter = ""
		else:
			a_filter = "ip or arp or tcp or udp or icmp"
		sniffer = AsyncSniffer(
		iface=iface_name,
		prn=analyzer,
		filter=a_filter,
		store=0,
		stop_filter=lambda _:stop_sniff
		)
		sniffer.start()
		print(Fore.GREEN + Style.BRIGHT + f"✓ Started sniffing on {iface_name}...")
		print(Fore.CYAN + Style.BRIGHT + "Press Enter to stop sniffing...")
		def update_display():
			with Live(render_table(), refresh_per_second=1, console=console) as live:
				while sniffer.running:
					live.update(render_table())
					time.sleep(0.5)
		display_thread = Thread(target=update_display)
		display_thread.daemon = True
		display_thread.start()
		input()
		stop_sniff = True
		display_thread.join(timeout=2)
	except Exception as e:
		print(Fore.RED + f"Sniffing ERROR!!!: {e}")
	finally:
		stop_sniff=True
		if sniffer and hasattr(sniffer, 'running') and sniffer.running:
			try:
				sniffer.stop()
				sniffer.join(timeout=5)
			except:
				pass
		while not write_queue.empty():
			try:
				write_queue.get_nowait()
			except:
				break
		print(Fore.YELLOW + "\nCapture stopped")
def safe_payload_display(payload):
	try:
		decoded = payload.decode('utf-8', errors='ignore')
		cleaned = ''.join(char if char.isprintable() else '.' for char in decoded)
		if len(cleaned) <= 30:
			return cleaned
		if len(cleaned) > MAX_PAYLOAD_DISPLAY:
			return cleaned[:30] + "..." + cleaned[-30:]        
		return cleaned[:MAX_PAYLOAD_DISPLAY]
	except:
		if len(payload) > 10:
			hex_dump = ' '.join(f'{byte:02x}' for byte in payload[:5])
			return f"[HEX: {hex_dump}...]"
		else:
			hex_dump = ' '.join(f'{byte:02x}' for byte in payload)
			return f"[HEX: {hex_dump}]"
def pcap_file_write(filename):
	global stop_sniff
	os.makedirs("Archives_IDS", exist_ok=True)
	filepath = os.path.join("Archives_IDS", filename)
	if not filepath.endswith('.pcap'):
		filepath += '.pcap'    
	print(Fore.GREEN + Style.BRIGHT + f"Saving PCAP session to: {filepath}")
	pcap_packets = []
	packet_count = 0
	start_time = time.time()    
	try:
		while True:
			try:
				pkt = pcap_queue.get(timeout=0.5)
				pcap_packets.append(pkt)
				packet_count += 1
				if packet_count % 100 == 0:
					wrpcap(filepath, pcap_packets, append=True)
					pcap_packets = []
			except queue.Empty:
				if stop_sniff and (time.time() - start_time > 2):
					break
				if stop_sniff:
					continue
				time.sleep(0.1)
				continue
		if pcap_packets:
			wrpcap(filepath, pcap_packets, append=True)            
			print(Fore.GREEN + f"PCAP session saved to: {filepath}")
			print(Fore.GREEN + f"Total packets in PCAP: {packet_count}")       
	except Exception as e:
		print(Fore.RED + f"Error saving PCAP file: {e}")
def file_write(filename):
	global stop_sniff
	os.makedirs("Archives_IDS",exist_ok=True)
	filepath=os.path.join("Archives_IDS",filename)
	if not filepath.endswith('.log'):
		filepath+='.log'
	print(Fore.GREEN + f"Saving session to: {filepath}")
	try:
		with open(filepath,"w",encoding='utf-8') as f:
			f.write(f"Capture started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
			f.write("=" * 60 + "\n")
			f.flush()
			packet_count=0
			start_time=time.time()
			file_size=0
			while True:
				try:
					data = write_queue.get(timeout=0.5)
					if file_size + len(data) > MAX_FILE_SIZE:
						f.write("[FILE SIZE LIMIT REACHED]\n")
						break
					f.write(data + "\n")
					f.flush()
					file_size += len(data)
					packet_count += 1
				except queue.Empty:
					if stop_sniff and (time.time() - start_time>2):
						break
					if stop_sniff:
						continue
					time.sleep(0.1)
					continue
			f.write("=" * 60 + "\n")
			f.write(f"Capture ended at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
			f.write(f"Total packets captured: {packet_count}\n")
		print(Fore.GREEN + f"Session saved to: {filepath}")
		print(Fore.GREEN + f"Total packets: {packet_count}")
	except Exception as e:
		print(Fore.RED + f"Error saving file: {e}")
def get_interface(prompt=Fore.RED + Style.BRIGHT + "Enter The InterFace Name( e.g. - wlan0 - eth0 ):"):
	interfaces=psutil.net_if_addrs()
	while True:
		interf=input(prompt).strip()
		if interf=="":
			print(Fore.RED + Style.BRIGHT + """InterFace cant by empty!!!""")
			continue
		if interf in interfaces:
			return interf
		else:
			print(Fore.RED + Style.BRIGHT + f"Invalid interface name! Available interfaces: {', '.join(interfaces.keys())}")
def get_filename(prompt=Fore.RED + Style.BRIGHT + "Enter file name to save session :"):
	while True:
		filename=input(prompt).strip()
		if filename=="":
				print(Fore.RED + Style.BRIGHT + """Filename cant by empty!!!""")
				continue
		if '/' in filename or '\\' in filename or '..' in filename:
			print(Fore.RED + "Invalid filename!")
			continue
		if len(filename) > 50:
			print(Fore.RED + "Filename too long!")
			continue
		return filename
@contextlib.contextmanager
def suppress_scapy_warnings():
	original_stdout = sys.stdout
	original_stderr = sys.stderr
	null_dev = open(os.devnull, 'w')    
	sys.stdout = null_dev
	sys.stderr = null_dev

	try:
		yield
	finally:
		sys.stdout = original_stdout
		sys.stderr = original_stderr
		null_dev.close()
def enable_monitor_mode(iface):
	"""Enable monitor mode for wireless interface - works with both built-in and external adapters"""
	try:
		print(Fore.YELLOW + f" Attempting to enable monitor mode on {iface}...")
		os.system("sudo systemctl stop NetworkManager.service 2>/dev/null")
		os.system("sudo systemctl stop wpa_supplicant.service 2>/dev/null")        
		os.system(f"sudo ip link set {iface} down 2>/dev/null")
		time.sleep(1)      
		commands = [
		f"sudo iw dev {iface} set type monitor",
		f"sudo iwconfig {iface} mode monitor",
		f"sudo airmon-ng start {iface} 2>/dev/null"
		]
		for cmd in commands:
			result = os.system(cmd + " 2>/dev/null")
			if result == 0:
				break        
		os.system(f"sudo ip link set {iface} up 2>/dev/null")
		time.sleep(2)
		check_cmds = [
		f"iwconfig {iface} | grep -i monitor",
		f"iw dev {iface} info | grep -i type"
			]
		for cmd in check_cmds:
			result = os.popen(cmd).read()
			if "monitor" in result.lower():
				print(Fore.GREEN + f" Monitor mode enabled on {iface}")
				return True
		print(Fore.RED + f"Failed to enable monitor mode on {iface}")
		return False
	except Exception as e:
		print(Fore.RED + f"Error: {e}")
		return False
def detect_all_wireless_interfaces():
	"""Detect all available wireless interfaces (both built-in and external adapters)"""
	wireless_ifaces=[]
	try:
		interfaces = os.popen("ls /sys/class/net/").read().split()
		for iface in interfaces:
			if iface in ['lo', 'eth0', 'eno1', 'ens33']:
				continue
			if iface.startswith(('wlan', 'wlp', 'wlx', 'wifi')):
				wireless_ifaces.append(iface)
			else:
				result = os.popen(f"iw dev {iface} info 2>/dev/null").read()
				if "type" in result:
					wireless_ifaces.append(iface)
		return wireless_ifaces
	except Exception as e:
		print(Fore.RED + f"Detection error: {e}")
		return []
def disable_monitor_mode(iface):
	"""Disable monitor mode and return interface to managed mode"""
	try:
		os.system(f"sudo ip link set {iface} down 2>/dev/null")
		os.system(f"sudo iwconfig {iface} mode managed 2>/dev/null")
		os.system(f"sudo iw dev {iface} set type managed 2>/dev/null")
		os.system(f"sudo ip link set {iface} up 2>/dev/null")
		print(Fore.GREEN + f"✓ Monitor mode disabled on {iface}")
		return True
	except Exception as e:
		print(Fore.RED + f"Error disabling monitor mode: {e}")
		return False
def render_table():
	global lock,packets_data,stat,monitoring_type
	terminal_size = shutil.get_terminal_size((80,30))
	max_rows_screen = terminal_size.lines - 8
	if monitoring_type=="local":
		stats_text = f"TCP: {stats.get('tcp',0)} | UDP: {stats.get('udp',0)} | HTTPS: {stats.get('https',0)} | ARP: {stats.get('arp',0)} | DNS: {stats.get('dns',0)} | Total: {stats.get('total',0)}"
	else:
		stats_text = f"WLAN: {stats.get('wlan',0)} | Total: {stats.get('total',0)}"
	table = Table(
	title=f"Live Network Traffic [{stats_text}]",
	expand=True,
	box=box.SQUARE,
	border_style="red"
	)
	col_style = "grey70"
	if monitoring_type =="local":
		table.add_column("Time", style=col_style, no_wrap=True)
		table.add_column("Proto", style=col_style)
		table.add_column("Src IP", style=col_style)
		table.add_column("Dst IP", style=col_style)
		table.add_column("Src Port", style=col_style)
		table.add_column("Dst Port", style=col_style)
		table.add_column("Info", style=col_style, width=40)
	else:
		table.add_column("Time", style=col_style, no_wrap=True)
		table.add_column("Proto", style=col_style)
		table.add_column("Src MAC", style=col_style)
		table.add_column("Dst MAC", style=col_style)
		table.add_column("BSSID", style=col_style)
		table.add_column("SSID", style=col_style)
		table.add_column("Info", style=col_style, width=40)
	with lock:
		if not packets_data:
			table.add_row("--:--:--", "WAITING", "For packets", "To arrive", "-", "-", "Listening...")
		if monitoring_type=="local":
			rows = packets_data[-max_rows_screen:]
			for pkt in rows:
				table.add_row(
				pkt["time"], 
				pkt["proto"],     
				pkt["src"], 
				pkt["dst"],
				pkt["sport"], 
				pkt["dport"], 
				pkt["info"][:50]
				)
		else:
			rows = packets_data[-max_rows_screen:]
			for pkt in rows:
				table.add_row(
				pkt["time"],
				pkt["proto"],
				pkt.get("src","N/A"),
				pkt.get("dst","N/A"),
				pkt.get("bssid","-"),
				pkt.get("ssid","-"),
				pkt.get("info","")[:50]
				)
	alerts_panel = Panel(
	"\n".join(alerts) if alerts else "No alerts yet",
	title="⚠ Alerts",
	border_style="red"
	)
	layout = Table.grid(expand=True)
	layout.add_row(table)
	layout.add_row(alerts_panel)
	return layout
	return table
def find_bssid_from_ssid(pkt, ssid):
	"""Find BSSID from SSID in beacon frames"""
	global target_bssid    
	if pkt.haslayer(Dot11Beacon):
		current_ssid = extract_ssid(pkt)
		if current_ssid == ssid:
			target_bssid = pkt.addr3
			print(Fore.GREEN + f"✓ Found target BSSID: {target_bssid} for SSID: {ssid}")
			return True
	return False
def extract_ssid(pkt):
	if pkt.haslayer(Dot11Elt):
		elt = pkt[Dot11Elt]
		while isinstance(elt, Dot11Elt):
			if elt.ID == 0 and elt.info:  # SSID element
				try:
					return elt.info.decode('utf-8', errors='ignore')
				except:
					return elt.info.hex()
			elt = elt.payload
	return ""
def is_packet_related_to_target(pkt, target_bssid):
	if not hasattr(pkt, "addr1") and not hasattr(pkt, "addr2") and not hasattr(pkt, "addr3"):
		return False       
	addrs = []
	if hasattr(pkt, 'addr1') and pkt.addr1:
		addrs.append(pkt.addr1.lower())
	if hasattr(pkt, 'addr2') and pkt.addr2:
		addrs.append(pkt.addr2.lower())
	if hasattr(pkt, 'addr3') and pkt.addr3:
		addrs.append(pkt.addr3.lower())    
	target_bssid_lower = target_bssid.lower()    
	if target_bssid_lower in addrs:
		for addr in addrs:
			if addr and addr != target_bssid_lower and addr != "ff:ff:ff:ff:ff:ff":
				associated_clients.add(addr)
		return True    
	for addr in addrs:
		if addr in associated_clients:
			return True    
	return False
alerts_dict = {
    "ARP_Spoof": {},
    "DNS_Spoof": {},
    "SYN_Flood": {},
    "UDP_Flood": {},
    "ICMP_Flood": {},
    "Port_Scan": {},
    "Deauth": {},
    "BeaconFlood": {},
    "ProbeFlood": {},
    "WPA_Handshake": {},
    "KRACK_Attack": {}
}
def play_alert_sound():
	try:
		import subprocess
		import threading
		def play_sound_thread():
			try:
				methods = [
				'echo -e "\a\a\a" > /dev/console 2>/dev/null',
				'echo -e "\a\a\a" > /dev/tty 2>/dev/null',
				'which speaker-test >/dev/null 2>&1 && timeout 0.3 speaker-test -t sine -f 1500 -l 1 >/dev/null 2>&1',
				'which aplay >/dev/null 2>&1 && echo "P" | timeout 0.2 aplay -q 2>/dev/null',
				'python3 -c "import sys; sys.stdout.buffer.write(b\'\\a\\a\\a\'); sys.stdout.flush()" >/dev/tty 2>/dev/null'
				]
				for cmd in methods:
					try:
						result = subprocess.run(cmd, shell=True, timeout=1.0, 
							stdout=subprocess.DEVNULL, 
							stderr=subprocess.DEVNULL)
						if result.returncode == 0:
							break
					except:
						continue                        
			except Exception as e:
				try:
					sys.stderr.buffer.write(b'\a\a')
					sys.stderr.flush()
				except:
					pass
			sound_thread = threading.Thread(target=play_sound_thread)
			sound_thread.daemon = True
			sound_thread.start()
	except Exception as e:
		try:
			os.system('echo -e "\a" > /dev/tty 2>/dev/null')
		except:
			pass
def trigger_alert(message):
	global last_alert_time
	current_time = time.time()
	if current_time - last_alert_time >= ALERT_COOLDOWN:
		with lock:
			if message not in alerts_shown:
				alerts.append(message)
				alerts_shown.add(message)
		play_alert_sound()
		last_alert_time = current_time
def log_alert(attack_type, src_ip, detail=""):
	if src_ip not in alerts_dict[attack_type]:
		alerts_dict[attack_type][src_ip] = {"count": 0, "details": set()}    
	alerts_dict[attack_type][src_ip]["count"] += 1
	if detail:
		alerts_dict[attack_type][src_ip]["details"].add(detail)
def log_attack(attack_type, details):
	"""Save detected attack details into Detected_Attack folder"""
	os.makedirs("Detected_Attack", exist_ok=True)
	filename_log = os.path.join("Detected_Attack", f"{attack_type}.log")
	try:
		with open(filename_log, "a", encoding="utf-8") as f:
			timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
			if filename:
				session_ref = f"(See PCAP: Archives_IDS/{filename}.pcap)"
			else:
				session_ref = "(No PCAP available)"            
			f.write(f"[{timestamp}] {details} {session_ref}\n")
	except Exception as e:
		print(Fore.RED + f"Error logging attack: {e}")
def detect_arp_spoofing(pkt):
	if not pkt.haslayer(ARP):
		return
	if pkt[ARP].op != 2:
		return
	src_ip = pkt[ARP].psrc
	src_mac = pkt[ARP].hwsrc
	if src_ip in arp_table:
		if arp_table[src_ip] != src_mac:
			alert_msg =(Fore.RED + f"⚠ ARP Spoofing detected! IP: {src_ip} "
			f"claimed {src_mac} but previous MAC: {arp_table[src_ip]}"+ Style.RESET_ALL)
			trigger_alert(alert_msg)
			log_alert(Fore.RED + "ARP_Spoof", src_ip, f"claimed {src_mac}, prev {arp_table[src_ip]}")
			log_attack("ARP_Spoof", alert_msg)
			last_syn_alert_time[src_ip] = time.time()
	else:
		arp_table[src_ip] = src_mac
def load_system_resolvers():
	resolvers = set()
	try:
		with open("/etc/resolv.conf", "r") as f:
			for line in f:
				line = line.strip()
				if line.startswith("nameserver"):
					parts = line.split()
					if len(parts) >= 2:
						resolvers.add(parts[1])
	except Exception:
		pass
	return resolvers
TRUSTED_RESOLVERS = load_system_resolvers()
def normalize_rdata(rr):
	try:
		if isinstance(rr, bytes):
			return rr.decode(errors='ignore')
		return str(rr)
	except:
		return str(rr)
def detect_dns_spoofing(pkt):
	if not pkt.haslayer(DNSRR):
		return
	now = time.time()
	src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
	try:
		rr = pkt[DNSRR]
		if pkt.haslayer(DNSQR):
			try:
				qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
			except:
				qname = str(pkt[DNSQR].qname)
		else:
			try:
				qname = rr.rrname.decode('utf-8', errors='ignore') if hasattr(rr, 'rrname') else str(rr.rrname)
			except:
				qname = str(rr.rrname)
		if not qname:
			return
		rtype = getattr(rr, 'type', None)  # رقمي (1=A, 28=AAAA, ...)
		type_key = str(rtype) if rtype is not None else 'UNKNOWN'
		rdata_str = normalize_rdata(rr.rdata) if hasattr(rr, 'rdata') else normalize_rdata(rr)
		if qname in dns_cache and now - dns_cache[qname].get('last_seen', 0) > DNS_CACHE_TTL:
			dns_cache.pop(qname, None)
		entry = dns_cache.setdefault(qname, {'types': {}, 'last_seen': now})
		types = entry['types']
		records = types.setdefault(type_key, {})
		if qname in dns_cache and now - dns_cache[qname].get('last_seen', 0) > DNS_CACHE_TTL:
			dns_cache.pop(qname, None)
		entry = dns_cache.setdefault(qname, {'types': {}, 'last_seen': now})
		types = entry['types']
		records = types.setdefault(type_key, {})
		if rdata_str in records:
			records[rdata_str]['sources'].add(src_ip)
			entry['last_seen'] = now
			return
		records[rdata_str] = {'sources': set([src_ip]), 'first_seen': now}
		entry['last_seen'] = now
		existing_values = [v for v in records.keys() if v != rdata_str]
		if not existing_values:
			return
		trusted_seen = False
		for old in existing_values:
			old_sources = records[old]['sources']
			if any(src in TRUSTED_RESOLVERS for src in old_sources):
				trusted_seen = True
				break
		if src_ip in TRUSTED_RESOLVERS:
			return
		if trusted_seen and src_ip not in TRUSTED_RESOLVERS:
			alert_msg = (Fore.RED + f"⚠ DNS Spoofing detected! {qname} (type {type_key}) conflicting values: "
			f"trusted={existing_values} <- untrusted new={rdata_str} from {src_ip}" + Style.RESET_ALL)
			trigger_alert(alert_msg)
			log_alert("DNS_Spoof", src_ip, f"{qname} -> {rdata_str}")
			log_attack("DNS_Spoof", alert_msg)
			return
		total_conflicting_sources = set()
		for val, meta in records.items():
			if now - meta.get('first_seen', now) > CONFLICT_WINDOW:
				continue
			total_conflicting_sources.update(meta['sources'])
		if len(total_conflicting_sources) >= 2:
			alert_msg = (Fore.RED + f"⚠ DNS Spoofing detected! {qname} (type {type_key}) multiple conflicting answers "
			f"from sources {sorted(list(total_conflicting_sources))}: values={list(records.keys())}" + Style.RESET_ALL)
			trigger_alert(alert_msg)
			log_alert("DNS_Spoof", src_ip, f"{qname} -> {rdata_str}")
			log_attack("DNS_Spoof", alert_msg)
			return
	except Exception:
		return
def detect_syn_flood(pkt):
	if pkt.haslayer(TCP) and pkt.haslayer(IP):
		tcp = pkt[TCP]
		ip_layer = pkt[IP]       
		if tcp.flags & 0x02:  # SYN flag
			src_ip = ip_layer.src
			current_time = time.time()            
			if src_ip not in syn_packets:
				syn_packets[src_ip] = []
			syn_packets[src_ip].append(current_time)
			syn_packets[src_ip] = [t for t in syn_packets[src_ip] if current_time - t < 5]
			if len(syn_packets[src_ip]) > SYN_FLOOD_THRESHOLD:
				alert_msg =(Fore.RED +  f"TCP SYN Flood {src_ip} ({len(syn_packets[src_ip])} SYNs)" + Style.RESET_ALL)
				trigger_alert(alert_msg)
				log_alert("SYN_Flood", src_ip, f"{len(syn_packets[src_ip])} SYNs")
				log_attack("SYN_Flood", alert_msg)
def detect_udp_flood(pkt):
	if pkt.haslayer(UDP):
		src_ip = pkt[IP].src
		current_time = time.time()        
		if src_ip not in udp_packets:
			udp_packets[src_ip] = []
		udp_packets[src_ip].append(current_time)
		udp_packets[src_ip] = [t for t in udp_packets[src_ip] if current_time - t < 1]
		if len(udp_packets[src_ip]) > UDP_FLOOD_THRESHOLD:
			alert_msg =(Fore.RED + f"⚠ UDP Flood detected from {src_ip} ({len(udp_packets[src_ip])} packets)" + Style.RESET_ALL)
			trigger_alert(alert_msg)
			log_alert("UDP_Flood", src_ip, f"{len(udp_packets[src_ip])} packets")
			log_attack("UDP_Flood", alert_msg)
def detect_icmp_flood(pkt):
	if pkt.haslayer(ICMP):
		src_ip = pkt[IP].src
		current_time = time.time()        
		if src_ip not in icmp_packets:
			icmp_packets[src_ip] = []        
		icmp_packets[src_ip].append(current_time)        
		icmp_packets[src_ip] = [t for t in icmp_packets[src_ip] if current_time - t < 1]     
		if len(icmp_packets[src_ip]) > ICMP_FLOOD_THRESHOLD:
			alert_msg =(Fore.RED + f"⚠ ICMP Flood detected from {src_ip} ({len(icmp_packets[src_ip])} packets)" + Style.RESET_ALL)
			trigger_alert(alert_msg)
			log_alert("ICMP_Flood", src_ip, f"{len(icmp_packets[src_ip])} packets")
			log_attack("ICMP_Flood", alert_msg)
def detect_port_scan(pkt):
	if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
		return
	tcp = pkt[TCP]
	ip_layer = pkt[IP]
	flags = tcp.flags
	is_syn = False
	try:
		is_syn = bool(flags & 0x02)
	except Exception:
		if str(flags) == 'S':
			is_syn = True
	if not is_syn:
		return
	src_ip = ip_layer.src
	dst_port = tcp.dport
	current_time = time.time()
	if src_ip not in scan_attempts:
		scan_attempts[src_ip] = {'ports': set(), 'start_time': current_time}
	scan_attempts[src_ip]['ports'].add(dst_port)
	time_window = current_time - scan_attempts[src_ip]['start_time']
	if len(scan_attempts[src_ip]['ports']) > PORT_SCAN_THRESHOLD and time_window < 10:
		ports = scan_attempts[src_ip]['ports']
		alert_msg =(Fore.YELLOW + f"⚠ Port Scan detected from {src_ip} (scanned {len(ports)} ports)" + Style.RESET_ALL)
		trigger_alert(alert_msg)
		log_alert("Port_Scan", src_ip, f"Scanned ports: {sorted(list(ports))}")
		log_attack("Port_Scan", alert_msg)
		scan_attempts[src_ip] = {'ports': set(), 'start_time': current_time}  # reset after alert
	if time_window > 10:
		scan_attempts[src_ip] = {'ports': set(), 'start_time': current_time}
def detect_deauth(pkt):
	if pkt.haslayer(Dot11Deauth):
		src = pkt.addr2 or "unknown"
		dst = pkt.addr1 or "broadcast"
		alert_msg = Fore.RED + f"⚠ Deauthentication attack detected! {src} -> {dst}" + Style.RESET_ALL
		trigger_alert(alert_msg)
		log_alert("Deauth", src, f"target:{dst}")
		log_attack("Deauth", alert_msg)
def detect_beacon_flood(pkt):
	if not pkt.haslayer(Dot11Beacon):
		return
	ssid = extract_ssid(pkt) or "<hidden>"
	bssid = (pkt.addr2 or "").lower()
	prev = beacon_cache.get(ssid)
	if prev and prev != bssid:
		alert_msg = Fore.RED + f"⚠ Beacon Flood / Fake AP detected! SSID: {ssid} BSSID: {prev} -> {bssid}" + Style.RESET_ALL
		trigger_alert(alert_msg)
		log_alert("BeaconFlood", bssid, f"SSID:{ssid}")
		log_attack("BeaconFlood", alert_msg)
	else:
		beacon_cache[ssid] = bssid
def detect_probe_flood(pkt):
	if not pkt.haslayer(Dot11ProbeReq):
		return
	src = (pkt.addr2 or "").lower()
	probe_count[src] = probe_count.get(src, 0) + 1
	if probe_count[src] > 50:
		alert_msg = Fore.RED + f"⚠ Probe Request Flood detected from {src} (count={probe_count[src]})" + Style.RESET_ALL
		trigger_alert(alert_msg)
		log_alert("ProbeFlood", src, f"count:{probe_count[src]}")
		log_attack("ProbeFlood", alert_msg)
def detect_handshake(pkt):
	if pkt.haslayer(EAPOL):
		src = (pkt.addr2 or "").lower()
		dst = (pkt.addr1 or "").lower()
		handshake_count[src] = handshake_count.get(src, 0) + 1
		if handshake_count[src] >= 2:
			alert_msg = Fore.RED + f"⚠ WPA Handshake detected from {src} -> {dst} (count={handshake_count[src]})" + Style.RESET_ALL
			trigger_alert(alert_msg)
			log_alert("WPA_Handshake", src, f"target:{dst},count:{handshake_count[src]}")
			log_attack("WPA_Handshake", alert_msg)
def detect_krack_attack(pkt):
	if pkt.haslayer(EAPOL):
		eapol = pkt[EAPOL] 
	if hasattr(eapol, 'key_replay_counter'):
		src_mac = pkt.addr2.lower()
		if src_mac not in krack_monitor:
			krack_monitor[src_mac] = {'last_counter': eapol.key_replay_counter, 'count': 0}            
		if eapol.key_replay_counter == krack_monitor[src_mac]['last_counter']:
			krack_monitor[src_mac]['count'] += 1                
		if krack_monitor[src_mac]['count'] > 2:
			alert_msg = (Fore.RED + f"⚠ KRACK attack detected! "
			f"Source: {src_mac} (Replayed key {krack_monitor[src_mac]['count']} times)" + Style.RESET_ALL)
			trigger_alert(alert_msg)
			log_alert("KRACK_Attack", src_mac, f"replay_count:{krack_monitor[src_mac]['count']}")
			log_attack("KRACK_Attack", alert_msg)
		else:
			krack_monitor[src_mac]['last_counter'] = eapol.key_replay_counter
			krack_monitor[src_mac]['count']=0
def analyzer(pkt):
	global summary,filename,packet_buffer,seen_packets,packets_data,stats,save_session,write_queue,tcp_count,udp_count,arp_count,icmp_count,dns_count,raw_count,total_count,https_count,lock,wlan_count,target_bssid,target_ssid
	if not pkt or len(pkt) < 14: 
		return
	if monitoring_type == 'wireless' and target_ssid and not target_bssid:
		if find_bssid_from_ssid(pkt, target_ssid):
			return
	if monitoring_type == 'wireless' and target_bssid:
		if not is_packet_related_to_target(pkt, target_bssid):
			return
	try:
		if pkt.haslayer(RadioTap) or pkt.haslayer(Dot11):
			handle_wireless_packet(pkt)
			return
		if monitoring_type == 'local':
			if pkt.haslayer(ARP):
				detect_arp_spoofing(pkt)
			if pkt.haslayer(DNSRR):
				detect_dns_spoofing(pkt)
			if pkt.haslayer(TCP) and pkt.haslayer(IP):
				detect_syn_flood(pkt)
				detect_port_scan(pkt)
			if pkt.haslayer(UDP) and pkt.haslayer(IP):
				detect_udp_flood(pkt)
			if pkt.haslayer(ICMP) and pkt.haslayer(IP):
				detect_icmp_flood(pkt)
		else:
			detect_deauth(pkt)
			detect_beacon_flood(pkt)
			detect_probe_flood(pkt)
			detect_handshake(pkt)
			detect_krack_attack(pkt)
		timestamp = datetime.now().strftime("%H:%M:%S")
		src_ip = dst_ip = "N/A"
		sport = dport = "-"
		proto = "OTHER"
		info=""
		src_mac = dst_mac = "N/A"
		if pkt.haslayer(Ether):
			src_mac, dst_mac = pkt[Ether].src, pkt[Ether].dst
		if pkt.haslayer(IP):
			src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
			if pkt.haslayer(TCP):
				sport, dport = pkt[TCP].sport, pkt[TCP].dport
				if sport == 443 or dport == 443:
					proto, info = "HTTPS", "Encrypted TLS traffic"
					https_count+=1
					stats["https"]=https_count
				else:
					proto = "TCP"
				tcp_count += 1
				stats["tcp"]=tcp_count
		elif pkt.haslayer(UDP):
			proto = "UDP"
			sport, dport = pkt[UDP].sport, pkt[UDP].dport
			udp_count += 1
			stats["udp"]=udp_count
		elif pkt.haslayer(ICMP):
			proto = "ICMP"
			icmp_count += 1
			stats["icmp"]=icmp_count
		elif pkt.haslayer(ARP):
			proto = "ARP"
			src_ip = pkt[ARP].psrc
			dst_ip = pkt[ARP].pdst
			arp_count += 1
			stats["arp"]=arp_count
		if pkt.haslayer(DNS):
			proto = "DNS"
			try:
				if pkt.haslayer(DNSQR):
					dns_query = pkt[DNSQR].qname.decode(errors='ignore')
					info = f"DNS Query: {dns_query}"
			except:
				info = "DNS Packet"
			dns_count+=1
			stats["dns"]=dns_count
		elif pkt.haslayer(Raw) and not info:
			info = safe_payload_display(pkt[Raw].load)
			if proto == "OTHER":
				proto = "RAW"
			raw_count += 1
		total_count += 1
		stats["total"]=total_count
		row = {
			"time": timestamp,
			"proto": proto,
			"src": src_ip,
			"dst": dst_ip,
			"sport": str(sport),
			"dport": str(dport),
			"info": info
			}
		with lock:
			packets_data.append(row)
			if len(packets_data) > MAX_ROWS:
				packets_data.pop(0)
		if len(packet_buffer) > MAX_BUFFER_SIZE*2:
			oldest_packet=packet_buffer.pop(0)
			if hasattr(oldest_packet, 'src') and hasattr(oldest_packet, 'dst'):
				sport = oldest_packet.sport if hasattr(oldest_packet, 'sport') else '0'
				dport = oldest_packet.dport if hasattr(oldest_packet, 'dport') else '0'
				oldest_signature = f"{oldest_packet.src}-{oldest_packet.dst}-{sport}-{dport}"
				seen_packets.discard(oldest_signature)
		if hasattr(pkt, 'src') and hasattr(pkt, 'dst'):
			sport = pkt.sport if hasattr(pkt, 'sport') else '0'
			dport = pkt.dport if hasattr(pkt, 'dport') else '0'
			packet_signature = f"{pkt.src}-{pkt.dst}-{sport}-{dport}"
			if packet_signature not in seen_packets:
				seen_packets.add(packet_signature)
				packet_buffer.append(pkt)    
		if len(seen_packets)>MAX_SEEN_PACKETS:
			seen_packets.clear()
		if save_session:
			timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
			summary = f"{timestamp} | {proto} | {src_ip}:{sport} -> {dst_ip}:{dport} | Len:{len(pkt)}"
			if pkt.haslayer(Raw):
				try:
					payload = pkt[Raw].load.decode('utf-8', errors='ignore')
					summary += f" | Payload: {payload[:50]}..."
				except:
					summary += " | Payload: [unreadable]"
			write_queue.put(summary)
		if save_pcap_session:
			try:
				pcap_queue.put_nowait(pkt)
			except queue.Full:
				pass
	except Exception as e:
		if "Malformed" in str(e):
			return
		return
def handle_wireless_packet(pkt):
	"""Handle 802.11 wireless packets in monitor mode"""
	global total_count, stats, packets_data,lock,wlan_count,target_bssid,target_ssid
	total_count += 1
	stats["total"] = total_count    
	if pkt.haslayer(Dot11):
		wlan_count+=1
		stats["wlan"]=wlan_count
		dot11 = pkt[Dot11]
		proto = "WLAN"
		info = ""        
		bssid = "N/A"
		ssid = "N/A"
		if hasattr(dot11, 'addr3'):
			bssid = dot11.addr3        
		if target_bssid and not is_packet_related_to_target(pkt, target_bssid):
			return
		if pkt.haslayer(Dot11Beacon):
			info = "Beacon Frame"
			try:
				elt = pkt[Dot11Elt]
				while isinstance(elt, Dot11Elt):
					if elt.ID == 0:  # SSID
						try:
							ssid = elt.info.decode('utf-8', errors='ignore')
							if ssid:
								info += f" - SSID: {ssid}"
						except:
							pass
					elt = elt.payload
			except:
				pass
		elif pkt.haslayer(Dot11ProbeReq):
			info = "Probe Request"
		elif pkt.haslayer(Dot11ProbeResp):
			info = "Probe Response"
		elif pkt.haslayer(Dot11Auth):
			info = "Authentication"
		elif pkt.haslayer(Dot11Deauth):
			info = "Deauthentication"
		else:
			info = f"802.11 Type: {dot11.type} Subtype: {dot11.subtype}"        
		row = {
		"time": datetime.now().strftime("%H:%M:%S"),
		"proto": proto,
		"src": dot11.addr2 if hasattr(dot11, 'addr2') else "N/A",
		"dst": dot11.addr1 if hasattr(dot11, 'addr1') else "N/A",
		"bssid": bssid,
		"ssid": ssid,
		"info": info
		}
		with lock:
			packets_data.append(row)
			if len(packets_data) > MAX_ROWS:
				packets_data.pop(0)
		if hasattr(pkt, 'addr2') and hasattr(pkt, 'addr1'):
			packet_signature = f"{pkt.addr2}-{pkt.addr1}"
			if packet_signature not in seen_packets:
				seen_packets.add(packet_signature)
				packet_buffer.append(pkt)
			if len(seen_packets) > MAX_SEEN_PACKETS:
				seen_packets.clear()
		src_mac = dot11.addr2 if hasattr(dot11, 'addr2') else "N/A"
		dst_mac = dot11.addr1 if hasattr(dot11, 'addr1') else "N/A"
		if save_session:
			timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
			summary = f"{timestamp} | {proto} | {src_mac} -> {dst_mac} | Info: {info}"
			write_queue.put(summary)
		if save_pcap_session:
			try:
				pcap_queue.put_nowait(pkt)
			except queue.Full:
				pass

logo =(Fore.RED + r"""
		   ....                                                            
             -%@@@@@@@@@@@%-                                                      
          .#@@@@@@@@@@@@@@@@@%:                                                   
        .*@@@@@@@@@@@@@@@@@@@@@#                                                  
        #@@@@@@:         .%@@@@@@.                                                
       #@@@@@*             *@@@@@#.                                               
      -@@@@@%.             .@@@@@@-                                               
      =@@@@@#.              @@@@@@=                                               
      +@@@@@#.              @@@@@@=                                               
      +@@@@@#.              @@@@@@=                                               
      +@@@@@#.              @@@@@@+                                               
      +@@@@@#.              @@@@@@+                                               
 :%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+                            :*@@@@%+.     
-@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%.                        +@@@@@@@@@@%:   
+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@-                       %@@@@:. =%@@@@  
@@@@@@@@@@@@@@@@@===+%@@@@@=::-::--::-:                      .  @@@@*      :%@@@+ 
@@@@@@@@@@@@@@@=        .@@@:  -=++==++==+++=++==+++++++++++++%@@@*:          %@@@:
@@@@@@@@@@@@@@+.         .%@@: #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.           +@@@
*@@@@@@@@@@@@@@.          #@@: #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%           =@@@#
*@@@@@@@@@@@@@@#.        :@@@: #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.          =@@@#
#@@@@@@@@@@@@@@@#.     .@@@@: +#%@@@@@@%##%@@@@@#############%@@@@=         .#@@@=
@@@@@@@@@@@@@@@@@:      .:@@@@=-. -@@@@@@+  =@@@@#            -@@@@=       *@@@# 
*@@@@@@@@@@@@@@%:        +@@@@@= -@@@@@@+  =@@@@#               -@@@@#:,-@@@@%: 
@@@@@@@@@@@@@@+          .#@@@@=-@@@@@@+  :====-                :%@@@@@@@@@@@.  
@@@@@@@@@@@@@@            -@@@@= :%%%%%%=                          :%@@@@@@@.    
*@@@@@@@@@@@@@:            #@@@=                                       ..         
*@@@@@@@@@@@@@%%%%%%%%%%%%%@@@@@@@@@@@@@@:                                        
*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:                                        
=@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%:                                        
 =@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:                                         
    .   .   .   .   .   .   .   .                                       
"""+ Style.RESET_ALL)
def show_logo():
    for line in logo.split("\n"):
        print(Fore.RED + line)
        time.sleep(0.15)
    time.sleep(1.5)  
    os.system('clear')
show_logo()
def banner():
	print(Fore.RED + Style.BRIGHT +  r"""

					██████████████████████████████████████████	
					█▒▒▒▒▒▒▒▒▒▒█▒▒▒▒▒▒▒▒▒▒▒▒███▒▒▒▒▒▒▒▒▒▒▒▒▒▒█	[1]- Local Device Monitoring  (eth0)		
					█▒▒▄▀▄▀▄▀▒▒█▒▒▄▀▄▀▄▀▄▀▒▒▒▒█▒▒▄▀▄▀▄▀▄▀▄▀▒▒█	
					█▒▒▒▒▄▀▒▒▒▒█▒▒▄▀▒▒▒▒▄▀▄▀▒▒█▒▒▄▀▒▒▒▒▒▒▒▒▒▒█	[2]- Wireless Monitoring Mode (wlan0 - monitor)
					███▒▒▄▀▒▒███▒▒▄▀▒▒██▒▒▄▀▒▒█▒▒▄▀▒▒█████████	( Operates in monitor mode )
					███▒▒▄▀▒▒███▒▒▄▀▒▒██▒▒▄▀▒▒█▒▒▄▀▒▒▒▒▒▒▒▒▒▒█
					███▒▒▄▀▒▒███▒▒▄▀▒▒██▒▒▄▀▒▒█▒▒▄▀▄▀▄▀▄▀▄▀▒▒█	
					███▒▒▄▀▒▒███▒▒▄▀▒▒██▒▒▄▀▒▒█▒▒▒▒▒▒▒▒▒▒▄▀▒▒█	[99]- Help
					███▒▒▄▀▒▒███▒▒▄▀▒▒██▒▒▄▀▒▒█████████▒▒▄▀▒▒█
					█▒▒▒▒▄▀▒▒▒▒█▒▒▄▀▒▒▒▒▄▀▄▀▒▒█▒▒▒▒▒▒▒▒▒▒▄▀▒▒█	
					█▒▒▄▀▄▀▄▀▒▒█▒▒▄▀▄▀▄▀▄▀▒▒▒▒█▒▒▄▀▄▀▄▀▄▀▄▀▒▒█
					█▒▒▒▒▒▒▒▒▒▒█▒▒▒▒▒▒▒▒▒▒▒▒███▒▒▒▒▒▒▒▒▒▒▒▒▒▒█	[00]- Exit
					██████████████████████████████████████████
""" + Style.RESET_ALL)
while True:
	os.system("clear")
	banner()
	choix=input(Fore.RED + Style.BRIGHT + "Enter your choice==========> :" + Style.RESET_ALL)
	if choix=="1":
		iface_name=get_interface()
		save=input(Fore.RED + Style.BRIGHT + "Do you want to save the session ? [Y=Yes / N=Non ]:"+ Style.RESET_ALL).strip().upper()
		file_thread=None
		with lock:
			packets_data.clear()
		seen_packets.clear()
		packet_buffer.clear()
		tcp_count = udp_count = arp_count = icmp_count = https_count = raw_count = dns_count = total_count = 0
		stats = {'total':0, 'tcp':0, 'udp':0, 'icmp':0, 'arp':0,'https':0, 'dns':0,'wlan':0}
		if save=="Y":
			fmt = input(Fore.RED + Style.BRIGHT+ "Choose format to save [log/pcap] (pcap If you want to analyze the file in Wireshark): "+ Style.RESET_ALL).strip().lower()
			if fmt=="":
				print(Fore.RED + Style.BRIGHT + """Format  cant by empty!!!""")
				continue
			if fmt=="log":
				filename=get_filename()
				save_session=True
				stop_sniff = False
				while not write_queue.empty():
					try:
						write_queue.get_nowait()
					except queue.Empty:
						break
				file_thread = Thread(target=file_write, args=(filename,))
				file_thread.daemon = True
				file_thread.start()
				print(Fore.GREEN + "Session saving enabled...")
			elif fmt=="pcap":
				filename = get_filename()
				save_pcap_session = True
				stop_sniff = False
				while not pcap_queue.empty():
					try:
						pcap_queue.get_nowait()
					except queue.Empty:
						break    
				pcap_thread = Thread(target=pcap_file_write, args=(filename,))
				pcap_thread.daemon = True
				pcap_thread.start()
				print(Fore.GREEN + Style.BRIGHT + "PCAP session saving enabled...")
		else:
			save_session=False
			save_pcap_session = False
		os.system("clear")
		start_sniffing(iface_name)
		if save_session and file_thread:
			stop_sniff = True
			file_thread.join(timeout=10)
			print(Fore.GREEN + Style.BRIGHT + "Session saved successfully"+ Style.RESET_ALL)
		if save_pcap_session and pcap_thread:
			stop_sniff = True
			pcap_thread.join(timeout=10)
			print(Fore.GREEN + Style.BRIGHT + "PCAP session saved successfully"+ Style.RESET_ALL) 
		input(Fore.YELLOW + "\nPress Enter to return to main menu..."+ Style.RESET_ALL)
	if choix=="2":
		iface_name=get_interface()
		target_bssid = input(Fore.RED + Style.BRIGHT+ "Enter target BSSID (leave empty if not known): "+ Style.RESET_ALL).strip()
		target_ssid = None
		if not target_bssid:
    			target_ssid = input(Fore.RED + Style.BRIGHT + "Enter target SSID: "+ Style.RESET_ALL).strip()
		save=input(Fore.RED + Style.BRIGHT + "Do you want to save the session ? [Y=Yes / N=Non ]:"+ Style.RESET_ALL).strip().upper()
		file_thread=None
		with lock:
			packets_data.clear()
		seen_packets.clear()
		packet_buffer.clear()
		stats = {'total':0, 'tcp':0, 'udp':0, 'icmp':0, 'arp':0,'https':0, 'dns':0,'wlan':0}
		if save=="Y":
			fmt = input(Fore.RED + Style.BRIGHT + "Choose format to save [log/pcap] (pcap If you want to analyze the file in Wireshark): "+ Style.RESET_ALL).strip().lower()
			if fmt=="":
				print(Fore.RED + Style.BRIGHT + """Format  cant by empty!!!""")
			if fmt=="log":
				filename=get_filename()
				save_session=True
				stop_sniff = False
				while not write_queue.empty():
					try:
						write_queue.get_nowait()
					except queue.Empty:
						break
				file_thread = Thread(target=file_write, args=(filename,))
				file_thread.daemon = True
				file_thread.start()
				print(Fore.GREEN + Style.BRIGHT + "Session saving enabled..."+ Style.RESET_ALL)
			elif fmt=="pcap":
				filename = get_filename()
				save_pcap_session = True
				stop_sniff = False
				while not pcap_queue.empty():
					try:
						pcap_queue.get_nowait()
					except queue.Empty:
						break    
				pcap_thread = Thread(target=pcap_file_write, args=(filename,))
				pcap_thread.daemon = True
				pcap_thread.start()
				print(Fore.GREEN + Style.BRIGHT + "PCAP session saving enabled..."+ Style.RESET_ALL)
		else:
			save_session=False
			save_pcap_session = False
		os.system("clear")
		start_sniffing(iface_name)
		if save_session and file_thread:
			stop_sniff = True
			file_thread.join(timeout=10)
			print(Fore.GREEN + Style.BRIGHT + "Session saved successfully")
		if save_pcap_session and pcap_thread:
			stop_sniff = True
			pcap_thread.join(timeout=10)
			print(Fore.GREEN + Style.BRIGHT + "PCAP session saved successfully") 
		input("\nPress Enter to return to main menu..."+ Style.RESET_ALL)
		os.system("clear")
	elif choix=="00":
		interfaces = detect_all_wireless_interfaces()
		for iface in interfaces:
			disable_monitor_mode(iface)
		os.system("sudo systemctl start NetworkManager.service 2>/dev/null")
		os.system("sudo systemctl start wpa_supplicant.service 2>/dev/null")
		if save_session and session_file and not session_file.closed:
			session_file.close()
		print("Exiting .....")
		break
	elif choix == "99":
		os.system("clear")
		print(Fore.RED + Style.BRIGHT + """
╔══════════════════════════════════════════════════════════════════╗
║                     HELP - IDS MONITOR                           ║
╠══════════════════════════════════════════════════════════════════╣
║ [1] Local Device Monitoring (eth0)                               ║
║     ➤ Monitor wired network interfaces                          ║
║     ➤ Detect: ARP spoofing, DNS spoofing                        ║
║     ➤ Detect: SYN/UDP/ICMP floods, port scanning                ║
║     ➤ Save sessions as log or PCAP format                       ║
║                                                                  ║
║ [2] Wireless Monitoring Mode (wlan0 - monitor)                   ║
║     ➤ Monitor wireless networks (requires monitor mode)         ║
║     ➤ Detect: Deauth attacks, beacon floods                     ║
║     ➤ Detect: KRACK attacks, WPA handshakes                     ║
║     ➤ Target specific BSSID or SSID                             ║
║                                                                  ║
║ 											                       ║
║    										                       ║
║   									                           ║
║                                                                  ║
║ [00] Exit                                                        ║
║     ➤ Exit and restore network interfaces                       ║
║                                                                  ║
║ DETECTION CAPABILITIES:                                          ║
║ • ARP Spoofing    • DNS Spoofing    • SYN Flood                  ║
║ • UDP Flood       • ICMP Flood      • Port Scan                  ║
║ • Deauth Attacks  • Beacon Flood    • Probe Flood                ║
║ • WPA Handshake   • KRACK Attack    • Evil Twin                  ║
║                                                                  ║
║ REQUIREMENTS:                                                    ║
║ • Root privileges                                                ║
║ • Wireless card supporting monitor mode                          ║
║ • Python packages: scapy, colorama, rich, psutil                 ║
╚══════════════════════════════════════════════════════════════════╝
""" + Style.RESET_ALL)
		input(Fore.RED + "\nPress Enter to continue..." + Style.RESET_ALL)
