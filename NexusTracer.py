import sys
import time
import getpass
import re
import traceback
import os
import csv
import logging
import tempfile
import paramiko
from netmiko import ConnectHandler

# ==========================================
# LOGGING CONFIGURATION
# ==========================================
logging.basicConfig(
    filename='nexus_tracer.log',
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# ==========================================
# UTILITY CLASS
# ==========================================
class Utils:
    @staticmethod
    def clear_screen():
        os.system('cls' if os.name == 'nt' else 'clear')

    @staticmethod
    def flush_buffer():
        """ מנקה את זיכרון המקלדת מכל הלחיצות הישנות כדי למנוע קלטים שגויים """
        try:
            import msvcrt
            while msvcrt.kbhit():
                msvcrt.getch()
        except ImportError:
            pass

    @staticmethod
    def ask_yes_no(prompt):
        Utils.flush_buffer()
        while True:
            ans = input(prompt).strip().lower()
            if ans in ['y', 'yes']: return True
            if ans in ['n', 'no']: return False
            print("    [!] Invalid input. Please enter 'y' or 'n'.")

    @staticmethod
    def ask_int_choice(prompt, min_val, max_val):
        Utils.flush_buffer()
        while True:
            ans = input(prompt).strip()
            if ans.isdigit():
                val = int(ans)
                if min_val <= val <= max_val: return val
            print(f"    [!] Invalid input. Please select a number between {min_val} and {max_val}.")

    @staticmethod
    def pause_and_return(msg=""):
        if msg: print(msg)
        Utils.flush_buffer()
        while True:
            ans = input("\n[?] Press [ENTER] or [M] for Main Menu, or [Q] to Quit: ").strip().lower()
            if ans in ['q', 'quit']:
                print("\n[!] Exiting Nexus Tracer. See ya!")
                time.sleep(1)
                sys.exit(0)
            elif ans in ['m', '']:
                break

    @staticmethod
    def format_mac_for_cisco(mac_address):
        mac_clean = mac_address.replace(':', '').replace('-', '').replace('.', '')
        return f"{mac_clean[:4]}.{mac_clean[4:8]}.{mac_clean[8:]}".lower()

# ==========================================
# CREDENTIALS MANAGER (UNIFIED KEYCHAIN)
# ==========================================
class CredentialVault:
    def __init__(self):
        self.pa_creds = []
        self.sw_creds = []
        self.cp_creds = []

    def add_pa(self, u, p):
        if (u, p) not in self.pa_creds: self.pa_creds.insert(0, (u, p))

    def add_sw(self, u, p):
        if (u, p) not in self.sw_creds: self.sw_creds.insert(0, (u, p))

    def add_cp(self, u, p, exp):
        if (u, p, exp) not in self.cp_creds: self.cp_creds.insert(0, (u, p, exp))

# ==========================================
# REPORT GENERATOR (NORMALIZED UNIFIED DATA)
# ==========================================
class ReportGenerator:
    @staticmethod
    def print_unified_cli(results):
        txt_report = "\n" + "="*125 + "\n"
        txt_report += f"{'FW IP'.ljust(16)} | {'VENDOR'.ljust(12)} | {'STATUS'.ljust(18)} | {'EDGE DEVICE'.ljust(25)} | {'PORT'.ljust(20)}\n"
        txt_report += "="*125 + "\n"
        for res in results:
            fw_ip = res.get('FW_IP', 'N/A').ljust(16)
            vendor = res.get('Vendor', 'Unknown').ljust(12)
            status = res.get('Status', 'Failed').ljust(18)
            target = res.get('Target_Device', 'N/A')[:24].ljust(25)
            port = res.get('Target_Port', 'N/A')[:19].ljust(20)
            
            txt_report += f"{fw_ip} | {vendor} | {status} | {target} | {port}\n"
            
            if res.get('Status') == 'Success':
                ip_str = res.get('Target_IP', 'N/A').ljust(16)
                model_str = res.get('Target_Model', 'N/A')
                txt_report += f"{''.ljust(16)} | {''.ljust(12)} | {''.ljust(18)} | IP: {ip_str} | Model: {model_str}\n"
            
            txt_report += "-"*125 + "\n"
            
        print(txt_report)
        with open("unified_discovery_report.txt", "w", encoding='utf-8') as f:
            f.write(txt_report)
        logging.info("Saved text report to unified_discovery_report.txt")

    @staticmethod
    def save_csv(results, filename):
        if not results:
            return

        fieldnames = ["FW_IP", "FW_Hostname", "Vendor", "Status", "Target_Device", "Target_Port", "Target_IP", "Target_Model", "Target_Version"]

        def write_path(path):
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(results)

        try:
            write_path(filename)
            print(f"[V] SCAN COMPLETE! Excel-ready report saved to '{filename}'")
            logging.info(f"Saved CSV report to {filename}")
        except PermissionError:
            fallback_path = os.path.join(os.path.expanduser('~'), os.path.basename(filename))
            try:
                write_path(fallback_path)
                print(f"[!] Permission denied writing to '{filename}'. Saved report to '{fallback_path}' instead.")
                logging.warning(f"Permission denied writing {filename}; saved to {fallback_path} instead.")
            except Exception as e:
                temp_path = os.path.join(tempfile.gettempdir(), os.path.basename(filename))
                try:
                    write_path(temp_path)
                    print(f"[!] Permission denied writing to '{filename}'. Saved report to '{temp_path}' instead.")
                    logging.warning(f"Permission denied writing {filename}; saved to {temp_path} instead.")
                except Exception as final_exc:
                    print(f"[X] Failed to save CSV report: {final_exc}")
                    logging.error(f"Failed to save CSV report to '{filename}', '{fallback_path}', and '{temp_path}'.", exc_info=True)
        except Exception as e:
            print(f"[X] Failed to save CSV report: {e}")
            logging.error(f"Failed to save CSV report to {filename}.", exc_info=True)

# ==========================================
# CISCO L2/L3 TRACER CLASS (RESTORED AUTH LOOP)
# ==========================================
class CiscoTracer:
    def __init__(self, start_ip, cisco_mac, fw_ip, vault, keepalive_cb=None):
        self.current_ip = start_ip
        self.cisco_mac = cisco_mac
        self.fw_ip = fw_ip
        self.vault = vault
        self.keepalive_cb = keepalive_cb
        self.visited_ips = set()
        self.hop_count = 0
        self.loop_mitigation_active = False
        self.result = {"Target_Device": "N/A", "Target_Port": "N/A", "Target_IP": "N/A", "Target_Model": "N/A", "Target_Version": "N/A"}

    def trace(self):
        logging.info(f"Initiating Cisco L2/L3 trace starting at {self.current_ip}")
        print(f"\n    [*] Starting switch trace from Default Gateway: {self.current_ip}")
        
        while self.current_ip:
            self.hop_count += 1
            if self.hop_count > 20:
                print(f"    [X] Hop limit (20) exceeded! Halting to prevent infinite loop.")
                self.result["Status"] = "Hop Limit Exceeded"
                return self.result

            if self.current_ip in self.visited_ips:
                if not self.loop_mitigation_active:
                    print(f"    [!] MAC Routing Loop detected at {self.current_ip}! Forcing L3 ARP resolution to break loop...")
                    self.loop_mitigation_active = True
                    self.visited_ips.remove(self.current_ip)
                else:
                    print(f"    [X] Hard Loop detected at {self.current_ip} even with ARP fallback. Ending trace.")
                    logging.error(f"Routing loop detected at {self.current_ip}.")
                    self.result["Status"] = "Routing Loop Detected"
                    return self.result
            else:
                self.visited_ips.add(self.current_ip)
                
            sw_conn = None
            
            if self.keepalive_cb:
                print(f"    [*] Waking up MAC/ARP tables (Sending Ping from FW...)")
                self.keepalive_cb()

            # חזרנו ללולאת ה-while הישנה והטובה שמונעת קריסות רקורסיה
            auth_success = False
            while not auth_success:
                for u, p in self.vault.sw_creds:
                    sw_device = {
                        'device_type': 'cisco_ios', 
                        'host': self.current_ip, 
                        'username': u, 
                        'password': p,
                        'conn_timeout': 15, 
                        'auth_timeout': 15  
                    }
                    try:
                        print(f"    -> Attempting connection to Switch {self.current_ip} with user '{u}'...")
                        sw_conn = ConnectHandler(**sw_device)
                        print(f"    [V] Connected to {self.current_ip}")
                        auth_success = True
                        break 
                    except Exception as e:
                        error_str = str(e).lower()
                        if "auth" in error_str or "password" in error_str or "login" in error_str:
                            continue 
                        else:
                            e_str = str(e).strip()
                            err_msg = e_str.splitlines()[-1] if e_str else "[Unknown Exception Context]"
                            print(f"    [X] Network Error to Switch {self.current_ip}: {err_msg}")
                            self.result["Status"] = f"Conn Error @ {self.current_ip}"
                            return self.result
                
                if not auth_success:
                    print(f"\n[!] All known credentials failed for Switch {self.current_ip}.")
                    if Utils.ask_yes_no(f"    Enter new Cisco credentials for {self.current_ip}? (y/n): "):
                        new_u = input(f"    New User for {self.current_ip}: ")
                        new_p = getpass.getpass(f"    New Password: ")
                        self.vault.add_sw(new_u, new_p)
                        continue # ממשיך את הלולאה כדי לנסות את הסיסמה החדשה ללא רקורסיה
                    else:
                        print(f"    [X] Giving up on {self.current_ip} due to auth failure.")
                        self.result["Status"] = f"Auth Error @ {self.current_ip}"
                        return self.result

            try:
                port = ""; mac_found = False

                if not self.loop_mitigation_active:
                    logging.info(f"Checking MAC table on {self.current_ip} for {self.cisco_mac}")
                    mac_out = sw_conn.send_command(f"show mac address-table address {self.cisco_mac}")
                    if not mac_out or self.cisco_mac not in mac_out.lower():
                        mac_out = sw_conn.send_command(f"show mac-address-table address {self.cisco_mac}")
                    if not mac_out or self.cisco_mac not in mac_out.lower():
                        mac_out = sw_conn.send_command(f"show mac address-table | include {self.cisco_mac}")

                    if mac_out and self.cisco_mac in mac_out.lower():
                        lines = [l.strip() for l in mac_out.splitlines() if self.cisco_mac in l.lower()]
                        if lines:
                            port = lines[0].split()[-1]
                            mac_found = True
                            print(f"    [V] Found in MAC Table (L2) on port: {port}")

                if not mac_found or self.loop_mitigation_active:
                    if self.loop_mitigation_active:
                        print(f"    [*] Loop Mitigation Mode: Bypassing MAC and checking ARP table directly...")
                    else:
                        print(f"    [*] MAC not found in L2. Trying ARP table (L3 Routing) fallback...")
                        
                    arp_out = sw_conn.send_command(f"show ip arp | include {self.cisco_mac}")
                    if arp_out and self.cisco_mac in arp_out.lower():
                        lines = [l.strip() for l in arp_out.splitlines() if self.cisco_mac in l.lower()]
                        if lines:
                            port = lines[0].split()[-1]
                            mac_found = True
                            print(f"    [V] Found in ARP Table (L3) on interface: {port}")
                            if port.lower().startswith("vl"):
                                print(f"    [!] Note: ARP points to a logical SVI ({port}). L2 trace might stop here.")
                            self.loop_mitigation_active = False

                if not mac_found:
                    print(f"    [X] Device {self.cisco_mac} NOT FOUND in MAC or ARP tables on {self.current_ip}.")
                    self.result["Status"] = f"Lost (No MAC/ARP) @ {self.current_ip}"
                    return self.result

                if port.lower().startswith("po"):
                    print(f"    [*] Port is a Port-Channel ({port}). Resolving physical interface...")
                    po_num_match = re.search(r'\d+', port)
                    if po_num_match:
                        po_num = po_num_match.group()
                        ether_out = sw_conn.send_command("show etherchannel summary")
                        phys_port = None
                        for e_line in ether_out.splitlines():
                            if re.search(rf'\bPo(?:rt-channel)?{po_num}\b', e_line, re.IGNORECASE):
                                members = re.findall(r'([A-Za-z]+[\d/]+)\(', e_line)
                                real_phys_ports = [m for m in members if not m.lower().startswith('po')]
                                if real_phys_ports:
                                    phys_port = real_phys_ports[0]
                                    break
                        if phys_port:
                            print(f"    [V] Resolved {port} to physical port: {phys_port}")
                            port = phys_port 
                        else:
                            print(f"    [X] Could not find physical members for {port}.")
                            self.result["Status"] = f"Po Parse Error @ {self.current_ip}"
                            return self.result

                cdp_out = sw_conn.send_command(f"show cdp neighbors {port} detail")
                if "Device ID" not in cdp_out or "Total cdp entries: 0" in cdp_out.lower():
                    print(f"\n    [***] EDGE SWITCH REACHED: {self.current_ip} [***]")
                    ver_out = sw_conn.send_command("show version")
                    hostname = sw_conn.find_prompt().replace('#', '').replace('>', '')
                    model_match = re.search(r'(WS-C\S+|C\d{4}\S+|N\dK\S+)', ver_out)
                    version_match = re.search(r'Version\s+([^,]+)', ver_out)
                    
                    self.result.update({
                        "Status": "Success", "Target_Device": hostname, "Target_Port": port,
                        "Target_IP": self.current_ip,
                        "Target_Model": model_match.group(0) if model_match else "Cisco Switch",
                        "Target_Version": version_match.group(1) if version_match else "Unknown"
                    })
                    return self.result
                else:
                    ip_match = re.search(r'(?i)(?:IP|IPv4) address:\s*([0-9\.]+)', cdp_out)
                    if ip_match:
                        next_ip = ip_match.group(1)
                        print(f"    [>] CDP Neighbor found on {port}. Hopping to next switch: {next_ip}")
                        self.current_ip = next_ip
                    else:
                        print(f"    [X] CDP neighbor exists but could not find its IP.")
                        self.result["Status"] = f"CDP IP Parse Error @ {self.current_ip}"
                        return self.result
                        
            except Exception as e:
                print(f"    [X] Command Execution Error on Switch {self.current_ip}: {e}")
                self.result["Status"] = f"Exec Error @ {self.current_ip}"
                return self.result
            finally:
                if sw_conn: sw_conn.disconnect()

        return self.result

# ==========================================
# PALO ALTO NODE CLASS (RESTORED TO STABLE V1)
# ==========================================
class PaloAltoNode:
    def __init__(self, ip, vault, client=None, shell=None, working_user=None, working_pass=None):
        self.ip = ip
        self.vault = vault
        self.provided_client = client
        self.provided_shell = shell

    def execute_scan(self):
        result = {
            "Vendor": "Palo Alto", "FW_IP": self.ip, "FW_Hostname": f"PA-{self.ip}", "Status": "Failed",
            "Target_Device": "N/A", "Target_Port": "N/A", "Target_IP": "N/A", "Target_Model": "N/A", "Target_Version": "N/A"
        }
        client = None
        shell = None

        try:
            auth_success = False
            if self.provided_client and self.provided_shell:
                client = self.provided_client
                shell = self.provided_shell
                auth_success = True

            while not auth_success:
                for u, p in self.vault.pa_creds:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    try:
                        client.connect(self.ip, username=u, password=p, timeout=15, look_for_keys=False, allow_agent=False)
                        client.get_transport().set_keepalive(15) 
                        shell = client.invoke_shell()
                        auth_success = True
                        break
                    except paramiko.AuthenticationException:
                        if client: client.close()
                        shell = None
                        continue 
                    except Exception as e:
                        result["Status"] = "PA Conn Failed"
                        if shell: shell.close()
                        if client: client.close()
                        return result
                
                if not auth_success:
                    print(f"\n[!] All known credentials failed for Palo Alto {self.ip}.")
                    if Utils.ask_yes_no(f"    Enter new credentials for this Firewall? (y/n): "):
                        new_u = input(f"    New PA User: ")
                        new_p = getpass.getpass(f"    New PA Password: ")
                        self.vault.add_pa(new_u, new_p)
                        continue
                    else:
                        result["Status"] = "PA Auth Failed"
                        return result

            try:
                if self.provided_client and self.provided_shell:
                    # Untaint the reused shell from the identify_vendor's 'show system info' pager
                    shell.send('q\n\n')
                    time.sleep(0.5)
                    while shell.recv_ready(): shell.recv(10000)

                shell.send('set cli pager off\n')
                time.sleep(1)
                if shell.recv_ready(): shell.recv(10000)
                    
                shell.send('show system info\n')
                time.sleep(0.5)
                shell.send('show interface management\n')
                
                output = ""
                for _ in range(30):
                    if shell.recv_ready():
                        output += shell.recv(10000).decode('utf-8', errors='ignore')
                    time.sleep(0.5)

                if not output:
                    result["Status"] = "PA No Output"
                    return result

                hostname_match = re.search(r'(?i)hostname:\s*(\S+)', output)
                if hostname_match:
                    result["FW_Hostname"] = hostname_match.group(1)

                mac_match = re.search(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', output)
                dg_match = re.search(r'(?i)Default gateway:\s*([0-9\.]+)', output)

                if not (mac_match and dg_match):
                    print("    [X] Missing data in PA output. MAC/DG not found in buffer.")
                    result["Status"] = "MAC/DG Not Found"
                    return result

                pa_mac = mac_match.group(1)
                dg_ip = dg_match.group(1)
                cisco_mac = Utils.format_mac_for_cisco(pa_mac)
                
                def keepalive_ping():
                    try:
                        shell.send(f'ping count 2 host {dg_ip}\n')
                        time.sleep(1.5)
                    except: pass

                tracer = CiscoTracer(dg_ip, cisco_mac, self.ip, self.vault, keepalive_cb=keepalive_ping)
                tracer_result = tracer.trace()
                result.update(tracer_result)
                return result
                
            except Exception as e:
                result["Status"] = "PA Conn Failed"
                return result

        finally:
            if shell: shell.close()
            if client: client.close()

# ==========================================
# CHECK POINT NODE CLASS
# ==========================================
class CheckPointNode:
    def __init__(self, ip, vault, client=None, shell=None, working_user=None, working_pass=None):
        self.ip = ip
        self.vault = vault
        self.client = client
        self.shell = shell
        self.working_user = working_user
        self.working_pass = working_pass
        self.working_exp = None 

    def _reconnect_to_expert(self):
        try:
            if self.client: self.client.close()
        except: pass
        
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        w_u, w_p = None, None
        for u, p, exp in self.vault.cp_creds:
            if exp == self.working_exp:
                w_u, w_p = u, p; break
                
        self.client.connect(self.ip, username=w_u, password=w_p, timeout=10, look_for_keys=False, allow_agent=False)
        self.client.get_transport().set_keepalive(15)
        self.shell = self.client.invoke_shell()
        time.sleep(1)
        if self.shell.recv_ready(): self.shell.recv(4096)
        
        self.shell.send('expert\n')
        time.sleep(1)
        self.shell.send(self.working_exp + '\n')
        time.sleep(1.5)
        self.shell.send('unset TMOUT\nexport TMOUT=0\n')
        while self.shell.recv_ready(): self.shell.recv(4096)

    def execute_scan(self):
        base_result = {
            "Vendor": "Check Point", "FW_IP": self.ip, "FW_Hostname": "N/A", "Status": "Failed", 
            "Target_Device": "N/A", "Target_Port": "N/A", "Target_IP": "N/A", "Target_Model": "N/A", "Target_Version": "N/A"
        }
        
        auth_success = False
        
        if self.client and self.shell and self.working_user and self.working_pass:
            for u, p, exp in self.vault.cp_creds:
                if u == self.working_user and p == self.working_pass:
                    self.working_exp = exp
                    break
            
            if self.working_exp is not None:
                try:
                    self.shell.send('show hostname\n')
                    time.sleep(1)
                    if self.shell.recv_ready():
                        out_hostname = self.shell.recv(4096).decode('utf-8', errors='ignore')
                        match = re.search(r'Hostname:\s*(\S+)', out_hostname, re.IGNORECASE)
                        if match: base_result["FW_Hostname"] = match.group(1)

                    self.shell.send('expert\n')
                    time.sleep(1)
                    self.shell.send(self.working_exp + '\n')
                    time.sleep(1.5)
                    
                    expert_check = ""
                    if self.shell.recv_ready():
                        expert_check = self.shell.recv(4096).decode('utf-8', errors='ignore')
                    
                    if "incorrect" in expert_check.lower() or "denied" in expert_check.lower():
                        if self.client: self.client.close()
                        self.client, self.shell = None, None
                    else:
                        auth_success = True
                        self.shell.send('unset TMOUT\nexport TMOUT=0\n')
                        while self.shell.recv_ready(): self.shell.recv(4096)
                except Exception:
                    if self.client: self.client.close()
                    self.client, self.shell = None, None
            else:
                if self.client: self.client.close()
                self.client, self.shell = None, None

        while not auth_success:
            for u, p, exp in self.vault.cp_creds:
                self.client = paramiko.SSHClient()
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                try:
                    self.client.connect(self.ip, username=u, password=p, timeout=10, look_for_keys=False, allow_agent=False)
                    self.client.get_transport().set_keepalive(15)
                    self.shell = self.client.invoke_shell()
                    time.sleep(1)
                    
                    self.shell.send('show hostname\n')
                    time.sleep(1)
                    if self.shell.recv_ready():
                        out_hostname = self.shell.recv(4096).decode('utf-8', errors='ignore')
                        match = re.search(r'Hostname:\s*(\S+)', out_hostname, re.IGNORECASE)
                        if match: base_result["FW_Hostname"] = match.group(1)

                    self.shell.send('expert\n')
                    time.sleep(1)
                    self.shell.send(exp + '\n')
                    time.sleep(1.5)
                    
                    expert_check = ""
                    if self.shell.recv_ready():
                        expert_check = self.shell.recv(4096).decode('utf-8', errors='ignore')
                    
                    if "incorrect" in expert_check.lower() or "denied" in expert_check.lower():
                        if self.client: self.client.close()
                        continue 
                    
                    auth_success = True
                    self.working_user = u
                    self.working_pass = p
                    self.working_exp = exp 
                    self.shell.send('unset TMOUT\nexport TMOUT=0\n')
                    while self.shell.recv_ready(): self.shell.recv(4096)
                    break 

                except paramiko.AuthenticationException:
                    if self.client: self.client.close()
                    continue 
                except Exception as e:
                    base_result["Status"] = "Connection Error"
                    if self.client: self.client.close()
                    return base_result

            if not auth_success:
                print(f"\n[!] All known credentials failed for Check Point {self.ip}.")
                if Utils.ask_yes_no(f"    Enter new credentials? (y/n): "):
                    new_u = input(f"    New CP User: ")
                    new_p = getpass.getpass(f"    New CP Password: ")
                    new_exp = getpass.getpass(f"    New Expert Password: ")
                    self.vault.add_cp(new_u, new_p, new_exp)
                    continue
                else:
                    base_result["Status"] = "Auth Error"
                    return base_result

        try:
            target_interface = "Mgmt"
            interface_attempt = 0
            max_interface_attempts = 3
            while interface_attempt < max_interface_attempts:
                print(f"    - Listening for CDP packet on {target_interface} (up to 75s)...")
                while self.shell.recv_ready(): self.shell.recv(4096)
                
                self.shell.send(f'tcpdump -nn -v -c 1 -i {target_interface} "ether[20:2] == 0x2000"\n')
                
                output = ""; start_time = time.time(); packet_found = False
                
                while time.time() - start_time < 75:
                    try:
                        if self.shell.recv_ready():
                            output += self.shell.recv(4096).decode('utf-8', errors='ignore')
                            if "packet captured" in output or "packets received by filter" in output:
                                time.sleep(1)
                                if self.shell.recv_ready():
                                    output += self.shell.recv(4096).decode('utf-8', errors='ignore')
                                print(f"    [V] CDP Packet captured successfully on {target_interface}!")
                                packet_found = True
                                break
                    except Exception:
                        print("    [!] SSH socket quietly dropped by firewall (idle limit reached).")
                        break 
                    time.sleep(1)
                
                if packet_found:
                    parsed = self._parse_checkpoint_cdp(output)
                    base_result.update(parsed)
                    return base_result
                
                print(f"    [X] Timeout reached. No CDP packets found on {target_interface}.")
                try:
                    self.shell.send('\x03')
                    time.sleep(0.5)
                    while self.shell.recv_ready(): self.shell.recv(4096)
                except: pass
                
                interface_attempt += 1
                if interface_attempt >= max_interface_attempts:
                    print(f"    [!] Max interface attempts ({max_interface_attempts}) reached.")
                    base_result["Status"] = "Timeout (No CDP)"
                    return base_result
                
                if not Utils.ask_yes_no(f"    Do you want to scan a different interface? (y/n): "):
                    base_result["Status"] = "Timeout (No CDP)"
                    return base_result
                
                print("    [*] Fetching interfaces directly from Expert mode (Kernel sysfs)...")
                
                session_alive = False
                try:
                    self.shell.send('\n')
                    time.sleep(0.5)
                    if self.shell.recv_ready():
                        resp = self.shell.recv(4096)
                        session_alive = True if resp else False
                except Exception: pass
                    
                if not session_alive:
                    print("    [*] Session timed out while waiting. Reconnecting to Expert...")
                    self._reconnect_to_expert()
                
                try:
                    self.shell.send('ls -1 /sys/class/net/\n')
                except Exception as e:
                    print(f"    [!] Failed to send command: {e}. Reconnecting...")
                    self._reconnect_to_expert()
                    self.shell.send('ls -1 /sys/class/net/\n')
                time.sleep(1.5)
                ifaces_out = ""
                while True:
                    if self.shell.recv_ready():
                        ifaces_out += self.shell.recv(4096).decode('utf-8', errors='ignore')
                        time.sleep(0.5)
                    else: break
                
                ifaces = []
                for line in ifaces_out.splitlines():
                    clean_line = line.strip()
                    if not clean_line or "ls -1" in clean_line or "expert" in clean_line.lower() or "#" in clean_line or ">" in clean_line or "[" in clean_line:
                        continue
                    if re.match(r'^[a-zA-Z0-9_.-]+$', clean_line) and clean_line not in ['lo', 'loopback', 'bonding_masters']:
                        ifaces.append(clean_line)
                
                ifaces = list(dict.fromkeys(ifaces))
                if not ifaces:
                    print("    [!] Could not parse interfaces from Expert mode.")
                    base_result["Status"] = "Interface Parse Error"
                    return base_result
                
                print("\n    Available Interfaces:")
                for idx, iface in enumerate(ifaces, 1): print(f"      [{idx}] {iface}")
                
                target_interface = ifaces[Utils.ask_int_choice(f"    Select interface number (1-{len(ifaces)}): ", 1, len(ifaces)) - 1]
                print(f"    [*] Restarting tcpdump on {target_interface}...")

        finally:
            if self.client: self.client.close()

    def _parse_checkpoint_cdp(self, content):
        device_match = re.search(r"Device-ID.*?:\s*'([^']+)'", content)
        port_match = re.search(r"Port-ID.*?:\s*'([^']+)'", content)
        ip_match = re.search(r"IPv4\s*\(\d+\)\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", content)
        platform_match = re.search(r"Platform.*?:\s*'([^']+)'", content)
        version_match = re.search(r"Version String.*?bytes:[\r\n\s]+([^\r\n]+)", content)
        
        return {
            "Status": "Success",
            "Target_Device": device_match.group(1) if device_match else "N/A",
            "Target_Port": port_match.group(1) if port_match else "N/A",
            "Target_IP": ip_match.group(1) if ip_match else "N/A",
            "Target_Model": platform_match.group(1) if platform_match else "N/A",
            "Target_Version": version_match.group(1).strip() if version_match else "N/A"
        }

# ==========================================
# MAIN APPLICATION ORCHESTRATOR
# ==========================================
class NexusTracerApp:
    def __init__(self):
        self.vault = CredentialVault()

    def identify_vendor(self, ip):
        creds = list(set([(u, p) for u, p in self.vault.pa_creds] + [(u, p) for u, p, _ in self.vault.cp_creds]))
        
        for u, p in creds:
            client = None
            shell = None
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, username=u, password=p, timeout=5, look_for_keys=False, allow_agent=False)
                shell = client.invoke_shell()
                
                # Allow the FW pseudoterminal process to fully spawn before pushing commands
                time.sleep(1.5)
                shell.send('\nshow system info\n')
                
                out = ""
                for _ in range(40): 
                    if shell.recv_ready():
                        out += shell.recv(4096).decode('utf-8', errors='ignore').lower()
                        
                        if "sw-version" in out or "family" in out or "mac-address" in out or "palo alto" in out:
                            return "PA", client, shell, u, p
                        
                        if "syntax error" in out or "unknown command" in out or "not found" in out or "invalid" in out:
                            return "CP", client, shell, u, p
                    
                    time.sleep(0.2)

                if shell: shell.close()
                if client: client.close()
                    
            except paramiko.AuthenticationException:
                if shell: shell.close()
                if client: client.close()
                continue 
            except Exception:
                if shell: shell.close()
                if client: client.close()
                break
                
        return "Unknown", None, None, None, None

    def run_autonomous_discovery(self):
        Utils.clear_screen()
        print("======================================================")
        print("        AUTONOMOUS NETWORK DISCOVERY ENGINE           ")
        print("======================================================")
        
        ip_file = "firewalls.txt"
        if not os.path.exists(ip_file):
            with open(ip_file, "w") as f: f.write("# Enter all Firewall IPs here (Mixed Vendors)\n")
            Utils.pause_and_return(f"[!] Created '{ip_file}'. Add your IPs and try again.")
            return

        with open(ip_file, "r") as f:
            ips = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        if not ips:
            Utils.pause_and_return(f"[!] '{ip_file}' is empty. Feed me some IPs.")
            return

        print(f"\n[*] Ready to autonomously scan {len(ips)} Firewalls.\n")
        print("--- MASTER CREDENTIALS ---")
        cp_u = input("Check Point User: ")
        cp_p = getpass.getpass("Check Point Pass: ")
        cp_exp = getpass.getpass("Expert Pass: ")
        self.vault.add_cp(cp_u, cp_p, cp_exp)
        
        pa_u = input("\nPalo Alto User (Press Enter to use CP User): ") or cp_u
        pa_p = getpass.getpass("Palo Alto Pass: ") or cp_p
        self.vault.add_pa(pa_u, pa_p)

        sw_u = input("\nCisco Switches User (Press Enter to use PA User): ") or pa_u
        sw_p = getpass.getpass("Cisco Switches Pass: ") or pa_p
        self.vault.add_sw(sw_u, sw_p)
        
        all_results = []
        print("\n[*] Initializing Autonomous Scan... Let's go!\n")
        
        for ip in ips:
            print("\n" + "="*50)
            print(f"[*] Analyzing Target: {ip}")
            vendor, client, shell, w_u, w_p = self.identify_vendor(ip)
            
            attempts = 0
            while vendor == "Unknown" and attempts < 5:
                print(f"    [!] Could not connect or identify vendor for {ip} (Auth or Network failed).")
                if not Utils.ask_yes_no("    Do you want to try with different credentials? (y/n): "):
                    break
                
                print(f"    --- Attempt {attempts + 1}/5 ---")
                new_u = input("    New Username: ")
                new_p = getpass.getpass("    New Password: ")
                new_exp = getpass.getpass("    New Expert Password (for Check Point, press Enter if irrelevant): ")
                
                self.vault.add_pa(new_u, new_p)
                self.vault.add_sw(new_u, new_p)
                if new_exp:
                    self.vault.add_cp(new_u, new_p, new_exp)
                else:
                    self.vault.add_cp(new_u, new_p, "admin") 
                
                print(f"    [*] Testing new credentials on target...")
                vendor, client, shell, w_u, w_p = self.identify_vendor(ip)
                if vendor != "Unknown":
                    print(f"    [V] Successfully connected and identified vendor with the new credentials!")
                    break
                
                attempts += 1

            if vendor == "Unknown" and attempts >= 5:
                print(f"    [!] Maximum credential attempts (5) reached.")

            node = None
            if vendor == "PA":
                print(f"    [V] Vendor Identified: Palo Alto Networks")
                node = PaloAltoNode(ip, self.vault, client, shell, w_u, w_p)
            elif vendor == "CP":
                print(f"    [V] Vendor Identified: Check Point Software")
                node = CheckPointNode(ip, self.vault, client, shell, w_u, w_p)
            else:
                print(f"    [!] Could not automatically identify vendor.")
                ans = input("    Force Check Point (1), Force Palo Alto (2), Skip (3): ").strip()
                if ans == '1': node = CheckPointNode(ip, self.vault, client, shell, w_u, w_p)
                elif ans == '2': node = PaloAltoNode(ip, self.vault, client, shell, w_u, w_p)
                else:
                    if shell: shell.close()
                    if client: client.close()
                    all_results.append({"Vendor": "Unknown", "FW_IP": ip, "FW_Hostname": "N/A", "Status": "Skipped", "Target_Device": "N/A", "Target_Port": "N/A", "Target_IP": "N/A", "Target_Model": "N/A", "Target_Version": "N/A"})
                    time.sleep(2)
                    continue
            
            if not node:
                if shell: shell.close()
                if client: client.close()
                all_results.append({"Vendor": vendor, "FW_IP": ip, "FW_Hostname": "N/A", "Status": "No Handler", "Target_Device": "N/A", "Target_Port": "N/A", "Target_IP": "N/A", "Target_Model": "N/A", "Target_Version": "N/A"})
                time.sleep(2)
                continue
                
            try:
                all_results.append(node.execute_scan())
            except Exception as e:
                print(f"    [X] Unexpected Crash: {e}")
                logging.error(f"Crash on {ip}", exc_info=True)
                all_results.append({"Vendor": vendor, "FW_IP": ip, "FW_Hostname": "N/A", "Status": "Crash", "Target_Device": "N/A", "Target_Port": "N/A", "Target_IP": "N/A", "Target_Model": "N/A", "Target_Version": "N/A"})
                if shell: shell.close()
                if client: client.close()
            
            print(f"    [~] Cooldown: Waiting 2 seconds before next IP to prevent rate-limiting...")
            time.sleep(2)

        if all_results:
            ReportGenerator.print_unified_cli(all_results)
            ReportGenerator.save_csv(all_results, "unified_discovery_report.csv")
            Utils.pause_and_return()

    def start(self):
        logging.info("Application started.")
        while True:
            Utils.clear_screen()
            print(r"""
    _   _ _______  ___   _ ____    _____ ____     _     ____ _____ ____  
   | \ | | ____\ \/ / | | / ___|  |_   _|  _ \   / \   / ___| ____|  _ \ 
   |  \| |  _|  \  /| | | \___ \    | | | |_) | / _ \ | |   |  _| | |_) |
   | |\  | |___ /  \| |_| |___) |   | | |  _ < / ___ \| |___| |___|  _ < 
   |_| \_|_____/_/\_\\___/|____/    |_| |_| \_/_/   \_\____|_____|_| \_\
                                                                          
            """)
            print("="*70)
            print("              [ NETWORK DISCOVERY AUTOMATION SUITE ]              ")
            print("                        Created by Ariel                          ")
            print("="*70)
            print("\n  [1] Autonomous Unified Discovery (Reads from firewalls.txt)")
            print("  [2] Exit Tool\n")
            
            Utils.flush_buffer()
            choice = input("Select an option (1-2): ").strip()
            
            if choice == '1': self.run_autonomous_discovery()
            elif choice == '2':
                print("\n[!] Exiting Nexus Tracer. See ya!"); time.sleep(1); sys.exit(0)
            else:
                print("\n[X] Invalid choice, bro. Try again."); time.sleep(1.5)

# ==========================================
# BOOTSTRAP
# ==========================================
if __name__ == "__main__":
    try:
        app = NexusTracerApp()
        app.start()
    except Exception as e:
        print(f"\n[!!!] CRITICAL CRASH DETECTED: {e}")
        logging.critical("CRITICAL CRASH IN MAIN LOOP", exc_info=True)
        traceback.print_exc()
        input("\n[!] Press ENTER to close this window...")
