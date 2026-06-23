import os
import re
import time
import json
import socket
import shutil
import requests
import subprocess
import ipaddress

from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv

load_dotenv()

# =========================================================
# CYBERGATE AI INCIDENT RESPONSE ASSISTANT PRO
# =========================================================

VERSION = "1.0"

THREAT_THRESHOLD = 30
MAX_RETRIES = 3
REQUEST_TIMEOUT = 10
AUTO_SAVE_FIREWALL = True

LOG_FILE = "incident_log.json"

WHITELIST = {
    "127.0.0.1",
    "1.1.1.1",
    "8.8.8.8"
}

IS_WINDOWS = os.name == "nt"

# =========================================================
# COLORS
# =========================================================

class Color:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

# =========================================================
# RETRY DECORATOR
# =========================================================

def retry_request(func):

    def wrapper(*args, **kwargs):

        last_error = None

        for attempt in range(1, MAX_RETRIES + 1):

            try:
                return func(*args, **kwargs)

            except Exception as e:

                last_error = e

                print(
                    f"{Color.YELLOW}[Retry {attempt}/{MAX_RETRIES}] "
                    f"{func.__name__}: {e}{Color.RESET}"
                )

                time.sleep(2)

        return {}, str(last_error)

    return wrapper

# =========================================================
# LOGGING
# =========================================================

def log_event(event_type, ip, details):

    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event": event_type,
        "ip": ip,
        "details": details
    }

    try:

        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")

    except Exception as e:

        print(
            f"{Color.RED}[LOG ERROR] {e}{Color.RESET}"
        )

# =========================================================
# ROOT CHECK
# =========================================================

def check_root():

    if not IS_WINDOWS:

        if os.geteuid() != 0:

            print(
                f"{Color.RED}Run with sudo/root.{Color.RESET}"
            )

            exit()

# =========================================================
# DEPENDENCY CHECK
# =========================================================

def dependency_check():

    if IS_WINDOWS:
        return

    required = ["iptables"]

    missing = []

    for tool in required:

        if shutil.which(tool) is None:
            missing.append(tool)

    if missing:

        print(
            f"{Color.RED}Missing dependencies: "
            f"{', '.join(missing)}{Color.RESET}"
        )

        exit()

# =========================================================
# IP VALIDATION
# =========================================================

def is_valid_ip(ip):

    try:
        ipaddress.ip_address(ip)
        return True

    except ValueError:
        return False

# =========================================================
# GEOLOCATION
# =========================================================

@retry_request
def get_geo_data(ip):

    response = requests.get(
        f"http://ip-api.com/json/{ip}",
        timeout=REQUEST_TIMEOUT
    )

    data = response.json()

    if data.get("status") != "success":
        raise Exception("Geo lookup failed")

    return {
        "country": data.get("country", "Unknown"),
        "region": data.get("regionName", "Unknown"),
        "city": data.get("city", "Unknown"),
        "isp": data.get("isp", "Unknown"),
        "org": data.get("org", "Unknown")
    }, None

# =========================================================
# REVERSE DNS
# =========================================================

def reverse_dns(ip):

    try:

        socket.setdefaulttimeout(3)

        return socket.gethostbyaddr(ip)[0]

    except:
        return "Unknown"

# =========================================================
# ABUSEIPDB
# =========================================================

@retry_request
def get_abuseipdb_data(ip):

    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        raise Exception("ABUSEIPDB_API_KEY missing")

    response = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={
            "Key": api_key,
            "Accept": "application/json"
        },
        params={
            "ipAddress": ip,
            "maxAgeInDays": "90"
        },
        timeout=REQUEST_TIMEOUT
    )

    if response.status_code != 200:
        raise Exception(f"API {response.status_code}")

    data = response.json()["data"]

    return {
        "score": data.get("abuseConfidenceScore", 0),
        "country": data.get("countryCode", "Unknown"),
        "usage": data.get("usageType", "Unknown"),
        "isp": data.get("isp", "Unknown"),
        "reports": data.get("totalReports", 0),
        "domain": data.get("domain", "Unknown")
    }, None

# =========================================================
# PING
# =========================================================

def ping_ip(ip):

    try:

        if IS_WINDOWS:

            cmd = ["ping", "-n", "1", ip]

        else:

            cmd = ["ping", "-c", "1", "-W", "2", ip]

        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        return result.returncode == 0

    except:
        return False

# =========================================================
# PORT SCAN
# =========================================================

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NETBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    6379: "REDIS",
    8080: "HTTP-ALT"
}

def scan_common_ports(ip):

    open_ports = []

    for port in COMMON_PORTS:

        try:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            sock.settimeout(1)

            result = sock.connect_ex((ip, port))

            if result == 0:
                open_ports.append(port)

            sock.close()

        except:
            pass

    return open_ports

# =========================================================
# FIREWALL
# =========================================================

def firewall_rule_exists(ip):

    if IS_WINDOWS:
        return False

    result = subprocess.run(
        ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0

def save_firewall():

    if AUTO_SAVE_FIREWALL and not IS_WINDOWS:

        try:

            with open("/etc/iptables/rules.v4", "w") as f:

                subprocess.run(
                    ["iptables-save"],
                    stdout=f,
                    check=True
                )

        except:
            pass

def isolate_ip(ip):

    if IS_WINDOWS:
        return False, "Firewall unsupported on Windows"

    try:

        if firewall_rule_exists(ip):
            return True, "Already isolated"

        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )

        save_firewall()

        return True, None

    except Exception as e:

        return False, str(e)

def unisolate_ip(ip):

    if IS_WINDOWS:
        return False, "Firewall unsupported on Windows"

    try:

        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )

        save_firewall()

        return True, None

    except Exception as e:

        return False, str(e)

# =========================================================
# TELEGRAM
# =========================================================

@retry_request
def notify_telegram(message):

    token = os.getenv("TELEGRAM_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")

    if not token or not chat_id:
        raise Exception("Telegram credentials missing")

    response = requests.post(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data={
            "chat_id": chat_id,
            "text": message
        },
        timeout=REQUEST_TIMEOUT
    )

    if response.status_code != 200:
        raise Exception("Telegram API failed")

    return True, None

# =========================================================
# THREAT SCORE
# =========================================================

def calculate_threat_score(
    base_score,
    open_ports,
    ping_status,
    isp
):

    score = base_score

    dangerous_ports = {
        22: 10,
        23: 35,
        445: 40,
        3389: 35,
        3306: 20,
        6379: 25
    }

    for port in open_ports:

        if port in dangerous_ports:
            score += dangerous_ports[port]

    if ping_status:
        score += 5

    hosting_keywords = [
        "cloud",
        "hosting",
        "vps",
        "digitalocean",
        "ovh",
        "aws",
        "google",
        "azure"
    ]

    isp = isp.lower()

    if any(k in isp for k in hosting_keywords):
        score += 15

    if 445 in open_ports:
        score = max(score, 85)

    if 3389 in open_ports:
        score = max(score, 75)

    if 23 in open_ports:
        score = max(score, 95)

    return min(score, 100)

# =========================================================
# ANALYSIS
# =========================================================

def analyze_ip(ip):

    print(
        f"\n{Color.CYAN}Investigating {ip}...{Color.RESET}\n"
    )

    with ThreadPoolExecutor() as executor:

        abuse_future = executor.submit(
            get_abuseipdb_data,
            ip
        )

        geo_future = executor.submit(
            get_geo_data,
            ip
        )

        ping_future = executor.submit(
            ping_ip,
            ip
        )

        ports_future = executor.submit(
            scan_common_ports,
            ip
        )

        abuse_data, abuse_err = abuse_future.result(timeout=15)

        geo_data, geo_err = geo_future.result(timeout=15)

        ping_status = ping_future.result(timeout=15)

        open_ports = ports_future.result(timeout=15)

    if abuse_err:

        print(
            f"{Color.RED}Threat lookup failed.{Color.RESET}"
        )

        return

    if not geo_data:
        geo_data = {}

    hostname = reverse_dns(ip)

    score = calculate_threat_score(
        abuse_data.get("score", 0),
        open_ports,
        ping_status,
        abuse_data.get("isp", "")
    )

    
    print("CYBERGATE INCIDENT RESPONSE REPORT")
    
    print("=" * 50)

    print(f"IP Address : {ip}")
    print(f"Hostname : {hostname}")
    print(f"Threat Score : {score}/100")
    print(f"Reports : {abuse_data.get('reports', 0)}")
    print(f"Usage Type : {abuse_data.get('usage', 'Unknown')}")
    print(f"ISP : {abuse_data.get('isp', 'Unknown')}")
    print(f"Domain : {abuse_data.get('domain', 'Unknown')}")
    print(f"Reachable : {ping_status}")
    print(f"Open Ports : {open_ports}")
    
    print(f"Country : {geo_data.get('country', 'Unknown')}")
    print(f"Region : {geo_data.get('region', 'Unknown')}")
    print(f"City : {geo_data.get('city', 'Unknown')}")

    print("=" * 50)

    report = f"""
🧠 CYBERGATE INCIDENT RESPONSE REPORT

🌐 IP: {ip}
🖥 Hostname: {hostname}
⚠ Threat Score: {score}/100
📢 Reports: {abuse_data.get('reports', 0)}
🏢 ISP: {abuse_data.get('isp', 'Unknown')}
🌍 Country: {geo_data.get('country', 'Unknown')}
📍 Region: {geo_data.get('region', 'Unknown')}
🏙 City: {geo_data.get('city', 'Unknown')}
📡 Reachable: {ping_status}
🔓 Open Ports: {open_ports}

🕒 {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""

    notify_telegram(report)

    log_event(
        "analysis",
        ip,
        {
            "score": score,
            "ports": open_ports
        }
    )

    if ip in WHITELIST:

        print(
            f"{Color.BLUE}Whitelisted IP.{Color.RESET}"
        )

        return

    if score >= THREAT_THRESHOLD:

        print(
            f"{Color.RED}HIGH RISK DETECTED{Color.RESET}"
        )

        choice = input(
            "Isolate IP? (y/n): "
        ).strip().lower()

        if choice == "y":

            success, err = isolate_ip(ip)

            if success:

                print(
                    f"{Color.GREEN}"
                    f"{ip} isolated."
                    f"{Color.RESET}"
                )

                notify_telegram(
                    f"""
🚨 IP ISOLATED

🌐 IP: {ip}
⚠ Threat Score: {score}/100
🛡 Action: Firewall DROP rule added

🕒 {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""
                )

                log_event(
                    "isolation",
                    ip,
                    "Firewall rule added"
                )

            else:

                print(
                    f"{Color.RED}"
                    f"Isolation failed: {err}"
                    f"{Color.RESET}"
                )

    else:

        print(
            f"{Color.GREEN}"
            f"Low threat detected."
            f"{Color.RESET}"
        )

# =========================================================
# HELP
# =========================================================

def show_help():

    print(f"""
{Color.CYAN}
CyberGate Commands
========
scan <ip>      Analyze IP
isolate <ip>   Force isolate IP
remove <ip>    Remove firewall block
logs           View logs
help           Show help
exit           Quit
{Color.RESET}
""")

# =========================================================
# LOG VIEWER
# =========================================================

def view_logs():

    if not os.path.exists(LOG_FILE):

        print("No logs.")
        return

    with open(LOG_FILE, "r") as f:

        lines = f.readlines()

    for line in lines[-10:]:

        try:
            print(json.dumps(json.loads(line), indent=4))
        except:
            pass

# =========================================================
# MAIN LOOP
# =========================================================

def run():

    check_root()

    dependency_check()

    print(f"""
{Color.BLUE}
========================================
 CYBERGATE AI INCIDENT RESPONSE ASSISTANT PRO
 Version: {VERSION}
========================================
{Color.RESET}
""")

    show_help()

    while True:

        try:

            command = input("> ").strip()

            if not command:
                continue

            if command.lower() in ["exit", "quit"]:

                print("Goodbye.")
                break

            if command.lower() == "help":

                show_help()
                continue

            if command.lower() == "logs":

                view_logs()
                continue

            parts = command.split()

            if len(parts) < 2:

                print("Invalid command.")
                continue

            action = parts[0].lower()
            ip = parts[1]

            if not is_valid_ip(ip):

                print("Invalid IP.")
                continue

            if action == "scan":

                analyze_ip(ip)

            elif action == "isolate":

                if ip in WHITELIST:

                    print("Protected IP.")
                    continue

                success, err = isolate_ip(ip)

                if success:

                    print(
                        f"{Color.GREEN}"
                        f"{ip} isolated."
                        f"{Color.RESET}"
                    )

                    notify_telegram(
                        f"""
🚨 FORCE ISOLATION

🌐 IP: {ip}
🛡 Action: Manual isolation

🕒 {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""
                    )

                else:

                    print(
                        f"{Color.RED}{err}"
                        f"{Color.RESET}"
                    )

            elif action == "remove":

                success, err = unisolate_ip(ip)

                if success:

                    print(
                        f"{Color.GREEN}"
                        f"Rule removed."
                        f"{Color.RESET}"
                    )

                else:

                    print(
                        f"{Color.RED}{err}"
                        f"{Color.RESET}"
                    )

            else:

                print("Unknown command.")

        except KeyboardInterrupt:

            print("\nInterrupted.")
            break

        except Exception as e:

            print(
                f"{Color.RED}"
                f"Unexpected error: {e}"
                f"{Color.RESET}"
            )

# =========================================================
# START
# =========================================================

if __name__ == "__main__":

    run()