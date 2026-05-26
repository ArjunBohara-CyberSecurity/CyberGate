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

# =========================================================
# AI INCIDENT RESPONSE ASSISTANT PRO
# =========================================================

VERSION = "2.0"

THREAT_THRESHOLD = 50
MAX_RETRIES = 3
REQUEST_TIMEOUT = 10
AUTO_SAVE_FIREWALL = True

LOG_FILE = "incident_log.json"

WHITELIST = {
    "127.0.0.1",
    "1.1.1.1",
    "8.8.8.8"
}

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

        return None, str(last_error)

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

        if not os.path.exists(LOG_FILE):

            with open(LOG_FILE, "w") as f:
                json.dump([], f)

        with open(LOG_FILE, "r+") as f:

            data = json.load(f)

            data.append(entry)

            f.seek(0)

            json.dump(data, f, indent=4)

    except Exception as e:

        print(f"{Color.RED}[LOG ERROR] {e}{Color.RESET}")

# =========================================================
# ROOT CHECK
# =========================================================

def check_root():

    if os.name != "nt":

        if os.geteuid() != 0:

            print(
                f"{Color.RED}Run with sudo/root.{Color.RESET}"
            )

            exit()

# =========================================================
# DEPENDENCY CHECK
# =========================================================

def dependency_check():

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
# IP EXTRACTION
# =========================================================

def extract_ip(text):

    ipv4_pattern = (
        r'\b(?:25[0-5]|2[0-4][0-9]|'
        r'1?[0-9]{1,2})(?:\.(?:25[0-5]|'
        r'2[0-4][0-9]|1?[0-9]{1,2})){3}\b'
    )

    match = re.search(ipv4_pattern, text)

    if match:
        return match.group(0)

    return None

# =========================================================
# VALIDATION
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
        "country": data.get("country"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "isp": data.get("isp"),
        "org": data.get("org")
    }, None

# =========================================================
# REVERSE DNS
# =========================================================

def reverse_dns(ip):

    try:
        return socket.gethostbyaddr(ip)[0]

    except:
        return "Unknown"

# =========================================================
# ABUSEIPDB
# =========================================================

@retry_request
def get_abuseipdb_data(ip):

    api_key = os.environ.get("ABUSEIPDB_API_KEY")

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
        "country": data.get("countryCode"),
        "usage": data.get("usageType"),
        "isp": data.get("isp"),
        "reports": data.get("totalReports", 0),
        "domain": data.get("domain")
    }, None

# =========================================================
# PING CHECK
# =========================================================

def ping_ip(ip):

    try:

        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        return result.returncode == 0

    except:
        return False

# =========================================================
# PORT SCAN
# =========================================================

def scan_common_ports(ip):

    ports = [22, 23, 53, 80, 443, 445, 3389]
    open_ports = []

    for port in ports:

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

    result = subprocess.run(
        ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0

def save_firewall():

    if AUTO_SAVE_FIREWALL:

        try:

            subprocess.run(
                ["iptables-save"],
                stdout=open("/etc/iptables/rules.v4", "w")
            )

        except:
            pass

def isolate_ip(ip):

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
# TELEGRAM ALERTS
# =========================================================

@retry_request
def notify_telegram(ip, score, action):

    token = os.environ.get("TELEGRAM_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")

    if not token or not chat_id:
        raise Exception("Telegram credentials missing")

    message = f"""
🧠 AI INCIDENT RESPONSE

🌐 IP: {ip}
⚠️ Threat Score: {score}/100
🛡 Action: {action}
🕒 Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""

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

        abuse_data, abuse_err = abuse_future.result()

        geo_data, geo_err = geo_future.result()

        ping_status = ping_future.result()

        open_ports = ports_future.result()

    if abuse_err:

        print(
            f"{Color.RED}Threat lookup failed: "
            f"{abuse_err}{Color.RESET}"
        )

        return

    hostname = reverse_dns(ip)

    score = abuse_data["score"]

    print("=" * 50)

    print(f"IP Address : {ip}")
    print(f"Hostname : {hostname}")
    print(f"Threat Score : {score}/100")
    print(f"Reports : {abuse_data['reports']}")
    print(f"Usage Type : {abuse_data['usage']}")
    print(f"ISP : {abuse_data['isp']}")
    print(f"Domain : {abuse_data['domain']}")
    print(f"Reachable : {ping_status}")
    print(f"Open Ports : {open_ports}")

    if geo_data:

        print(f"Country : {geo_data['country']}")
        print(f"Region : {geo_data['region']}")
        print(f"City : {geo_data['city']}")

    print("=" * 50)

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
            f"{Color.BLUE}Whitelisted IP."
            f"{Color.RESET}"
        )

        return

    if score >= THREAT_THRESHOLD:

        print(
            f"{Color.RED}HIGH RISK DETECTED"
            f"{Color.RESET}"
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
                    ip,
                    score,
                    "Isolated"
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
# COMMANDS
# =========================================================

def show_help():

    print(f"""
{Color.CYAN}
Commands
========
scan <ip> Analyze IP
isolate <ip> Force isolate IP
remove <ip> Remove block
logs View logs
help Show help
exit Quit
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

        data = json.load(f)

    for item in data[-10:]:

        print(json.dumps(item, indent=4))

# =========================================================
# MAIN LOOP
# =========================================================

def run():

    check_root()

    dependency_check()

    print(f"""
{Color.BLUE}
========================================
 AI INCIDENT RESPONSE ASSISTANT PRO
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
                        ip,
                        100,
                        "Force isolated"
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