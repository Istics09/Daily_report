import socket
import os, json, time, pwd, smtplib
from dotenv import load_dotenv
from pathlib import Path
from datetime import datetime
import re
from collections import Counter
import requests
from email.message import EmailMessage

#Check if the .env exist
location = load_dotenv(Path(__file__).parent / ".env")

#If .env not available quit & leave message!
if not location:
    print("I can't find .env file! Quiting!")
    exit()


#Today
today = datetime.today().strftime('%Y-%m-%d')

#print(today + "\n")
#print(location)

#Auth log location:
auth_log_location = ["/var/log/auth.log"]

#ufw log location:
ufw_log_location = ["/var/log/ufw.log"]

#Check ip in cached json:
cache_file = Path(__file__).parent / "geo_cache.json"

if cache_file.exists():
    with open(cache_file, "r", encoding="utf-8") as f:
        geo_cache = json.load(f)
else:
    geo_cache = {}

report = []

def out(text=""):
    #print(text)
    report.append(text)

#We will use it later, geo location checker:
def geo(ip):
    if ip in geo_cache:
        return geo_cache[ip]

    result = "Unknown"
    try:
        time.sleep(1.4)
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,isp", timeout=5)
        data = r.json()
        if data["status"] == "success":
            result = f'{data["country"]} ({data["countryCode"]}) / {data["isp"]}'
    
    except Exception:
        pass
    
    
    if result != "Unknown":
        geo_cache[ip] = result
    return result

def user_exists(name):
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


#Auth log read:
ssh_attempts = Counter()
ssh_success = []
ssh_users = Counter()

for path in auth_log_location:
    with open(path, "r", errors="replace") as f:
        for line in f:
            if not line.startswith(today):
                continue
            m = re.search(r"Accepted (\S+) for (\S+) from (\S+) port", line)
            if m:
                method, user, ip = m.group(1), m.group(2), m.group(3)
                login_time = line[11:19]
                ssh_success.append((login_time, method, user, ip))
                continue
            if "Failed password" not in line:
                continue
            m = re.search(r"Failed password for (?:invalid user )?(\S+) from (\S+) port", line)
            if m:
                user, ip = m.group(1), m.group(2)
                ssh_attempts[ip] += 1
                ssh_users[user] += 1

#Verify if i got ips:
#print(ssh_attempts.most_common(50))

out("##############################################\n")
out("the most frequently attacked IP addresses \n")
out("##############################################\n")

#Get geo location for each ip's:
for ip, count in ssh_attempts.most_common(20):
    out(f"{count:>5}x  {ip:<16} {geo(ip)}")

#Success login:
out("##############################################\n")
out("Success login: \n")
for login_time, method, user, ip in ssh_success:
    out(f" {login_time} {user:<10} {method:<10} {ip:<16} {geo(ip)}")
out("\n##############################################\n")

#Existing users:
out("\nAttempts on existing users:\n")
for user, count in ssh_users.most_common():
    if user_exists(user):
        out(f"{count:>5}x {user}")
out("\n##############################################\n")


#Ufw logs:
ufw_ips = Counter()
ufw_ports = Counter()

for path in ufw_log_location:
    with open(path, "r", errors="replace") as f:
        for line in f:
            if not line.startswith(today):
                continue
            if "[UFW BLOCK]" not in line:
                continue
            m = re.search(r"SRC=(\S+) .*DPT=(\d+)", line)
            if m:
                ufw_ips[m.group(1)] += 1
                ufw_ports[m.group(2)] += 1

out("##############################################\n")
out("Ufw blocked IP: \n")
for ip, count in ufw_ips.most_common(50):
    out(f"{count:>5}x {ip:<16} {geo(ip)}")

out("\n##############################################\n")
out("\n Most attacked port: \n")
for port, count in ufw_ports.most_common(10):
    out(f"{count:>5}x port {port}")
out("\n##############################################\n")

with open(cache_file, "w", encoding="utf-8") as f:
    json.dump(geo_cache, f, indent=2, ensure_ascii=False)

msg = EmailMessage()
msg["Subject"] = f"{os.getenv('server_name')} Daily report {today}"
msg["From"] = os.getenv("u_name")
msg["To"] = os.getenv("email_to")
msg.set_content("\n".join(report))

with smtplib.SMTP_SSL(os.getenv("smtp_host"), int(os.getenv("smtp_port"))) as server:
    server.login(os.getenv("u_name"), os.getenv("pass"))
    server.send_message(msg)

print("Email sent!")