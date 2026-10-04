# Daily report in python:

Parses `auth.log` and `ufw.log` and sends a daily email report:  
failed SSH logins, successful logins, attacked users, blocked IPs and ports.

IP geolocation results are cached in `geo_cache.json` to save API calls.

## Requirements:
- `pip install dotenv --break-system-packages`

## Setup:
- `cp .env.example .env`
- `nano .env`               #Fill all SMTP settings


The script reports on the current day, so run it shortly before midnight:

`55 23 * * * /usr/bin/python3 /script/location/here`