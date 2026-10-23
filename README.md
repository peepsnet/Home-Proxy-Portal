# Home Portal

Password-protected gateway to the web servers on your LAN, through ONE port.

1. `apt install python3-aiohttp`
2. Edit `config.json` targets (auto-created on first run).
3. Set a password:   `python3 portal.py --set-password`
4. Add TLS (`tls_cert` / `tls_key` in config.json) BEFORE forwarding the port
   on your router. Or put Caddy in front and set `"behind_https_proxy": true`.

## Option A: systemd (Linux)

    sudo useradd -r -s /usr/sbin/nologin homeportal
    sudo mkdir /opt/home-portal && sudo cp portal.py requirements.txt /opt/home-portal/
    cd /opt/home-portal
    sudo python3 -m venv venv && sudo venv/bin/pip install -r requirements.txt
    sudo chown -R homeportal:homeportal /opt/home-portal
    sudo -u homeportal venv/bin/python portal.py --set-password
    sudo cp home-portal.service /etc/systemd/system/
    sudo systemctl daemon-reload && sudo systemctl enable --now home-portal
    journalctl -u home-portal -f          # logs

## Option B: Docker

    docker compose build
    docker compose run --rm portal python portal.py --set-password
    # edit ./data/config.json (targets, TLS paths like /data/cert.pem)
    docker compose up -d

Containers reach LAN IPs (192.168.x.x) normally. Use the LAN IP of each
server, not `localhost`, in config.json targets.

## Config options

| key | meaning |
|---|---|
| listen_port | port to listen on (forward this on your router) |
| session_hours | login lifetime |
| tls_cert / tls_key | PEM files for built-in HTTPS |
| behind_https_proxy | true if Caddy/nginx terminates TLS in front |
| inject_back_button | show the floating "Portal" button on proxied pages |
| targets | list of `{id, name, url}` (id: letters, digits, `_`, `-`) |

## Notes
- The back button is only added to top-level HTML page loads. Pages with a
  strict Content-Security-Policy may block its hover effect; the link still works.
- Apps using absolute paths (`/static/...`) are routed to the server you opened last.
