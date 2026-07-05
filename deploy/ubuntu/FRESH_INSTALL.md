# Fresh Ubuntu install — full command list

Everything needed to go from a bare Ubuntu server to a working MikroTik
auto-provisioning system. Commands assume you're root; prefix with `sudo`
otherwise.

## 1. Log in and update the OS

```bash
ssh root@<SERVER_IP>

apt update && apt -y upgrade
apt -y install git
# if the upgrade pulled a new kernel:  reboot  (then ssh back in)
```

## 2. Get the code

```bash
cd /opt
git clone https://github.com/VysionISP/wireguard.git mtprov
cd mtprov
```

## 3. Deploy

The script installs Node.js, WireGuard, builds the project, creates the
tunnel, config and systemd service, and prints the bootstrap one-liner:

```bash
deploy/ubuntu/deploy.sh \
    --public-url http://<SERVER_IP>:8442 \
    --endpoint-host <SERVER_IP>
```

(If you have a DNS name pointed at the server, use
`--public-url https://<name>` instead and put caddy/nginx in front —
see "HTTPS" below.)

## 4. Firewall (recommended)

Fresh Ubuntu usually has ufw installed but inactive. **Allow SSH before
enabling** or you'll lock yourself out:

```bash
ufw allow OpenSSH
ufw allow 51820/udp comment "WireGuard"
ufw allow 8442/tcp comment "provisioning HTTP"
ufw enable
```

## 5. Check everything is up

```bash
systemctl status mtprov --no-pager     # provisioning server
systemctl status wg-quick@wg0 --no-pager
wg show wg0                            # tunnel + peers
curl http://127.0.0.1:8442/healthz     # {"ok":true}
journalctl -u mtprov -f                # live logs (ctrl-c to exit)
```

## 6. Provision a router

Print the one-liner (also shown at the end of the deploy):

```bash
cd /opt/mtprov
node dist/cli.js bootstrap
```

Paste that one line into a terminal on a factory-fresh RouterOS v7 device
(Winbox → New Terminal, serial, or MAC-telnet). ~10 seconds later:

```bash
node dist/cli.js list                  # router appears, state "confirmed"
node dist/cli.js show <serial>         # tunnel IP + management credentials
node dist/cli.js verify <serial>       # handshake + REST check over the tunnel
```

Talk to the router over the tunnel from the server:

```bash
ssh wg-mgmt@<tunnelIp>                             # password from `show`
curl -u wg-mgmt:<password> http://<tunnelIp>/rest/system/resource
```

## Day-to-day

```bash
node dist/cli.js list                  # fleet overview
node dist/cli.js revoke <serial>       # kick a router off the VPN permanently
systemctl restart mtprov               # after editing config.json
node dist/cli.js sync                  # re-apply peers manually (serve does this on start)
```

## Updating the code

```bash
cd /opt/mtprov
git pull
npm ci && npm run build
systemctl restart mtprov
```

## HTTPS (recommended once you have a DNS name)

The registration response contains router credentials, so once a DNS name
points at the server:

```bash
apt -y install caddy
cat > /etc/caddy/Caddyfile <<'EOF'
provision.example.com {
    reverse_proxy 127.0.0.1:8442
}
EOF
systemctl restart caddy
ufw allow 80/tcp && ufw allow 443/tcp
```

Then edit `publicUrl` in `/opt/mtprov/config.json` to
`https://provision.example.com`, run `systemctl restart mtprov`, and
consider closing the plain port: `ufw delete allow 8442/tcp`
(the proxy reaches it on localhost). Already-provisioned routers are
unaffected — only new bootstraps use the URL.
