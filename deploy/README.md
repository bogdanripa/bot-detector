# Deploying the honeypot on GCP (free tier, $0)

The honeypot must **terminate its own TLS** (own the socket) to capture JA3/JA4 +
header order — so it runs on a plain VM, **never behind a load balancer / managed
TLS**. GCP's always-free `e2-micro` is a perfect fit.

Total cost target: **$0** — free VM + free DuckDNS domain + free Let's Encrypt cert.

---

## 1. Create the free VM

Always-free `e2-micro` is free only in **us-west1 / us-central1 / us-east1**.

```bash
gcloud compute instances create honeypot \
  --machine-type=e2-micro \
  --zone=us-central1-a \
  --image-family=debian-12 --image-project=debian-cloud \
  --tags=http-server,https-server

# open 80 (ACME challenge + redirect) and 443
gcloud compute firewall-rules create allow-web \
  --allow=tcp:80,tcp:443 --target-tags=http-server,https-server

# note the external IP
gcloud compute instances describe honeypot --zone=us-central1-a \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)'
```

(The ephemeral external IP is free while the instance runs; it changes on
stop/start. Reserving a static IP attached to the running VM is also free.)

## 2. Free domain (DuckDNS) → point it at the IP

Autocert (Let's Encrypt) needs a hostname. Get a free one at
<https://www.duckdns.org> (sign in, pick `yourname.duckdns.org`, set its IP to the
VM's external IP). Any domain you control works; DuckDNS is just the free option.

## 3. One-time setup on the VM

```bash
gcloud compute ssh honeypot --zone=us-central1-a
# on the VM:
sudo useradd --system --home /opt/honeypot --shell /usr/sbin/nologin honeypot || true
sudo mkdir -p /opt/honeypot/certs && sudo chown -R honeypot:honeypot /opt/honeypot
```

Install the service unit (copy `deploy/honeypot.service` up, or paste it), then
**edit `BD_DOMAIN`** to your DuckDNS name:

```bash
sudo nano /etc/systemd/system/honeypot.service     # set BD_DOMAIN=yourname.duckdns.org
sudo systemctl daemon-reload
sudo systemctl enable honeypot
```

## 4. Deploy the binary (from your laptop)

The binary is self-contained (web pages, client JS, and scoring config are
embedded) — you copy exactly one file.

```bash
HOST=USER@VM_IP ./deploy/deploy.sh
```

First start, autocert fetches a cert from Let's Encrypt (needs :80 reachable — the
firewall rule above). Then browse to **https://yourname.duckdns.org/** — a real
cert, no warnings.

## 5. Automated deploy via GitHub Actions

`.github/workflows/deploy.yml` builds the binary and ships it over SSH on every
push to `main` (or via **Run workflow** / `workflow_dispatch`). The one-time VM
setup above is the prerequisite; the Action only updates the binary + restarts.

**a) A locked-down deploy user on the VM** (owns `/opt/honeypot`, one sudo rule):

```bash
# on the VM
sudo useradd -m -s /bin/bash deployer
sudo chown -R deployer:deployer /opt/honeypot           # deployer writes the binary…
sudo chown -R honeypot:honeypot /opt/honeypot/certs     # …honeypot writes the certs
echo 'deployer ALL=(root) NOPASSWD: /usr/bin/systemctl restart honeypot' \
  | sudo tee /etc/sudoers.d/deployer-honeypot
sudo chmod 440 /etc/sudoers.d/deployer-honeypot
```

**b) A deploy SSH key** (keep the private half in GitHub, put the public half on
the VM):

```bash
# on your laptop
ssh-keygen -t ed25519 -f deploy_key -N '' -C 'gh-actions-deploy'
# add the PUBLIC key to the VM's deployer user:
ssh-copy-id -i deploy_key.pub deployer@VM_IP     # or append deploy_key.pub to ~deployer/.ssh/authorized_keys
# host key for pinning (optional but recommended):
ssh-keyscan VM_IP
```

**c) Repo secrets** (Settings → Secrets and variables → Actions):

| Secret | Value |
|--------|-------|
| `DEPLOY_HOST` | `deployer@VM_IP` |
| `DEPLOY_SSH_KEY` | contents of the **private** `deploy_key` |
| `DEPLOY_KNOWN_HOSTS` | (optional) the `ssh-keyscan VM_IP` output — pins the host key |

**d) SSH reachability:** the runner needs port **22** open to the VM. GCP's
`default-allow-ssh` rule usually covers this; GitHub runner IPs are dynamic, so 22
is open to the internet (fine for a demo — harden later with IAP/a bastion, or
restrict to GitHub's published IP ranges).

Push to `main` → the workflow tests, builds a static binary, scp's it, and
restarts the service. Rollbacks are just a revert + push.

## 6. (Optional) full IP→ASN coverage

Built-in cloud ranges work out of the box. For every routed IP, drop the free
iptoasn table on the VM and point `BD_IPASN_TSV` at it:

```bash
curl -sSL -o /opt/honeypot/ip2asn-v4.tsv.gz https://iptoasn.com/data/ip2asn-v4.tsv.gz
# uncomment BD_IPASN_TSV in honeypot.service, then: sudo systemctl restart honeypot
```

---

## Config (env vars, set in the service unit)

| Var | Default | Meaning |
|-----|---------|---------|
| `BD_ADDR` | `:8443` (unit sets `:443`) | listen address |
| `BD_DOMAIN` | — | domain for Let's Encrypt autocert (enables real TLS) |
| `BD_CERT` / `BD_KEY` | — | use your own cert files instead of autocert |
| `BD_CERT_CACHE` | `certs` | autocert cert cache dir (writable) |
| `BD_ENFORCE_BAND` | `suspicious` | `/test` block threshold — aggressive; `automated` = conservative |
| `BD_IPASN_TSV` | — | path to the iptoasn table for full IP coverage |
| `BD_WEB_DIR`/`BD_CLIENT_JS`/`BD_SCORING` | embedded | disk overrides (dev only) |

## Notes / gotchas

- **Never** put GCP HTTPS Load Balancer, Cloud CDN, or Cloudflare (proxied) in
  front — they terminate TLS and Layer 3 is lost. The VM's external IP is direct;
  keep it that way.
- Free-tier **egress** is 1 GB/mo from North America — plenty for a demo; heavy
  traffic could incur cost. Set a billing budget alert to be safe.
- HTTP/2 is intentionally off (we speak http/1.1 for reliable header-order
  capture), so JA4's ALPN field shows `h1`. That's expected.
