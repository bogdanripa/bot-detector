# Deploying the honeypot on GCP (free tier, $0)

The honeypot must **terminate its own TLS** (own the socket) to capture JA3/JA4 +
header order — so it runs on a plain VM, **never behind a load balancer / managed
TLS**. GCP's always-free `e2-micro` is a perfect fit.

Two ways to deploy. **Option A needs no terminal** (great from a phone).

---

## Option A — zero-terminal, pull-based (recommended)

How it works: the GitHub Action (`.github/workflows/deploy.yml`, job `release`)
builds the binary and publishes it as the **`latest` GitHub Release**. The VM runs
a tiny **updater timer** that pulls that binary every ~2 min and restarts. No SSH,
no secrets, no Cloud Shell — you just create a VM with a 2-line startup script.

**Prereq:** push to `main` at least once so the release exists (check the repo's
**Actions** tab shows a green run, and **Releases** shows `latest`).

1. **GCP Console → Compute Engine → Create instance** (all taps):
   - Name `honeypot`; Region **us-central1** (or us-west1 / us-east1 — required for
     free tier); Machine type **e2-micro**.
   - Boot disk: **Debian 12** (default).
   - Firewall: check **Allow HTTP traffic** and **Allow HTTPS traffic**.
   - Expand **Advanced options → Management → Automation → Startup script**, and
     paste (this pastes into a web form, not a terminal — works on mobile):

     ```bash
     #! /bin/bash
     curl -fsSL https://raw.githubusercontent.com/bogdanripa/bot-detector/main/deploy/vm-bootstrap.sh | bash
     ```
   - **Create**.

2. Wait ~2–3 minutes (boot + first pull). Find the VM's **External IP** in the
   instance list.

3. Visit **`https://EXTERNAL_IP/`**. It's a self-signed cert for now → tap
   **Advanced → proceed**. Try `/test` (blocks bots) and `/debug` (shows the
   report).

**Future deploys are automatic:** push to `main` → the Action rebuilds + republishes
the release → the VM's timer pulls it within ~2 min.

### Optional: real cert (no warning) — also no terminal

1. Get a free `you.duckdns.org` at <https://www.duckdns.org> and point it at the
   VM's External IP.
2. GCP Console → your VM → **Edit → Metadata → Add item**: key `bd-domain`, value
   `you.duckdns.org` → **Save**. (Optionally key `bd-enforce` = `automated` to make
   `/test` less aggressive; default is `suspicious`.)

Within ~2 min the updater re-reads the metadata, fetches a Let's Encrypt cert, and
restarts. Visit `https://you.duckdns.org/` — clean cert.

---

## Option B — SSH push (needs a terminal / laptop)

Build locally and ship over SSH. Don't mix with Option A on the same VM (the
Option-A updater would overwrite a hand-pushed binary).

```bash
# create the VM (from a machine with gcloud)
gcloud compute instances create honeypot --machine-type=e2-micro --zone=us-central1-a \
  --image-family=debian-12 --image-project=debian-cloud --tags=http-server,https-server
gcloud compute firewall-rules create allow-web --allow=tcp:80,tcp:443 \
  --target-tags=http-server,https-server

# one-time VM setup (creates users, systemd unit, deploy access)
#   sudo bash setup-vm.sh '<deploy-ssh-public-key>' ['<domain>']
# then from your laptop:
HOST=deployer@VM_IP ./deploy/deploy.sh          # build linux/amd64 + scp + restart
```

`deploy/setup-vm.sh` is the one-time bootstrap for this mode. For CI push
(build-and-ssh on every push) you'd re-add an SSH deploy job; Option A's
release-pull model replaced it here to keep the phone path secret-free.

---

## Config (env vars / metadata)

| Var | Where | Default | Meaning |
|-----|-------|---------|---------|
| `BD_DOMAIN` | metadata `bd-domain` (A) / env (B) | — | domain for Let's Encrypt autocert; empty → self-signed |
| `BD_ENFORCE_BAND` | metadata `bd-enforce` (A) / env (B) | `suspicious` | `/test` block threshold — aggressive; `automated` = conservative |
| `BD_ADDR` | env | `:443` (prod) | listen address |
| `BD_CERT`/`BD_KEY` | env | — | use your own cert files instead of autocert |
| `BD_IPASN_TSV` | env | — | path to the free iptoasn table for full IP coverage |

## Notes / gotchas

- **Never** put GCP HTTPS Load Balancer, Cloud CDN, or Cloudflare (proxied) in
  front — they terminate TLS and Layer 3 is lost. Keep the VM's external IP direct.
- Free-tier egress is 1 GB/mo from North America — plenty for a demo; set a billing
  budget alert to be safe.
- HTTP/2 is intentionally off (http/1.1 for reliable header-order capture), so JA4's
  ALPN field shows `h1`. Expected.
- The repo must be **public** for the VM to pull the release + scripts anonymously.
