# Certificate Transparency Discovery Demo

## The problem this demonstrates

A common assumption among developers and sysadmins is that a new server is
safe until someone finds it — and that finding it requires guessing its name
or IP address.  Neither is true once you request a TLS certificate.

Every certificate issued by a publicly-trusted CA (Let's Encrypt, DigiCert,
etc.) must be submitted to one or more **Certificate Transparency logs** — a
set of public, append-only, globally-mirrored ledgers.  Anyone can watch the
live feed.  Automated scanners do exactly this, 24 hours a day, and will
probe a newly-appearing hostname within minutes of certificate issuance —
long before any real user has visited the site.

This means:

- A staging server, internal tool, or test environment that gets a TLS cert
  is immediately and publicly announced to every scanner on the internet.
- Attackers do not need to guess your hostname or brute-force your IP range.
  The CT feed hands it to them directly.
- "Security through obscurity" — keeping a hostname secret — is **not
  possible** once a certificate has been issued for it.

This demo makes that visible in real time.

## How it works

1. Zeek captures all incoming traffic on the server's public interface
2. The monitor displays a live feed of probes hitting ports 22, 80, and 443,
   with separate IPv4 and IPv6 rates shown side by side
3. Before a certificate is requested, the IPv6 rate should be near zero —
   mass internet scanners are overwhelmingly IPv4, and the host's IPv6 address
   has never appeared anywhere public
4. Press `R` to request a Let's Encrypt certificate for your domain
5. The hostname is published to the CT logs within seconds of issuance
6. Watch both rates climb as automated scanners discover and target the host —
   typically within minutes, without any other announcement

The split IPv4/IPv6 display makes the CT-driven discovery clearly visible:
IPv6 climbs from a clean zero baseline while IPv4 climbs from a low background
noise floor.  Both protocols get targeted because CT log scanners resolve the
domain and probe whatever addresses they find — A and AAAA alike.

---

## Requirements

- Linux host with a public IP address (IPv4 and/or IPv6)
- DNS `A` record (IPv4) and/or `AAAA` record (IPv6) pointing at your host —
  dual-stack gives the best demo: maximum scanner coverage with a clean IPv6
  baseline to show CT-driven discovery against
- `zeek`, `certbot`, `nginx` installed (handled by `install.sh`)
- Python 3.11+ with `rich` (`pip install rich`, handled by `install.sh`)
- `asciinema` (optional, for recording — also installed by `install.sh`)

---

## Quick start

```bash
git clone <this repo>
cd certificate_transparency_discovery
sudo bash install.sh
```

The installer will prompt for your domain, email address, and network
interface, then install all dependencies, configure nginx, and write
`demo.conf`.

---

## Manual setup

### 1. Configure

```bash
cp demo.conf.example demo.conf
```

Edit `demo.conf`:

```ini
[demo]
domain  = www.your-domain.example
email   = you@example.com
log_dir = .
```

### 2. Point DNS at your host

Create DNS records pointing at your host's public address(es).  Dual-stack
is recommended — both records together give maximum scanner coverage while
keeping a clean IPv6 baseline to contrast against:

```bash
# IPv4
dig A www.your-domain.example

# IPv6
dig AAAA www.your-domain.example
```

If you only have one address type, a single record is fine — the demo still
works, you just won't see the IPv4/IPv6 split in the rate display.

### 3. Install dependencies

```bash
python3 -m venv venv && source venv/bin/activate
pip install rich
sudo apt install zeek nginx certbot asciinema
```

### 4. Configure nginx

```bash
sudo sed "s/DOMAIN/www.your-domain.example/g" nginx.conf \
    > /etc/nginx/sites-available/ct-demo
sudo ln -s /etc/nginx/sites-available/ct-demo /etc/nginx/sites-enabled/ct-demo
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl start nginx
```

### 5. Start Zeek

Run Zeek on your public-facing interface from the demo directory so it writes
logs there:

```bash
cd /path/to/demo
sudo zeek -i <interface> -C
```

`-C` disables checksum validation, which is needed on most cloud instances
where the NIC offloads checksum computation.

### 6. Start the monitor

```bash
venv/bin/python3 monitor.py
```

Or with explicit overrides:

```bash
venv/bin/python3 monitor.py --domain www.your-domain.example \
                             --email you@example.com \
                             --log-dir /path/to/zeek/logs
```

---

## Running the demo

### Key bindings

| Key | Action |
|-----|--------|
| `R` | Request a Let's Encrypt certificate via certbot (runs in the background) |
| `Q` | Quit |

### What you will see

```
┌─ CT Discovery Demo ──────────────────────────── Q to quit ─┐
│ Domain: www.your-domain.example  |  Watching: :22(SSH) :80(HTTP) :443(HTTPS) │
│ Rate  1s: 0.00/s  10s: 0.00/s  60s: 0.00/s   Total: 0              │
│ [R] request certificate                                               │
└───────────────────────────────────────────────────────────────────────┘
 Time       Source                                     Port    State          Info
 ──────────────────────────────────────────────────────────────────────────────
 14:32:01   2a01:4f8::1                                HTTP    SYN, no reply
 14:32:04   2600:1f18::dead:beef                       SSH     RST
```

After pressing `R`, the header updates to show a live timer and cert status:

```
│ Cert requested 00:01:23 ago  |  obtained — nginx reloaded           │
```

Once the certificate is obtained, nginx is automatically reloaded and begins
serving HTTPS on port 443.

Rate colours: white = quiet, **yellow** = light scanning, **red** = active targeting.

HTTP scanner requests (method, path, User-Agent) are pulled from Zeek's
`http.log` and shown in the Info column.  You will quickly see scanners
probing for `/.env`, `/wp-admin`, `/phpmyadmin`, `/actuator`, etc.

### Certbot log

If the certificate request fails, the full certbot output is written to
`certbot.log` in the log directory.  Check it with:

```bash
cat certbot.log
```

Common causes of failure:
- Port 80 not reachable from the internet (firewall / security group rule)
- DNS not yet propagated when `R` was pressed
- Domain does not resolve to this host's IP

---

## How the certificate request works

certbot uses the **webroot** method: it places a challenge file under
`/var/www/html/.well-known/acme-challenge/` and Let's Encrypt fetches it
over HTTP through nginx.  This means:

- nginx must be running and serving port 80 before pressing `R`
- Nothing else needs to stop or restart
- Port 80 stays up throughout the challenge

After the certificate is issued, nginx is reloaded automatically and begins
serving HTTPS.

---

## Recording with asciinema

Install asciinema:

```bash
sudo apt install asciinema
```

Wrap the demo directly — recording starts and stops with the monitor:

```bash
asciinema rec ct-demo.cast --command "sudo bash run.sh"
```

Or start a recorded shell session and run commands manually:

```bash
asciinema rec ct-demo.cast
sudo bash run.sh
# press R when ready, then Q to exit
exit
```

Play back locally:

```bash
asciinema play ct-demo.cast
asciinema play --speed 2 ct-demo.cast    # 2× faster
asciinema play --speed 0.5 ct-demo.cast  # half speed
```

Share online:

```bash
asciinema upload ct-demo.cast
```

Or self-host: the `.cast` file is plain JSON, playable with the
[asciinema-player](https://github.com/asciinema/asciinema-player) embedded
in any webpage.
