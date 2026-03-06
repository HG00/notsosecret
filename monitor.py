#!/usr/bin/env python3
"""
Certificate Transparency Discovery Demo
Tails Zeek conn.log / http.log / ssh.log and displays incoming probes in real-time.

Run Zeek first:
    sudo zeek -i <interface> -C

Then:
    python3 monitor.py

Press R inside the TUI to fire a Let's Encrypt certificate request.

Configuration is read from demo.conf in the same directory as this script.
CLI flags override config file values.
"""

import argparse
import configparser
import select
import subprocess
import sys
import termios
import threading
import time
import tty
from collections import deque
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

SCRIPT_DIR = Path(__file__).parent

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

WATCH_PORTS   = {22, 80, 443}
RATE_WINDOWS  = [1, 10, 60]
MAX_LOG       = 200
POLL_INTERVAL = 0.25

PORT_META = {
    22:  ("SSH",   "cyan"),
    80:  ("HTTP",  "green"),
    443: ("HTTPS", "bright_green"),
}

CONN_STATE = {
    "S0":   "SYN, no reply",
    "S1":   "established",
    "SF":   "closed normally",
    "REJ":  "RST",
    "RSTO": "orig reset",
    "RSTR": "resp reset",
    "SH":   "SYN+FIN",
    "OTH":  "other",
}

# ---------------------------------------------------------------------------
# Zeek TSV tailer
# ---------------------------------------------------------------------------

class ZeekTailer:
    def __init__(self, path: Path) -> None:
        self.path   = path
        self.fields: list[str] = []
        self._fh    = None
        self._pos   = 0

    def _open(self) -> bool:
        try:
            fh = open(self.path)
            for line in fh:
                if line.startswith("#fields\t"):
                    self.fields = line.strip().split("\t")[1:]
            self._fh  = fh
            self._pos = fh.tell()
            return True
        except OSError:
            return False

    def open(self) -> bool:
        return self._open()

    def poll(self) -> list[dict]:
        if self._fh is None:
            self._open()
            return []
        try:
            size = self.path.stat().st_size
        except OSError:
            self._fh = None
            return []
        if size < self._pos:
            self._fh.close()
            self._open()
            return []
        self._fh.seek(self._pos)
        rows: list[dict] = []
        for line in self._fh:
            line = line.rstrip("\n")
            if line.startswith("#fields\t"):
                self.fields = line.strip().split("\t")[1:]
                continue
            if line.startswith("#") or not line:
                continue
            if not self.fields:
                continue
            parts = line.split("\t")
            if len(parts) != len(self.fields):
                continue
            rows.append(dict(zip(self.fields, parts)))
        self._pos = self._fh.tell()
        return rows

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

event_times_v4: deque[float] = deque()
event_times_v6: deque[float] = deque()
log_entries: deque[dict]     = deque(maxlen=MAX_LOG)
total_v4     = 0
total_v6     = 0
port_counts: dict[int, int]  = {p: 0 for p in WATCH_PORTS}
HTTP_CACHE_MAX = 10_000
http_cache: dict[str, dict] = {}

monitor_started_at:        datetime | None = None
first_probe_at:            datetime | None = None
first_probe_after_cert_at: datetime | None = None
peak_rate_v4 = 0.0
peak_rate_v6 = 0.0

cert_requested_at: datetime | None = None
cert_status        = ""
stop_flag          = threading.Event()

public_ipv4: str = ""
public_ipv6: str = ""

# ---------------------------------------------------------------------------
# IP discovery
# ---------------------------------------------------------------------------

def fetch_public_ips(domain: str) -> None:
    global public_ipv4, public_ipv6
    for flag, target in [("-4", "public_ipv4"), ("-6", "public_ipv6")]:
        try:
            r = subprocess.run(
                ["curl", flag, "-s", "--max-time", "3", "https://icanhazip.com"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                ip = r.stdout.strip()
                if ip:
                    globals()[target] = ip
        except Exception:
            pass


def print_dns_setup(domain: str) -> None:
    """Print DNS and firewall instructions as static text before the Live TUI starts."""
    if not public_ipv4 and not public_ipv6:
        return
    print()
    print("  Set the following DNS records before requesting a certificate:")
    print()
    if public_ipv4:
        print(f"    A     {domain}  →  {public_ipv4}")
    if public_ipv6:
        print(f"    AAAA  {domain}  →  {public_ipv6}")
    print()
    print("  Ensure your firewall / cloud security group allows inbound TCP:")
    print("    22 (SSH)   80 (HTTP)   443 (HTTPS)")
    print()

# ---------------------------------------------------------------------------
# Log processors
# ---------------------------------------------------------------------------

def process_conn(row: dict) -> dict | None:
    global total_v4, total_v6, first_probe_at, first_probe_after_cert_at

    try:
        port = int(row.get("id.resp_p", 0))
    except ValueError:
        return None
    if port not in WATCH_PORTS:
        return None
    if row.get("local_orig") == "T":
        return None

    src_ip = row.get("id.orig_h", "?")
    ts_raw = row.get("ts", "")
    state  = row.get("conn_state", "")
    uid    = row.get("uid", "")

    try:
        ts = datetime.fromtimestamp(float(ts_raw))
    except (ValueError, OSError):
        ts = datetime.now()

    is_v6 = ":" in src_ip
    if is_v6:
        event_times_v6.append(time.time())
        total_v6 += 1
    else:
        event_times_v4.append(time.time())
        total_v4 += 1

    port_counts[port] = port_counts.get(port, 0) + 1

    if first_probe_at is None:
        first_probe_at = ts
    if cert_requested_at is not None and first_probe_after_cert_at is None:
        if ts >= cert_requested_at:
            first_probe_after_cert_at = ts

    label, color = PORT_META.get(port, (str(port), "white"))

    return {
        "time":        ts,
        "ip":          src_ip,
        "is_v6":       is_v6,
        "port":        port,
        "label":       label,
        "color":       color,
        "state_label": CONN_STATE.get(state, state),
        "uid":         uid,
    }


def process_http(row: dict) -> None:
    uid = row.get("uid", "")
    if uid:
        if len(http_cache) >= HTTP_CACHE_MAX:
            # Drop oldest quarter to avoid unbounded growth
            for k in list(http_cache)[:HTTP_CACHE_MAX // 4]:
                del http_cache[k]
        http_cache[uid] = {
            "method": row.get("method", ""),
            "host":   row.get("host", ""),
            "uri":    row.get("uri", ""),
            "ua":     row.get("user_agent", ""),
        }


def process_ssh(row: dict) -> None:
    uid    = row.get("uid", "")
    client = row.get("client", "")
    if uid and client:
        http_cache[uid] = {"method": "SSH", "host": "", "uri": "", "ua": client}

# ---------------------------------------------------------------------------
# Rate
# ---------------------------------------------------------------------------

def calculate_rates() -> tuple[dict[int, float], dict[int, float]]:
    now    = time.time()
    cutoff = now - max(RATE_WINDOWS)
    for q in (event_times_v4, event_times_v6):
        while q and q[0] < cutoff:
            q.popleft()
    v4 = {w: sum(1 for t in event_times_v4 if t >= now - w) / w for w in RATE_WINDOWS}
    v6 = {w: sum(1 for t in event_times_v6 if t >= now - w) / w for w in RATE_WINDOWS}
    return v4, v6

# ---------------------------------------------------------------------------
# Certbot
# ---------------------------------------------------------------------------

def _install_https_nginx(domain: str, nginx_template: Path) -> None:
    """Substitute domain into the full nginx template and reload nginx."""
    template = nginx_template.read_text()
    config   = template.replace("DOMAIN", domain)
    dest     = "/etc/nginx/sites-available/ct-demo"
    with open(dest, "w") as f:
        f.write(config)
    subprocess.run(["nginx", "-t"], check=True, capture_output=True, timeout=10)
    subprocess.run(["nginx", "-s", "reload"], check=True, timeout=10)


def request_cert(domain: str, email: str, log_path: Path, nginx_template: Path) -> None:
    global cert_requested_at, cert_status
    cert_requested_at = datetime.now()
    cert_status       = "requesting…"

    cmd = [
        "certbot", "certonly",
        "--webroot", "-w", "/var/www/html",
        "--non-interactive",
        "--agree-tos",
        "-m", email,
        "-d", domain,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        with open(log_path, "a") as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"certbot run: {cert_requested_at.isoformat()}\n")
            f.write(f"command: {' '.join(cmd)}\n")
            f.write(f"exit code: {result.returncode}\n")
            if result.stdout:
                f.write(f"--- stdout ---\n{result.stdout}\n")
            if result.stderr:
                f.write(f"--- stderr ---\n{result.stderr}\n")

        if result.returncode == 0:
            cert_status = "obtained — enabling HTTPS…"
            try:
                _install_https_nginx(domain, nginx_template)
                cert_status = "obtained — nginx reloaded with HTTPS"
            except Exception as e:
                cert_status = f"obtained — nginx reload failed: {e}"
        else:
            lines = [l.strip() for l in result.stderr.splitlines() if l.strip()]
            reason = lines[-1][:60] if lines else "unknown error"
            cert_status = f"failed: {reason}"
    except subprocess.TimeoutExpired:
        cert_status = "failed: timeout"
    except Exception as e:
        cert_status = f"failed: {e}"

# ---------------------------------------------------------------------------
# Keyboard input (background thread)
# ---------------------------------------------------------------------------

def keyboard_thread(domain: str, email: str, log_path: Path, nginx_template: Path) -> None:
    fd  = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while not stop_flag.is_set():
            r, _, _ = select.select([sys.stdin], [], [], 0.2)
            if not r:
                continue
            ch = sys.stdin.read(1).lower()
            if ch == "r" and cert_requested_at is None:
                t = threading.Thread(target=request_cert,
                                     args=(domain, email, log_path, nginx_template), daemon=True)
                t.start()
            elif ch == "q":
                stop_flag.set()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def fmt_elapsed(since: datetime) -> str:
    secs = int((datetime.now() - since).total_seconds())
    h, rem = divmod(secs, 3600)
    m, s   = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def _rate_style(r: float) -> str:
    return "bold red" if r > 5 else "bold yellow" if r > 0.5 else "white"


def build_display(log_dir: Path, domain: str,
                  rates_v4: dict | None = None,
                  rates_v6: dict | None = None) -> Layout:
    if rates_v4 is None or rates_v6 is None:
        rates_v4, rates_v6 = calculate_rates()

    header = Text()

    # ---- row 1: domain + ports ----
    header.append("Domain: ", style="dim")
    header.append(domain, style="bold white")
    header.append("  |  Watching: ", style="dim")
    for p in sorted(WATCH_PORTS):
        lbl, col = PORT_META[p]
        header.append(f":{p}", style=f"bold {col}")
        header.append(f"({lbl}) ", style="dim")
    header.append("\n")

    # ---- row 2: IPv4 rate ----
    header.append("IPv4  ", style="bold white")
    for w in RATE_WINDOWS:
        r = rates_v4[w]
        header.append(f"{w}s: ", style="dim")
        header.append(f"{r:.2f}/s  ", style=_rate_style(r))
    header.append(f"  Total: {total_v4}", style="white")
    header.append("\n")

    # ---- row 3: IPv6 rate ----
    header.append("IPv6  ", style="bold cyan")
    for w in RATE_WINDOWS:
        r = rates_v6[w]
        header.append(f"{w}s: ", style="dim")
        header.append(f"{r:.2f}/s  ", style=_rate_style(r))
    header.append(f"  Total: {total_v6}", style="cyan")
    header.append("\n")

    # ---- row 3: cert status ----
    if cert_requested_at is None:
        header.append("[R] ", style="bold green")
        header.append("request certificate", style="dim")
    else:
        elapsed = fmt_elapsed(cert_requested_at)
        header.append("Cert requested ", style="dim")
        header.append(elapsed, style="bold yellow")
        header.append(" ago  |  ", style="dim")
        status_style = (
            "bold green"  if cert_status.startswith("obtained")  else
            "bold red"    if cert_status.startswith("failed")     else
            "bold yellow"
        )
        header.append(cert_status, style=status_style)

    # ---- log table ----
    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold dim",
        expand=True,
        padding=(0, 1),
    )
    table.add_column("Time",   style="dim", width=10, no_wrap=True)
    table.add_column("Source",              width=42, no_wrap=True)
    table.add_column("Port",               width=7,  no_wrap=True)
    table.add_column("State",              width=14, no_wrap=True)
    table.add_column("Info",               ratio=1)

    for entry in list(log_entries):
        t     = entry["time"].strftime("%H:%M:%S")
        label = Text(entry["label"], style=entry["color"])
        state = Text(entry["state_label"], style="dim")

        info  = ""
        extra = http_cache.get(entry["uid"])
        if extra:
            parts = []
            if extra["method"] and extra["uri"]:
                parts.append(f'{extra["method"]} {extra["uri"][:60]}')
            if extra["host"]:
                parts.append(f'Host:{extra["host"]}')
            if extra["ua"]:
                parts.append(f'UA:{extra["ua"][:50]}')
            info = "  ".join(parts)

        ip_style = "cyan" if entry["is_v6"] else "white"
        table.add_row(t, Text(entry["ip"], style=ip_style), label, state,
                      Text(info, style="dim", no_wrap=True))

    layout = Layout()
    layout.split_column(
        Layout(
            Panel(header,
                  title="[bold blue]CT Discovery Demo[/bold blue]  [dim]Q to quit[/dim]",
                  border_style="blue"),
            name="header",
            size=8,
        ),
        Layout(table, name="log"),
    )
    return layout

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def load_config() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(SCRIPT_DIR / "demo.conf")
    return cfg


def main() -> None:
    cfg = load_config()
    c   = cfg["demo"] if "demo" in cfg else {}

    parser = argparse.ArgumentParser(description="CT Discovery Demo — Zeek monitor")
    parser.add_argument("--log-dir", default=c.get("log_dir", "."),
                        help="Zeek log directory (default: .)")
    parser.add_argument("--domain",  default=c.get("domain", ""),
                        help="Domain to request a certificate for")
    parser.add_argument("--email",   default=c.get("email", ""),
                        help="Email address for Let's Encrypt registration")
    parser.add_argument("--nginx-template",
                        default=c.get("nginx_template", str(SCRIPT_DIR / "nginx.conf")),
                        help="Path to nginx.conf template (default: nginx.conf next to this script)")
    args = parser.parse_args()

    if not args.domain:
        print("Error: domain not set. Add 'domain = ...' to demo.conf or pass --domain.")
        sys.exit(1)
    if not args.email:
        print("Error: email not set. Add 'email = ...' to demo.conf or pass --email.")
        sys.exit(1)

    log_dir = Path(args.log_dir)

    conn_tailer = ZeekTailer(log_dir / "conn.log")
    http_tailer = ZeekTailer(log_dir / "http.log")
    ssh_tailer  = ZeekTailer(log_dir / "ssh.log")

    if not conn_tailer.open():
        print(f"Warning: {log_dir / 'conn.log'} not found yet — waiting for first connection…")

    http_tailer.open()
    ssh_tailer.open()

    nginx_template = Path(args.nginx_template)
    if not nginx_template.exists():
        print(f"Warning: nginx template not found at {nginx_template} — HTTPS config won't be installed after cert issuance")

    log_path = log_dir / "certbot.log"
    kb = threading.Thread(target=keyboard_thread,
                          args=(args.domain, args.email, log_path, nginx_template), daemon=True)
    kb.start()

    fetch_public_ips(args.domain)
    print_dns_setup(args.domain)
    if public_ipv4 or public_ipv6:
        input("  Press Enter when DNS is configured (or to skip)… ")

    global monitor_started_at, peak_rate_v4, peak_rate_v6
    monitor_started_at = datetime.now()

    console = Console()
    with Live(build_display(log_dir, args.domain), console=console,
              refresh_per_second=4, screen=True) as live:
        try:
            while not stop_flag.is_set():
                for row in http_tailer.poll():
                    process_http(row)
                for row in ssh_tailer.poll():
                    process_ssh(row)
                for row in conn_tailer.poll():
                    entry = process_conn(row)
                    if entry:
                        log_entries.appendleft(entry)
                rv4, rv6 = calculate_rates()
                peak_rate_v4 = max(peak_rate_v4, rv4[1])
                peak_rate_v6 = max(peak_rate_v6, rv6[1])
                live.update(build_display(log_dir, args.domain, rv4, rv6))
                time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            stop_flag.set()

    print_report(args.domain, console)


def print_report(domain: str, console: Console) -> None:
    from rich.rule import Rule

    def delta(a: datetime, b: datetime) -> str:
        secs = int((b - a).total_seconds())
        if secs < 0:
            return "—"
        h, r = divmod(secs, 3600)
        m, s = divmod(r, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    now      = datetime.now()
    duration = delta(monitor_started_at, now) if monitor_started_at else "—"

    console.print()
    console.rule("[bold blue]CT Discovery Demo — Session Report[/bold blue]")
    console.print()

    # ---- session ----
    console.print(f"  [dim]Domain:[/dim]            {domain}")
    console.print(f"  [dim]Session duration:[/dim]  {duration}")
    if monitor_started_at:
        console.print(f"  [dim]Started:[/dim]           {monitor_started_at.strftime('%H:%M:%S')}")
    console.print()

    # ---- probe totals ----
    console.rule("[dim]Probe totals[/dim]", style="dim")
    total = total_v4 + total_v6

    def port_breakdown() -> str:
        parts = [f":{p} {port_counts.get(p, 0)}" for p in sorted(WATCH_PORTS)]
        return "  ".join(parts)

    console.print(f"  [white]IPv4[/white]   {total_v4:>6}    {port_breakdown() if total_v4 else ''}")
    console.print(f"  [cyan]IPv6[/cyan]   {total_v6:>6}")
    console.print(f"  [bold]Total[/bold]  {total:>6}")
    console.print()

    # ---- peak rates ----
    console.rule("[dim]Peak rates[/dim]", style="dim")
    console.print(f"  [white]IPv4[/white]   {peak_rate_v4:.2f}/s")
    console.print(f"  [cyan]IPv6[/cyan]   {peak_rate_v6:.2f}/s")
    console.print()

    # ---- timing ----
    console.rule("[dim]Timing[/dim]", style="dim")
    if monitor_started_at and first_probe_at:
        console.print(f"  First probe after monitor start:  {delta(monitor_started_at, first_probe_at)}")
    else:
        console.print("  First probe:  none recorded")

    if cert_requested_at and monitor_started_at:
        console.print(f"  Certificate requested at:         {cert_requested_at.strftime('%H:%M:%S')}  "
                      f"({delta(monitor_started_at, cert_requested_at)} after start)")
        console.print(f"  Cert request status:              {cert_status or '—'}")
        if first_probe_after_cert_at:
            console.print(f"  First probe after cert request:   {delta(cert_requested_at, first_probe_after_cert_at)}")
        else:
            console.print("  First probe after cert request:   none recorded")
    else:
        console.print("  No certificate was requested this session.")

    console.print()


if __name__ == "__main__":
    main()
