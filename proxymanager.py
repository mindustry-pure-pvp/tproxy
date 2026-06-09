#!/usr/bin/env python3
"""
Manages GRE tunnel and iptables rules for transparent proxying.
Reads config.txt every minute and applies changes automatically.

Usage:
    python proxymanager.py --proxy    # Run on the proxy server
    python proxymanager.py --server   # Run on the application server
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import re
import subprocess
import time
from typing import Literal, TypeAlias

Role: TypeAlias = Literal["proxy", "server"]
Settings: TypeAlias = dict[str, str]
PortMapping: TypeAlias = tuple[int, int]
IptablesRule: TypeAlias = tuple[str, str, str]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("proxymanager")

CONFIG_PATH = "config.txt"
TUNNEL_NAME = "gre1"
IPSET_NAME = "proxied_clients"
FWMARK = "1"
ROUTE_TABLE = "100"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd: str, check: bool = True) -> str | None:
    """Run a shell command, return stdout. Logs on failure."""
    log.debug("+ %s", cmd)
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        log.error("Command failed: %s\nstderr: %s", cmd, r.stderr.strip())
        return None
    return r.stdout.strip()


def run_ok(cmd: str) -> bool:
    """Return True if command exits 0."""
    r = subprocess.run(cmd, shell=True, capture_output=True)
    return r.returncode == 0


# ---------------------------------------------------------------------------
# Config parsing
# ---------------------------------------------------------------------------

def parse_config(path: str) -> tuple[Settings | None, list[PortMapping] | None]:
    """Parse config.txt, return (settings_dict, list_of_(proxy_port, app_port))."""
    settings: Settings = {}
    mappings: list[PortMapping] = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line and "->" not in line:
                    key, val = line.split("=", 1)
                    settings[key.strip()] = val.strip()
                elif "->" in line:
                    left, right = line.split("->", 1)
                    mappings.append((int(left.strip()), int(right.strip())))
    except FileNotFoundError:
        log.error("Config file not found: %s", path)
        return None, None
    except Exception as e:
        log.error("Failed to parse config: %s", e)
        return None, None

    required = ["PROXY_IP", "SERVER_IP", "GRE_LOCAL", "GRE_REMOTE", "PHYSICAL_MTU"]
    for key in required:
        if key not in settings:
            log.error("Missing required setting: %s", key)
            return None, None

    return settings, mappings


# ---------------------------------------------------------------------------
# Tunnel management
# ---------------------------------------------------------------------------

def get_existing_subnets() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Return a list of ipaddress networks from all interfaces (excluding lo)."""
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    output = run("ip -o addr show", check=False)
    if not output:
        return nets
    for line in output.splitlines():
        parts = line.split()
        iface = parts[1] if len(parts) > 1 else ""
        if iface == "lo":
            continue
        for i, p in enumerate(parts):
            if p in ("inet", "inet6") and i + 1 < len(parts):
                try:
                    nets.append(ipaddress.ip_network(parts[i + 1], strict=False))
                except ValueError:
                    pass
    return nets


def tunnel_exists() -> bool:
    """Check if the GRE tunnel interface exists."""
    return run_ok(f"ip link show {TUNNEL_NAME}")


def check_subnet_overlap(gre_local: str, gre_remote: str) -> bool:
    """Check if the tunnel subnet overlaps with existing subnets."""
    tunnel_net = ipaddress.ip_network(f"{gre_local}/30", strict=False)
    for net in get_existing_subnets():
        if net.version != tunnel_net.version:
            continue
        if tunnel_net.overlaps(net):
            log.warning(
                "Tunnel subnet %s overlaps with existing network %s",
                tunnel_net, net,
            )
            return True
    return False


def ensure_tunnel(settings: Settings, role: Role) -> bool:
    """Create the GRE tunnel if it doesn't exist."""
    if tunnel_exists():
        log.debug("Tunnel %s already exists", TUNNEL_NAME)
        if role == "server":
            ensure_ipset()
            ensure_policy_routing(settings)
        return True

    proxy_ip = settings["PROXY_IP"]
    server_ip = settings["SERVER_IP"]
    gre_local = settings["GRE_LOCAL"]
    gre_remote = settings["GRE_REMOTE"]
    mtu = int(settings["PHYSICAL_MTU"]) - 24

    if role == "proxy":
        local_ip, remote_ip = proxy_ip, server_ip
        tunnel_ip = gre_local
    else:
        local_ip, remote_ip = server_ip, proxy_ip
        tunnel_ip = gre_remote

    if check_subnet_overlap(gre_local, gre_remote):
        log.error("Aborting tunnel creation due to subnet overlap")
        return False

    cmds = [
        f"ip tunnel add {TUNNEL_NAME} mode gre remote {remote_ip} local {local_ip} ttl 255",
        f"ip addr add {tunnel_ip}/30 dev {TUNNEL_NAME}",
        f"ip link set {TUNNEL_NAME} mtu {mtu}",
        f"ip link set {TUNNEL_NAME} up",
    ]
    for cmd in cmds:
        if run(cmd) is None:
            return False

    log.info("Created tunnel %s (local=%s remote=%s tunnel_ip=%s mtu=%d)",
             TUNNEL_NAME, local_ip, remote_ip, tunnel_ip, mtu)

    if role == "proxy":
        run("sysctl -w net.ipv4.ip_forward=1")
    else:
        run("sysctl -w net.ipv4.ip_forward=1")
        run(f"sysctl -w net.ipv4.conf.{TUNNEL_NAME}.rp_filter=0")
        run("sysctl -w net.ipv4.conf.all.rp_filter=0")
        ensure_ipset()
        ensure_policy_routing(settings)

    return True


# ---------------------------------------------------------------------------
# ipset & policy routing (server only, created once)
# ---------------------------------------------------------------------------

def ipset_exists() -> bool:
    return run_ok(f"ipset list {IPSET_NAME}")


def ensure_ipset() -> None:
    if not ipset_exists():
        run(f"ipset create {IPSET_NAME} hash:ip,port timeout 60")
        log.info("Created ipset %s", IPSET_NAME)


def ensure_policy_routing(settings: Settings) -> None:
    """Add fwmark routing rule and route if missing."""
    rules = run("ip rule show") or ""
    if f"fwmark 0x{int(FWMARK):x}" not in rules and f"fwmark {FWMARK}" not in rules:
        run(f"ip rule add fwmark {FWMARK} table {ROUTE_TABLE}")
        log.info("Added ip rule fwmark %s -> table %s", FWMARK, ROUTE_TABLE)

    routes = run(f"ip route show table {ROUTE_TABLE}") or ""
    gre_local = settings["GRE_LOCAL"]
    if f"via {gre_local}" not in routes:
        run(f"ip route add default via {gre_local} table {ROUTE_TABLE}")
        log.info("Added default route via %s in table %s", gre_local, ROUTE_TABLE)


# ---------------------------------------------------------------------------
# iptables rule management
# ---------------------------------------------------------------------------

def iptables_rule_exists(table: str, chain: str, rule_args: str) -> bool:
    """Check if an iptables rule exists using -C (check)."""
    return run_ok(f"iptables -t {table} -C {chain} {rule_args}")


def add_rule(table: str, chain: str, rule_args: str) -> bool:
    if not iptables_rule_exists(table, chain, rule_args):
        if run(f"iptables -t {table} -A {chain} {rule_args}") is not None:
            log.info("Added: iptables -t %s -A %s %s", table, chain, rule_args)
            return True
    return False


def remove_rule(table: str, chain: str, rule_args: str) -> bool:
    if iptables_rule_exists(table, chain, rule_args):
        if run(f"iptables -t {table} -D {chain} {rule_args}") is not None:
            log.info("Removed: iptables -t %s -D %s %s", table, chain, rule_args)
            return True
    return False


# ---------------------------------------------------------------------------
# Build the desired rule sets
# ---------------------------------------------------------------------------

def proxy_rules_for_mapping(proxy_port: int, app_port: int, gre_remote: str) -> list[IptablesRule]:
    """Return list of (table, chain, rule_args) for one mapping on the proxy."""
    rules: list[IptablesRule] = []
    for proto in ("tcp", "udp"):
        rules.append((
            "nat", "PREROUTING",
            f"-p {proto} --dport {proxy_port} -j DNAT --to-destination {gre_remote}:{app_port}",
        ))
    return rules


def server_rules_for_mapping(app_port: int, gre_remote: str) -> list[IptablesRule]:
    """Return list of (table, chain, rule_args) for one mapping on the server."""
    rules: list[IptablesRule] = []
    for proto in ("tcp", "udp"):
        # NOTRACK incoming
        rules.append((
            "raw", "PREROUTING",
            f"-i {TUNNEL_NAME} -p {proto} --dport {app_port} -j NOTRACK",
        ))
        # ipset add in mangle PREROUTING
        rules.append((
            "mangle", "PREROUTING",
            f"-i {TUNNEL_NAME} -p {proto} --dport {app_port} -j SET --add-set {IPSET_NAME} src,src",
        ))
        # MARK replies in mangle OUTPUT
        rules.append((
            "mangle", "OUTPUT",
            f"-p {proto} --sport {app_port} -m set --match-set {IPSET_NAME} dst,dst -j MARK --set-mark {FWMARK}",
        ))
        # SNAT replies in nat POSTROUTING
        rules.append((
            "nat", "POSTROUTING",
            f"-o {TUNNEL_NAME} -p {proto} --sport {app_port} -j SNAT --to-source {gre_remote}",
        ))
    return rules


def get_desired_rules(role: Role, settings: Settings, mappings: list[PortMapping]) -> list[IptablesRule]:
    """Build the full set of desired rules from config."""
    gre_remote = settings["GRE_REMOTE"]
    all_rules: list[IptablesRule] = []
    for proxy_port, app_port in mappings:
        if role == "proxy":
            all_rules.extend(proxy_rules_for_mapping(proxy_port, app_port, gre_remote))
        else:
            all_rules.extend(server_rules_for_mapping(app_port, gre_remote))
    return all_rules


# ---------------------------------------------------------------------------
# Discover currently managed rules (by pattern matching against known format)
# ---------------------------------------------------------------------------

def get_current_managed_rules(role: Role, settings: Settings) -> list[IptablesRule]:
    """List rules currently in iptables that match our pattern."""
    gre_remote = settings["GRE_REMOTE"]
    found: list[IptablesRule] = []

    if role == "proxy":
        output = run("iptables -t nat -S PREROUTING") or ""
        for line in output.splitlines():
            # Match our DNAT rules to GRE_REMOTE
            m = re.search(
                r'-A PREROUTING -p (tcp|udp) (?:-m \w+ )?--dport (\d+) -j DNAT --to-destination '
                + re.escape(gre_remote) + r':(\d+)',
                line,
            )
            if m:
                proto, proxy_port, app_port = m.group(1), m.group(2), m.group(3)
                rule_args = f"-p {proto} --dport {proxy_port} -j DNAT --to-destination {gre_remote}:{app_port}"
                found.append(("nat", "PREROUTING", rule_args))
    else:
        for table, chain, cmd_flag in [
            ("raw", "PREROUTING", "-S PREROUTING"),
            ("mangle", "PREROUTING", "-S PREROUTING"),
            ("mangle", "OUTPUT", "-S OUTPUT"),
            ("nat", "POSTROUTING", "-S POSTROUTING"),
        ]:
            output = run(f"iptables -t {table} {cmd_flag}") or ""
            for line in output.splitlines():
                if table == "raw" and "-j NOTRACK" in line:
                    m = re.search(
                        r'-A PREROUTING -i ' + TUNNEL_NAME + r' -p (tcp|udp) (?:-m \w+ )?--dport (\d+) -j NOTRACK',
                        line,
                    )
                    if m:
                        proto, port = m.group(1), m.group(2)
                        found.append(("raw", "PREROUTING",
                                      f"-i {TUNNEL_NAME} -p {proto} --dport {port} -j NOTRACK"))

                elif table == "mangle" and chain == "PREROUTING" and "--add-set" in line:
                    m = re.search(
                        r'-A PREROUTING -i ' + TUNNEL_NAME + r' -p (tcp|udp) (?:-m \w+ )?--dport (\d+) -j SET --add-set '
                        + IPSET_NAME + r' src,src',
                        line,
                    )
                    if m:
                        proto, port = m.group(1), m.group(2)
                        found.append(("mangle", "PREROUTING",
                                      f"-i {TUNNEL_NAME} -p {proto} --dport {port} -j SET --add-set {IPSET_NAME} src,src"))

                elif table == "mangle" and chain == "OUTPUT" and ("--set-mark" in line or "--set-xmark" in line):
                    m = re.search(
                        r'-A OUTPUT -p (tcp|udp) (?:-m \w+ )?--sport (\d+) -m set --match-set '
                        + IPSET_NAME + r' dst,dst -j MARK --set-(?:x)?mark (?:0x)?' + FWMARK + r'(?:/0xffffffff)?',
                        line,
                    )
                    if m:
                        proto, port = m.group(1), m.group(2)
                        found.append(("mangle", "OUTPUT",
                                      f"-p {proto} --sport {port} -m set --match-set {IPSET_NAME} dst,dst -j MARK --set-mark {FWMARK}"))

                elif table == "nat" and "SNAT" in line:
                    m = re.search(
                        r'-A POSTROUTING -o ' + TUNNEL_NAME + r' -p (tcp|udp) (?:-m \w+ )?--sport (\d+) -j SNAT --to-source '
                        + re.escape(gre_remote),
                        line,
                    )
                    if m:
                        proto, port = m.group(1), m.group(2)
                        found.append(("nat", "POSTROUTING",
                                      f"-o {TUNNEL_NAME} -p {proto} --sport {port} -j SNAT --to-source {gre_remote}"))

    return found


# ---------------------------------------------------------------------------
# Reconcile: add missing rules, remove stale ones
# ---------------------------------------------------------------------------

def reconcile_rules(role: Role, settings: Settings, mappings: list[PortMapping]) -> None:
    desired = get_desired_rules(role, settings, mappings)
    current = get_current_managed_rules(role, settings)

    desired_set = set(desired)
    current_set = set(current)

    to_add = desired_set - current_set
    to_remove = current_set - desired_set

    for table, chain, rule_args in sorted(to_remove):
        remove_rule(table, chain, rule_args)

    for table, chain, rule_args in sorted(to_add):
        add_rule(table, chain, rule_args)

    if not to_add and not to_remove:
        log.debug("Rules are up to date")


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Transparent proxy manager")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--proxy", action="store_true", help="Run as proxy")
    group.add_argument("--server", action="store_true", help="Run as server")
    parser.add_argument("--config", default=CONFIG_PATH, help="Config file path")
    parser.add_argument("--interval", type=int, default=60, help="Check interval in seconds")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    parser.add_argument("--verbose", "-v", action="store_true", help="Debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    role: Role = "proxy" if args.proxy else "server"
    log.info("Starting proxymanager in %s mode (config=%s, interval=%ds)",
             role, args.config, args.interval)

    log.info("Sleeping for 10 seconds (startup delay to prevent race conditions)")
    time.sleep(10)

    while True:
        settings, mappings = parse_config(args.config)
        if settings is None or mappings is None:
            log.error("Skipping cycle due to config error")
        else:
            if not ensure_tunnel(settings, role):
                log.error("Tunnel not ready, skipping rule reconciliation")
            else:
                reconcile_rules(role, settings, mappings)

        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
