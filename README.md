# GRE tunnel based transparent proxy

Transparent proxy that preserves the client's real IP address for both TCP and UDP traffic. The server sees the original client IP instead of the proxy's IP, while all traffic still flows through the proxy.

Uses a GRE tunnel between proxy and server so the client's source IP is encapsulated inside legitimate outer packets. This works on providers that filter spoofed source IPs (e.g., NetCup, most VPS providers).

Note: For protocols that natively support proxying (e.g., HTTP with X-Forwarded-For), this approach is overengineering. Use it if your protocol doesn't support proxying or you can't/don't want to change it.

## How it works

```
Client ──► Proxy ══[GRE tunnel]══► Server app
           outer: src=ProxyIP dst=ServerIP (legit, not filtered)
           inner: src=ClientIP dst=ServerIP (preserved, app sees real client IP)
```

1. Client sends to proxy
2. Proxy DNATs to the server's tunnel IP and forwards through GRE — the client's real source IP is preserved inside the tunnel
3. Server receives the packet on the tunnel interface with the real client IP
4. Server replies — ipset identifies the reply as proxied traffic, marks it, and routes it back through the tunnel
5. SNAT fixes the source IP so the proxy's conntrack can match and un-DNAT the reply
6. Proxy sends the reply to the client as if it originated from the proxy

The application listens on a single port and handles both direct and proxied clients without any changes.
Direct clients connect to `$APP_PORT` on the server's public IP. Their traffic arrives on the server's physical interface (not `gre1`), so their (IP, port) pairs are never added to the ipset. Their replies are never marked and go out via the default route as usual.

The same client can connect through the proxy and directly at the same time. Each connection has a unique source port, and the ipset tracks (IP, port) pairs, so replies are routed independently per connection.

### Notes

- GRE is **not encrypted**. Between two servers in the same DC this is fine. For cross-DC traffic, consider WireGuard or GRE over IPsec.
- GRE uses IP protocol 47 (not a port number). Ensure the provider's firewall allows protocol 47 between the two servers.
- The `ip tunnel`, `ipset`, `iptables`, and `ip rule` commands do not survive reboot. They can also be flushed without a reboot — for example, `systemd-networkd` drops all manually-added `ip rule` entries when it restarts. Add them to a systemd unit, `/etc/network/interfaces`, or a startup script. Or use `proxymanager.py`
- The ipset timeout (60s default) should be tuned based on your application. For long-lived connections, increase it or refresh entries periodically.
- GRE adds 24 bytes of overhead per packet. Set the tunnel MTU to your physical interface MTU minus 24 (e.g., 1476 for 1500, 1276 for 1300). Check with `ip link show <interface>`. If the tunnel MTU is too high, TCP will recover via Path MTU Discovery (with some initial packet drops), but UDP packets will be fragmented or dropped.

## Setup (manual)

### Prerequisites

On the server:

```
apt install ipset xtables-addons-common -y
```

### Variables

- `$PROXY_IP` — proxy's public IP
- `$SERVER_IP` — server's public IP
- `$PROXY_PORT` — port clients connect to on the proxy
- `$APP_PORT` — port the application listens on
- `$GRE_LOCAL` — proxy's tunnel IP (e.g., `10.10.0.1`)
- `$GRE_REMOTE` — server's tunnel IP (e.g., `10.10.0.2`)
- `$PHYSICAL_MTU` — MTU of the physical interface (check with `ip link show`; typically 1500)

Make sure the tunnel IPs (`$GRE_LOCAL`, `$GRE_REMOTE`) do not overlap with any existing subnets on either machine (e.g., WireGuard, Docker, etc.).

### Proxy

#### 1. Enable IP forwarding

```
sysctl -w net.ipv4.ip_forward=1
```

#### 2. Create GRE tunnel

```
ip tunnel add gre1 mode gre remote $SERVER_IP local $PROXY_IP ttl 255
ip addr add $GRE_LOCAL/30 dev gre1
ip link set gre1 mtu $((PHYSICAL_MTU - 24))
ip link set gre1 up
```

#### 3. DNAT incoming traffic to the server through the tunnel

```
iptables -t nat -A PREROUTING -p tcp --dport $PROXY_PORT \
    -j DNAT --to-destination $GRE_REMOTE:$APP_PORT
iptables -t nat -A PREROUTING -p udp --dport $PROXY_PORT \
    -j DNAT --to-destination $GRE_REMOTE:$APP_PORT
```

### Server

#### 1. Enable IP forwarding

```
sysctl -w net.ipv4.ip_forward=1
```

#### 2. Create GRE tunnel

```
ip tunnel add gre1 mode gre remote $PROXY_IP local $SERVER_IP ttl 255
ip addr add $GRE_REMOTE/30 dev gre1
ip link set gre1 mtu $((PHYSICAL_MTU - 24))
ip link set gre1 up
```

#### 3. Disable reverse path filtering on the tunnel interface

Packets arriving on `gre1` have the client's real source IP, which the kernel can't route back via `gre1`. Without disabling rp_filter, the kernel drops these packets.

```
sysctl -w net.ipv4.conf.gre1.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0
```

#### 4. Disable conntrack on incoming tunnel traffic

Incoming GRE packets must be excluded from conntrack. Otherwise, conntrack creates an entry for the incoming packet that conflicts with the SNAT entry for the reply, causing the SNAT to remap the source port. The proxy then can't match the reply.

```
iptables -t raw -A PREROUTING -i gre1 -p tcp --dport $APP_PORT -j NOTRACK
iptables -t raw -A PREROUTING -i gre1 -p udp --dport $APP_PORT -j NOTRACK
```

#### 5. Track proxied connections with ipset

An ipset tracks which (client IP, client port) pairs arrived through the tunnel. Using `hash:ip,port` instead of `hash:ip` allows the same client to have simultaneous connections through the proxy and directly — each connection has a unique source port and is routed independently.

```
ipset create proxied_clients hash:ip,port timeout 60

iptables -t mangle -A PREROUTING -i gre1 -p tcp --dport $APP_PORT \
    -j SET --add-set proxied_clients src,src
iptables -t mangle -A PREROUTING -i gre1 -p udp --dport $APP_PORT \
    -j SET --add-set proxied_clients src,src
```

#### 6. Mark and SNAT replies to proxied clients

Mark replies whose (destination IP, destination port) match a known proxied connection. This triggers policy routing through the tunnel. Then SNAT the source IP to the tunnel IP so the proxy's conntrack can match and un-DNAT the reply.

```
iptables -t mangle -A OUTPUT -p tcp --sport $APP_PORT \
    -m set --match-set proxied_clients dst,dst -j MARK --set-mark 1
iptables -t mangle -A OUTPUT -p udp --sport $APP_PORT \
    -m set --match-set proxied_clients dst,dst -j MARK --set-mark 1

iptables -t nat -A POSTROUTING -o gre1 -p tcp --sport $APP_PORT \
    -j SNAT --to-source $GRE_REMOTE
iptables -t nat -A POSTROUTING -o gre1 -p udp --sport $APP_PORT \
    -j SNAT --to-source $GRE_REMOTE
```

#### 7. Policy routing for marked packets

```
ip rule add fwmark 1 table 100
ip route add default via $GRE_LOCAL table 100
```

## Setup (automatic)

Instead of running all the commands manually, you can use `proxymanager.py` to automatically manage the GRE tunnel and iptables rules. It reads a config file every minute and reconciles the actual state with the desired config — creating the tunnel if missing, adding new rules, and removing stale ones.

Requires Python 3.11+ and ipset installed on the server with `apt install ipset xtables-addons-common -y`.

### Config file

Create a `config.txt` (or any path you pass with `--config`):

```
# Tunnel configuration
PROXY_IP=1.2.3.4
SERVER_IP=5.6.7.8
GRE_LOCAL=10.10.0.1
GRE_REMOTE=10.10.0.2
PHYSICAL_MTU=1500

# Port mappings: proxy_port->app_port
101->50001
102->50002
103->50003
```

Each `proxy_port->app_port` line defines a port mapping. Add or remove lines and the manager will update the rules on the next cycle.

### Running

On the proxy:

```
sudo python3 proxymanager.py --proxy
```

On the server:

```
sudo python3 proxymanager.py --server
```

Options:

- `--config PATH` — config file path (default: `config.txt`)
- `--interval SECONDS` — how often to re-read config (default: 60)
- `--once` — apply config once and exit
- `-v` / `--verbose` — debug logging

### What it manages

- **Tunnel**: creates the GRE tunnel if it doesn't exist, checks that the tunnel subnet doesn't overlap with existing interfaces
- **Sysctl**: enables IP forwarding; on the server, disables reverse path filtering
- **ipset**: creates the `proxied_clients` ipset on the server
- **Policy routing**: adds the fwmark rule and route table on the server
- **iptables rules**: adds/removes all rules from the [Setup](#setup) section based on the port mappings in config — DNAT on the proxy; NOTRACK, SET, MARK, and SNAT on the server

## Testing

A simple UDP echo test is provided in `test/`.

On the server:

```
python test/server.py $APP_PORT
```

On the client (through the proxy):

```
python test/client.py $PROXY_IP $PROXY_PORT
```

The server prints the connecting client's IP and port. If the transparent proxy is working correctly, the server should show the client's real IP, not the proxy's.

## Debugging

### Packets not arriving at the server

Check if the GRE tunnel is up on both sides:

```
ip link show gre1
```

Check if packets arrive on the server's tunnel interface:

```
tcpdump -i gre1 -n udp dst port $APP_PORT
```

If nothing, check the proxy's DNAT rules and that the tunnel IPs are correct:

```
iptables -t nat -L PREROUTING -v -n    # on proxy
```

### Server receives packets but client gets no reply

This is the return path. Debug step by step:

**1. Check if ipset has the client IP:**

```
ipset list proxied_clients
```

If empty, the mangle PREROUTING SET rule isn't matching. Check:

```
iptables -t mangle -L PREROUTING -v -n
```

The `-i gre1 --dport $APP_PORT` SET rule should have a non-zero packet counter.

**2. Check if replies are being marked:**

```
iptables -t mangle -L OUTPUT -v -n
```

The MARK rule's packet counter should increment when you send a test packet.

**3. Check if marked packets route correctly:**

```
ip route get <CLIENT_IP> mark 1
```

Should show `via $GRE_LOCAL dev gre1 table 100 src $GRE_REMOTE`.

**4. Check if the reply enters the tunnel:**

```
tcpdump -i gre1 -n udp src port $APP_PORT
```

If nothing, add a LOG rule after the MARK to inspect:

```
iptables -t mangle -A OUTPUT -m mark --mark 1 -j LOG --log-prefix "MARKED: "
dmesg | grep MARKED
```

**5. Check if the reply arrives at the proxy:**

```
tcpdump -i gre1 -n udp    # on proxy
```

Verify the source port matches `$APP_PORT`. If the port is different (e.g., random high port), the NOTRACK rule in step 4 is missing — conntrack is remapping the port due to a tuple conflict.

**6. Check if the proxy forwards to the client:**

```
conntrack -L -p udp | grep <CLIENT_IP>    # on proxy
```

The conntrack entry should show the DNAT and the reply should be matched.

### `OSError: [Errno 126] Required key not available`

The application's reply is being routed through a WireGuard or IPsec tunnel that doesn't have a peer configured for the client's IP. This means the policy routing (table 100) is pointing to the wrong interface.

Check:

```
ip route show table 100
```

The route should point to `dev gre1`, not `dev wg0` or another tunnel. Fix with:

```
ip route replace default via $GRE_LOCAL dev gre1 table 100
```

Also ensure `$GRE_LOCAL` / `$GRE_REMOTE` don't overlap with other tunnel subnets.

## Cleanup

To remove the proxy without affecting other iptables rules.

### Proxy

```
iptables -t nat -D PREROUTING -p tcp --dport $PROXY_PORT \
    -j DNAT --to-destination $GRE_REMOTE:$APP_PORT
iptables -t nat -D PREROUTING -p udp --dport $PROXY_PORT \
    -j DNAT --to-destination $GRE_REMOTE:$APP_PORT

ip tunnel del gre1

sysctl -w net.ipv4.ip_forward=0    # only if nothing else needs it
```

### Server

```
iptables -t raw -D PREROUTING -i gre1 -p tcp --dport $APP_PORT -j NOTRACK
iptables -t raw -D PREROUTING -i gre1 -p udp --dport $APP_PORT -j NOTRACK

iptables -t mangle -D PREROUTING -i gre1 -p tcp --dport $APP_PORT \
    -j SET --add-set proxied_clients src,src
iptables -t mangle -D PREROUTING -i gre1 -p udp --dport $APP_PORT \
    -j SET --add-set proxied_clients src,src

iptables -t mangle -D OUTPUT -p tcp --sport $APP_PORT \
    -m set --match-set proxied_clients dst,dst -j MARK --set-mark 1
iptables -t mangle -D OUTPUT -p udp --sport $APP_PORT \
    -m set --match-set proxied_clients dst,dst -j MARK --set-mark 1

iptables -t nat -D POSTROUTING -o gre1 -p tcp --sport $APP_PORT \
    -j SNAT --to-source $GRE_REMOTE
iptables -t nat -D POSTROUTING -o gre1 -p udp --sport $APP_PORT \
    -j SNAT --to-source $GRE_REMOTE

ip rule del fwmark 1 table 100
ip route del default via $GRE_LOCAL table 100

ip tunnel del gre1

ipset destroy proxied_clients

sysctl -w net.ipv4.conf.all.rp_filter=1    # only if nothing else needs it off
sysctl -w net.ipv4.ip_forward=0             # only if nothing else needs it
```