# Running the relay behind nginx on a small host

The relay bounds its own memory and connections (see "Relay Memory" in
SECURITY.md). The reverse proxy in front of it and the kernel of the host
have limits of their own, shared by every site on the host, and with their
defaults they give out first. This page lists what to set and why, for the
bundled `docker-compose.yml` behind nginx on the same host.

The numbers come from a virtual machine built like a small production host:
one virtual CPU without AES instructions, 960 MB of memory, Debian 12 with
its kernel, nginx 1.22 and Docker 29, the relay in its 512 MiB container,
three other sites on the same nginx, and clients 40 ms away.

## What gives out with the defaults

- **nginx connections.** `worker_connections 768` (Debian's default) holds
  fewer than 400 proxied WebSocket connections, since each takes one
  connection to the client and one to the relay, and it is shared with
  every other site. At 380 legitimate connections nginx was refusing new
  ones, for all sites.
- **TCP memory of the host.** The kernel sizes `net.ipv4.tcp_mem` from the
  memory of the machine: on 1 GB, about 80 MiB for all TCP buffers
  together, and above 53 MiB it holds every socket to a small share. Left
  to grow, the buffers of nginx and docker-proxy reached that with 380
  legitimate connections exchanging pictures: 206 of 258 pictures were not
  delivered and most connections were closed. Small messages and pages
  still went through; large transfers stalled for every site.
- **Connection tracking.** With a firewall that tracks connections (ufw
  does), the kernel keeps every connection, and every closed one for two
  minutes, in a table of 8192 entries on 1 GB. 3000 connections opened and
  closed in a loop from 30 addresses filled it, and the kernel then dropped
  new connections to every service, SSH included.

## nginx

Main context and events:

```nginx
# Each proxied connection holds two descriptors; the soft limit inherited
# from systemd is 1024.
worker_rlimit_nofile 8192;
events {
    worker_connections 4096;
}
```

A connection costs nginx about 8 KB while it sends nothing, about 30 KB
while its request headers trickle in, and about 64 KB while it holds a TLS
handshake open: 3600 of those took nginx to 230 MB. With 2048 nginx stayed
at 130 MB, but against 3000 such connections from 30 addresses only 60% of
other clients' requests got through, against 100% with 4096.

`http` context. nginx takes these from the server that owns the listening
socket, before it knows which site a connection is for, so they apply to
every site:

```nginx
# TLS handshake and request headers must arrive within this time, counted
# once from the connection (default 60s).
client_header_timeout 15s;
# Longest pause between two reads of a request body (default 60s).
client_body_timeout 15s;
# Reset connections closed on a timeout, so that what is queued for a
# client that stopped reading is dropped at once instead of staying in an
# orphaned socket.
reset_timedout_connection on;

limit_conn_zone $binary_remote_addr zone=pinchat_ws_addr:10m;
limit_conn_zone $binary_remote_addr zone=pinchat_http_addr:10m;
limit_conn_zone $server_name zone=pinchat_total:1m;

# The container's fixed address on the compose network (see
# docker-compose.yml), not the published port: that port is served by
# docker-proxy, whose two extra sockets per connection grow their kernel
# buffers. nginx connects from the network's gateway, 172.18.0.1, which is
# what TRUSTED_PROXIES names.
upstream pinchat_backend {
    server 172.18.0.2:3000;
    keepalive 32;
}
```

On a CPU without AES instructions (check `grep -c aes /proc/cpuinfo`),
TLS encryption is the largest cost of relaying pictures: every receiver of
a group gets its own encrypted copy. ChaCha20-Poly1305 is a standard TLS
1.3 cipher suite, as strong as AES-GCM, and five times as fast there
(about 620 MB/s against 116 MB/s for AES-256-GCM on the machine above).
Clients that offer only AES still get it. It has to be set in the `http`
context; set for one server only, nginx 1.22 ignores it when the client
names the site in its handshake:

```nginx
ssl_conf_command Ciphersuites TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384;
ssl_conf_command Options ServerPreference,PrioritizeChaCha;
```

`ServerPreference` applies to TLS 1.2 as well: a TLS 1.2 client then gets
the first cipher of `ssl_ciphers` it supports (AES-128-GCM in the list
certbot installs) instead of its own first choice. `PrioritizeChaCha`
keeps ChaCha20-Poly1305 for a TLS 1.2 client that lists it first. Checked
with clients offering each order, with and without the name of a site, on
every site of the host: TLS 1.3 clients that offer ChaCha20 get it, those
that offer only AES-GCM get AES-128-GCM, and TLS 1.2 clients get what they
got before except that AES-128-GCM replaces AES-256-GCM.

The PinChat server:

```nginx
server {
    server_name your-domain www.your-domain;

    # Socket buffers fixed for every connection accepted on this port, for
    # all sites on it (they are options of the listening socket, and only
    # one listen directive per address and port may carry them). Without
    # them the kernel grows each buffer up to 4 to 6 MiB.
    listen 443 ssl sndbuf=128k rcvbuf=64k;
    listen [::]:443 ssl ipv6only=on sndbuf=128k rcvbuf=64k;

    # In total: above the relay's 400 WebSocket connections, with room for
    # the requests of the pages. Per address, for requests that are not
    # upgrades or static files. A location with limit_conn of its own does
    # not inherit these, so the locations below repeat the total.
    limit_conn pinchat_total 1200;
    limit_conn pinchat_http_addr 32;
    limit_conn_status 429;
    limit_req_status 429;

    location /ws/ {
        # Per address: above the relay's 50, so that the relay's own answer
        # (429 with Retry-After) comes first.
        limit_conn pinchat_total 1200;
        limit_conn pinchat_ws_addr 60;
        proxy_pass http://pinchat_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    location /static/ {
        # A page load fetches many files at once: no per-address limit.
        limit_conn pinchat_total 1200;
        proxy_pass http://pinchat_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
    }

    # /api/ and / as before, with X-Forwarded-For; they inherit both limits.
}
```

`sndbuf=128k` was the smallest size that did not slow pictures down: with
64k a picture took up to four minutes to reach every member under load,
because the data waited in the sockets between nginx and the relay
instead.

## Host

Connection tracking, 65536 entries of 256 bytes (16 MiB when full) and as
many hash buckets:

```
# /etc/modules-load.d/nf_conntrack.conf
nf_conntrack
# /etc/modprobe.d/nf_conntrack.conf
options nf_conntrack hashsize=65536
# /etc/sysctl.d/90-conntrack.conf
net.netfilter.nf_conntrack_max = 65536
```

All three are needed after a reboot: `systemd-sysctl` runs before the
firewall loads the module, so without `modules-load.d` the sysctl is
skipped, and with the module option alone the kernel sets the maximum to
eight times the bucket count. With these settings and nginx's defaults the
table still filled: nginx closed idle connections within a quarter of a
second to make room, and 84000 reconnections a minute left their entries
behind. It takes both.

Not recommended: capping the kernel's automatic buffer growth for the
host (`net.ipv4.tcp_rmem` and `tcp_wmem` at 512 KiB). It reduced the memory
held by the sockets between nginx and the relay, but the relay writes a
picture to one receiver at a time, and with less room in the kernel each
write waited longer: under the expected load 109 connections were closed
instead of 17.

## What this does and does not do

Measured with 200 legitimate connections (groups of 20 and one-to-one rooms
sending text and pictures) during each attack, as the share of requests
from a separate client to the four sites that succeeded:

| Attack | Defaults | Settings above |
|--------|----------|----------------|
| 3000 idle TCP connections from 30 addresses, reopened when closed | 40% | 100% |
| 3000 TLS handshakes left unfinished, reopened | 58% | 100% |
| 2000 requests whose headers arrive a line every 5 s | 63% | 100% |
| 1000 request bodies sent a byte every 5 s, from 50 addresses | 58% | 89% (PinChat answers 429, other sites 100%) |
| 400 WebSocket connections held from 8 addresses | 72% | 100% (the relay refuses the excess with 503) |
| 600 upgrades at the same moment from 12 addresses | 71% | 97% |

Without an attack, 380 connections (groups of 20 and one-to-one rooms, text
every 5 s, a picture every 30 s in each one-to-one room and two in each
group): with the defaults 52 of 258 pictures arrived, with the settings
above all 270, and in the groups 16 of 20 instead of 1, with the relay of
v0.9.0. The connections it still closed were the relay's own, receivers
more than 8 messages behind their room; with the ring of 64 of later
releases (see SECURITY.md) all 20 arrived in the groups and no connection
was closed. With the AES preference instead of ChaCha20 the pictures still
arrived, but nginx took 48% of the CPU instead of 27%, and PinChat's pages
took twice as long to answer (290 ms instead of 133 at the median, 898
instead of 383 at the 95th percentile).

It does not make the host immune:

- **Clients that stop reading.** 300 connections from 30 addresses that
  requested large responses and stopped reading took the host's TCP memory
  to its limit with either configuration: other clients' pages and text
  kept working, but 32 of 150 pictures arrived. The fixed buffers mean it
  takes hundreds of connections instead of a few dozen; the limits per
  address mean it takes several addresses.
- **WebSocket clients that send pictures to receivers that do not read.**
  From four addresses they hold the relay's budgets for large messages
  (see "Relay Memory" in SECURITY.md); with either configuration 30 to 41
  of 150 legitimate pictures arrived. nginx cannot tell them apart.
- **Many addresses.** Every limit per address is passed by enough
  addresses. Connections that never complete a TLS handshake are not
  counted by `limit_conn` (it counts a connection once its request headers
  are in) and cost nginx about 64 KB each until `client_header_timeout`;
  `worker_connections` is what bounds them, and with 4096 they can take
  nginx to about 260 MB.
- **Shared addresses.** Everyone behind one address (a carrier's NAT, an
  office) shares its 60 WebSocket connections and 32 requests in progress.
