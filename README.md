# `wgcfcat`

Like `netcat`, but over `Cloudflare WARP`!

Usage:
```
Usage of wgcfcat:
  -a, --accept-warp-tos     Accept the Cloudflare WARP Terms Of Service (reqired)
  -c, --config-dir string   Runtime directory where connection parameters will be stored
  -h, --host string         Host to connect to over cloudflare WARP
      --keepalive uint      Keepalive interval in seconds
  -p, --port uint           Port to connect to over cloudflare WARP
```

## Example uses

Access a remote host over IPv6 on an IPv4-only connection by going through Cloudflare WARP:

```
$ ssh -o ProxyCommand='wgcfcat --accept-warp-tos -h %h -p %p' user@ipv6-host
```

Query an HTTP web server over WARP:
```
$ echo -e 'GET / HTTP/1.1\nHost: ipv6.google.com\n\n' | wgcfcat -a -h ipv6.google.com -p 80
```

