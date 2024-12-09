# `wgcfcat`

Like `netcat`, but over [`Cloudflare WARP`](https://1.1.1.1)!

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
$ echo -e 'GET / HTTP/1.1\r\nHost: ipv6.google.com\r\n\r\n' | wgcfcat -a -h ipv6.google.com -p 80
```

## Credits

- wgcf - an unofficial, cross-platform CLI for Cloudflare WARP - https://github.com/ViRb3/wgcf
- wireguard-go - Go userland implementation of the WireGuard protocol - https://git.zx2c4.com/wireguard-go/about

## Notice of Non-Affiliation and Disclaimer

I am not affiliated, associated, authorized, endorsed by, or in any way officially connected with Cloudflare, or any of its subsidiaries or its affiliates. The official Cloudflare website can be found at https://www.cloudflare.com/.

The names Cloudflare Warp and Cloudflare as well as related names, marks, emblems and images are registered trademarks of their respective owners.
