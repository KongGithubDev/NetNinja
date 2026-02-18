# netninja proxy

dns bypass forward proxy. written in go.

## what it does

routes traffic through google/cloudflare dns to get around dns filters.
specific domains (geforcenow, nvidia) go direct — everything else gets proxied.

## run

```bash
go build -o proxy.exe proxy.go
PORT=5988 ./proxy.exe
```

## env vars

| var | default | what |
|-----|---------|------|
| `PORT` | `8080` | listen port |
| `PROXY_ADDR` | auto | override proxy addr in pac file |

## endpoints

- `/` or `/status` — dashboard
- `/proxy.pac` — auto-proxy config file

## behind caddy (https)

run proxy on 5988, let caddy handle tls:

```bat
set PORT=5988
set PROXY_ADDR=proxy.netninja.kongwatcharapong.in.th:5988
proxy.exe
```

caddyfile:
```
https://proxy.netninja.kongwatcharapong.in.th {
    tls /path/to/cert.pem /path/to/key.pem
    reverse_proxy 127.0.0.1:5988
}
```

cloudflare dns: A record, dns only (gray cloud)

## ipad setup

settings > wifi > (i) > proxy > automatic

pac url: `https://proxy.netninja.kongwatcharapong.in.th/proxy.pac`

## bypass domains

these skip the proxy:
- `*.geforcenow.nvidiagrid.net`
- `*.nvidia.com`
- `*.nvidiagrid.net`

edit `directDomains` in proxy.go to change.

## files

- `proxy.go` — main proxy
- `debug.js` — debug proxy w/ logging
- `dns.go` — doh forwarder
