# dynamic-shodan

A small self-hosted web app that shows what Shodan can see on your home or office connection, even when that connection has a dynamic public IP.

1. It resolves your **dynamic DNS hostname** on a schedule to find your current public IP.
2. It keeps an **IP history**: one entry for each continuous stretch you held an address, with first-seen and last-seen timestamps.
3. It pulls **Shodan host intel** for the current IP and **disregards stale findings**. Any service Shodan recorded *before* the address became yours most likely belongs to the previous holder, so it's shown separately and not counted.

The app is a single binary with the standard library only (no cgo), and the templates and CSS are embedded. It builds for Windows, macOS, Linux and BSD.

## Run

```sh
go run .                       # UI on http://127.0.0.1:8080/
```

Then open **Configuration** and enter:

- **Shodan API key**: from account.shodan.io. Host lookups don't use query credits. Use *Test API key* to check it.
- **Hostname**: your DDNS name, for example `myhome.duckdns.org`.
- **DNS server** (optional): query a specific server directly (for example your DDNS provider's authoritative nameserver or `1.1.1.1`) to avoid stale caches or split-horizon answers.
- **Intervals**: how often to re-resolve the hostname (default 10 min) and how often to re-query Shodan for an unchanged IP (default 12 h). Shodan is always re-queried right away when the IP changes.

### Flags

| Flag | Default | |
|---|---|---|
| `-listen` | `127.0.0.1:8080` | Address for the web UI |
| `-data` | user config dir + `/dynamic-shodan` | Where `config.json` and `state.json` live |
| `-auth` | env `DYNAMIC_SHODAN_AUTH` | Optional HTTP basic auth, `user:password`. Set this if you listen on anything other than loopback. |

The default data directory is `%AppData%\dynamic-shodan` on Windows, `~/Library/Application Support/dynamic-shodan` on macOS, and `~/.config/dynamic-shodan` on Linux. The API key is stored there in plain text (mode 0600 on Unix). It is never sent back to the browser.

## Container

The image follows [LinuxServer.io](https://www.linuxserver.io/) conventions. It is built on `ghcr.io/linuxserver/baseimage-alpine` with s6-overlay, the app runs as user `abc` mapped to `PUID`/`PGID`, and all state lives in `/config`. Images are multi-arch (`amd64`, `arm64`) and published to GHCR by CI.

### docker-compose

```yaml
services:
  dynamic-shodan:
    image: ghcr.io/<owner>/dynamic-shodan:latest
    container_name: dynamic-shodan
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=Etc/UTC
      - DYNAMIC_SHODAN_AUTH=admin:change-me   # optional, recommended
    volumes:
      - /path/to/dynamic-shodan/config:/config
    ports:
      - 8080:8080
    restart: unless-stopped
```

### docker cli

```sh
docker run -d \
  --name=dynamic-shodan \
  -e PUID=1000 -e PGID=1000 -e TZ=Etc/UTC \
  -e DYNAMIC_SHODAN_AUTH=admin:change-me \
  -p 8080:8080 \
  -v /path/to/dynamic-shodan/config:/config \
  --restart unless-stopped \
  ghcr.io/<owner>/dynamic-shodan:latest
```

| Parameter | Function |
|---|---|
| `-p 8080:8080` | Web UI |
| `-e PUID=1000` | User ID that owns `/config` |
| `-e PGID=1000` | Group ID that owns `/config` |
| `-e TZ=Etc/UTC` | Timezone used for displayed timestamps |
| `-e UMASK=022` | Optional umask for created files |
| `-e DYNAMIC_SHODAN_AUTH=user:pass` | Optional HTTP basic auth for the UI |
| `-v /config` | `config.json` (settings and API key) and `state.json` (IP history and cached intel) |

Inside the container, the hostname is resolved with the container's DNS. If you run local split-horizon DNS, set a public resolver on the Configuration page so you get the real public address.

## Build for other platforms

```sh
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -o dist/dynamic-shodan-linux-amd64 .
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -o dist/dynamic-shodan-linux-arm64 .   # Raspberry Pi 4/5
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -o dist/dynamic-shodan-darwin-arm64 .
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o dist/dynamic-shodan-windows-amd64.exe .
```

PowerShell: `$env:GOOS='linux'; $env:GOARCH='arm64'; $env:CGO_ENABLED='0'; go build -o dist/dynamic-shodan-linux-arm64 .`

## How staleness is decided

- Each Shodan service banner has a `timestamp`, the time Shodan's crawler observed it.
- Each scan is matched to the ownership period it was fetched in. A service is **current** if its timestamp is on or after that period's *first seen*. Otherwise it is **stale**, and its reason is shown, for example: "observed 2026-10-23, before this IP was yours (since 2026-11-18)".
- Vulnerabilities are aggregated **from current services only**.
- If you get an old address back (A → B → A), only findings from the latest stretch of A count.
- **First run caveat:** the app can only know you've had an address since it first saw it. If you've had the same IP for longer, go to **IP history** and set the real start date. Older findings then count as current.
- Ownership changes are detected at the check interval, so the true switch happened somewhere between the previous IP's *last seen* and the new IP's *first seen*. The app uses *first seen* as the boundary, which errs on the side of discarding. A shorter check interval narrows the gap.

## Endpoints

- `/`: dashboard (`/?ip=X` shows cached intel for a previous IP)
- `/history`: IP ownership history
- `/config`: settings
- `GET /api/status`: JSON summary (current IP, ownership, current services and vulnerabilities, stale count, last error)

Form posts are protected against cross-site requests (`http.CrossOriginProtection`), and pages send a strict CSP.

## Development

```sh
go test ./...
go vet ./...
```

Layout: `internal/model` (types and staleness rules), `internal/store` (JSON persistence and IP history), `internal/shodan` (API client), `internal/monitor` (scheduler), `internal/web` (handlers, embedded templates and CSS).
