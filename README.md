# mdnsproxy

mdnsproxy is a small DNS server that lets any DNS client resolve Multicast DNS (mDNS/Avahi/Bonjour) names by querying the
`.local` domain. When it receives a query for a `.local` name, it sends it to the local network over mDNS (IPv4 multicast) and
returns the first answer. Reverse (PTR) lookups for private and link-local IPv4 addresses (10.0.0.0/8, 172.16.0.0/12,
192.168.0.0/16, 169.254.0.0/16) are resolved over mDNS too. All other queries are forwarded to upstream DNS servers, so it
can be used as a regular forwarding DNS server (instead of 8.8.8.8 or your provider's DNS servers).

## Why?

To give mDNS access to machines that don't support it natively (Android before 13, old Windows machines, small IoT devices).
And to learn Go.

## Building

You need Go 1.24 or newer. To build, run:

```sh
go build
```

I'm using mdnsproxy on a Raspberry Pi. To cross-compile on my Linux machine, I do:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build
```

## Running

mdnsproxy accepts the following flags:

```
  -chroot string
    	Directory to chroot to
  -listen string
    	Address to listen on (default "0.0.0.0:53")
  -timeout int
    	Timeout for DNS queries (seconds) (default 1)
  -timestamp
    	Add timestamp to log entries
  -upstream string
    	Comma-separated addresses of upstream DNS servers (default "8.8.8.8")
  -user string
    	User to run as after dropping root (default "nobody")
```

mdnsproxy needs to be started as root (or with `CAP_NET_BIND_SERVICE`) to bind port 53. When started as root, it chroots
and switches to the user given by `-user` as soon as it has bound the listen port. `-chroot` defaults to that user's home
directory. On many systems (e.g. Debian, Ubuntu, Raspberry Pi OS) the home directory of `nobody` is `/nonexistent`, so
running as root with the default flags will fail; use a dedicated user with a real home directory, or pass `-chroot`
explicitly.

Non-local queries are forwarded to the servers listed in `-upstream`, tried in order until one answers. Each entry must be an
IPv4 address. `-timeout` applies to each attempt, both mDNS and upstream.

mdnsproxy logs one line per query to stderr, and timestamps log entries if `-timestamp` was used.

To check that it works, query it for a `.local` name on your network:

```sh
dig @192.168.1.2 myprinter.local
```

### Using it from other machines

To make clients use mdnsproxy, set the IP address of the machine running it as the DNS server, either in your router's DHCP
settings (affects the whole network) or in each device's network settings.

### Limitations

* Only UDP is supported; there is no TCP fallback for large (truncated) responses.
* mDNS queries are sent over IPv4 only.
* Only the first mDNS response is returned, even if several hosts answer.

## systemd

The included [unit file](mdnsproxy.service) can be used to start mdnsproxy automatically. It assumes a user `mdnsproxy`
exists, the program binary is at `/usr/local/bin/mdnsproxy`, and it chroots to `/home/mdnsproxy/chroot`. It also sets
`-timeout 10`, so an unanswered `.local` query takes 10 seconds to fail; lower it if your clients give up sooner.

The binary is started as root, so it should not be writable by the `mdnsproxy` user. To set everything up:

```sh
sudo useradd --system --create-home --shell /usr/sbin/nologin mdnsproxy
sudo mkdir /home/mdnsproxy/chroot
sudo install -m 755 mdnsproxy /usr/local/bin/mdnsproxy
sudo cp mdnsproxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mdnsproxy.service
```
