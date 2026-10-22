# mdnsproxy

mdnsproxy allows all DNS clients to use Multicast DNS (mDNS/Avahi/Bonjour) through querying ``.local`` domain. When it receives a query in ``.local``, it
broadcasts it on the local network using mDNS, and returns the first response. All other queries are forwarded to an upstream server, so it can be used
as a regular resolving DNS server (instead of 8.8.8.8 or your provider's DNS servers).

## Why?

To give mDNS access to machines that don't support it natively (Android before 13, old Windows machines, small IoT  devices). And to learn Go.

## Building
To build, run: 

```$ go build```

I'm using mdnsproxy on a Raspberry Pi. To cross-compile on my Linux machine, I do:

```$ CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build```

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

mdsnproxy needs to be started as root (or with ``CAP_NET_BIND_SERVICE``), but it will drop root privileges as soon as it binds the listen port; ``-user`` 
decides which user it will run as. ``-chroot``, defaulting to the homedir of non-privileged user, defines the directory that proxy will chroot to.

mdnsproxy logs to stderr, and timestamps log entries if ``-timestamp`` was used.

Non-local queries are forwarded to a server specified by ``-upstream`` (Google's 8.8.8.8 by default).

## systemd
The included [unit file](mdnsproxy.service) can be used to start mdnsproxy automatically. It assumes a user ``mdnsproxy`` exists, and the program binary is at /home/mdnsproxy/mdnsproxy. It will also chroot to /home/mdnsproxy/chroot on startup. Once you create the user, copy mdnsproxy.service to ``/etc/systemd/system`` and run:
```
systemctl daemon-reload
```

followed by

```
systemctl enable mdnsproxy.service
```

and

```
systemctl start mdnsproxy.service
```
