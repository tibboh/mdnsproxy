package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

var (
	listenFlag   = flag.String("listen", "0.0.0.0:53", "Address to listen on")
	upstreamFlag = flag.String("upstream", "8.8.8.8", "Comma-separated addresses of upstream DNS servers")
	timeoutFlag  = flag.Duration("timeout", time.Second, "Timeout for DNS queries")
	userFlag     = flag.String("user", "nobody", "User to run as after dropping root")
	chrootFlag   = flag.String("chroot", "", "Directory to chroot to")
	tsFlag       = flag.Bool("timestamp", false, "Add timestamp to log entries")
)

type config struct {
	listenAddr    string
	multicastAddr net.UDPAddr
	upstreamAddrs []net.UDPAddr
	timeout       time.Duration
	user          string
	chroot        string
}

func configFromFlags() config {
	var c config
	c.listenAddr = *listenFlag
	c.multicastAddr = net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}
	for _, up := range strings.Split(*upstreamFlag, ",") {
		ip := net.ParseIP(strings.TrimSpace(up))
		if ip == nil {
			log.Fatalf("Invalid upstream IP address: %s", up)
		}
		c.upstreamAddrs = append(c.upstreamAddrs, net.UDPAddr{IP: ip, Port: 53})
	}
	c.timeout = *timeoutFlag
	c.user = *userFlag
	c.chroot = *chrootFlag
	return c
}

type proxy struct {
	cfg         config
	server      *dns.Server
	localBlocks []*net.IPNet
	errc        chan error
}

func (p *proxy) fetchResponse(q *dns.Msg, addr *net.UDPAddr) (*dns.Msg, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen failed: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p.cfg.timeout))
	buf, err := q.Pack()
	if err != nil {
		return nil, fmt.Errorf("could not generate query: %w", err)
	}
	if _, err = conn.WriteToUDP(buf, addr); err != nil {
		return nil, fmt.Errorf("could not send query: %w", err)
	}
	buf = make([]byte, 65536)
	// Skip packets that can't be the answer: a wrong ID, or for unicast queries a wrong sender.
	// mDNS responders answer from their own address, so any sender is accepted for multicast.
	var parseErr error
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			if parseErr != nil {
				return nil, parseErr
			}
			return nil, fmt.Errorf("could not read response: %w", err)
		}
		if !addr.IP.IsMulticast() && !(from.IP.Equal(addr.IP) && from.Port == addr.Port) {
			continue
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			parseErr = fmt.Errorf("could not parse response: %w", err)
			continue
		}
		if msg.Id != q.Id {
			continue
		}
		return msg, nil
	}
}

func (p *proxy) isLocal(q *dns.Msg) bool {
	name := q.Question[0].Name
	if dns.IsSubDomain("local.", name) {
		return true
	}
	if q.Question[0].Qtype != dns.TypePTR {
		return false
	}
	if !dns.IsSubDomain("in-addr.arpa.", name) {
		return false
	}
	parts := dns.SplitDomainName(name)
	if len(parts) != 6 { // 4.3.2.1.in-addr.arpa
		return false
	}
	ip := net.ParseIP(fmt.Sprintf("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0]))
	if ip == nil {
		return false
	}
	for _, block := range p.localBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func (p *proxy) handleSelf(q *dns.Msg) (*dns.Msg, error) {
	response := new(dns.Msg)
	response.SetRcode(q, dns.RcodeNameError)
	return response, nil
}

func (p *proxy) handleLocal(q *dns.Msg) (r *dns.Msg, err error) {
	q.RecursionDesired = false
	q.Question[0].Qclass |= 1 << 15
	r, err = p.fetchResponse(q, &p.cfg.multicastAddr)
	if err != nil {
		return
	}
	if len(r.Question) > 0 {
		r.Question[0].Qclass &^= 1 << 15
	}
	for _, rr := range r.Answer {
		rr.Header().Class &^= 1 << 15
	}
	return
}

func (p *proxy) handleUpstream(q *dns.Msg) (r *dns.Msg, err error) {
	for _, addr := range p.cfg.upstreamAddrs {
		r, err = p.fetchResponse(q, &addr)
		if r != nil {
			return
		}
	}
	return
}

func (p *proxy) handleQuery(w dns.ResponseWriter, q *dns.Msg) {
	start := time.Now()
	if len(q.Question) != 1 {
		log.Printf("Invalid query")
		return
	}
	logstr := fmt.Sprintf("[%s] %d %s %s", w.RemoteAddr(), q.Id, dns.Type(q.Question[0].Qtype), dns.Name(q.Question[0].Name))
	mode := ""
	var response *dns.Msg
	var err error
	if q.Question[0].Name == "local." { // or reverse lookup for our own ip address!
		response, err = p.handleSelf(q)
		mode = "self"
	} else if p.isLocal(q) {
		response, err = p.handleLocal(q)
		mode = "local"
	} else {
		response, err = p.handleUpstream(q)
		mode = "upstream"
	}
	if response == nil {
		log.Printf("%s %s %d %s", logstr, mode, time.Since(start).Milliseconds(), err)
		return
	}
	if err = w.WriteMsg(response); err != nil {
		log.Printf("%s %s %d %s", logstr, mode, time.Since(start).Milliseconds(), err)
		return
	}
	log.Printf("%s %s %d OK", logstr, mode, time.Since(start).Milliseconds())
}

func newProxy(c config) *proxy {
	var localBlocks []*net.IPNet
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		localBlocks = append(localBlocks, block)
	}
	p := &proxy{
		cfg:         c,
		localBlocks: localBlocks,
		errc:        make(chan error, 1),
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", p.handleQuery)
	p.server = &dns.Server{
		Addr:              c.listenAddr,
		Net:               "udp",
		Handler:           mux,
		NotifyStartedFunc: p.started,
	}
	return p
}

func (p *proxy) serveInternal() error {
	if err := p.server.ListenAndServe(); err != nil {
		p.errc <- err
		return err
	}
	return nil // not reached
}

func (p *proxy) serve() error {
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go p.serveInternal()
	select {
	case e := <-p.errc:
		return e
	case sig := <-sigc:
		log.Printf("Terminating on signal (%s)", sig)
		return nil
	}
}

func (p *proxy) dropPrivileges() error {
	if syscall.Getuid() != 0 {
		return nil
	}
	if p.cfg.user == "" {
		return errors.New("running as root, but no user to switch to was given")
	}
	u, err := user.Lookup(p.cfg.user)
	if err != nil {
		return fmt.Errorf("could not look up user %s: %w", p.cfg.user, err)
	}
	dir := p.cfg.chroot
	if dir == "" {
		dir = u.HomeDir
	}
	if dir != "" {
		if err := syscall.Chroot(dir); err != nil {
			return fmt.Errorf("could not change root dir to %s: %w", dir, err)
		}
		if err := syscall.Chdir("/"); err != nil {
			return fmt.Errorf("could not change dir to new root: %w", err)
		}
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("could not parse UID %s: %w", u.Uid, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("could not parse GID %s: %w", u.Gid, err)
	}
	if err = syscall.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("could not set supplementary groups: %w", err)
	}
	if err = syscall.Setgid(gid); err != nil {
		return fmt.Errorf("could not set GID %d: %w", gid, err)
	}
	if err = syscall.Setuid(uid); err != nil {
		return fmt.Errorf("could not set UID %d: %w", uid, err)
	}
	return nil
}

func (p *proxy) started() {
	if err := p.dropPrivileges(); err != nil {
		log.Fatalf("could not drop privileges: %v", err)
	}
}

func main() {
	flag.Parse()
	if !*tsFlag {
		log.SetFlags(log.Flags() & ^(log.Ldate | log.Ltime))
	}
	p := newProxy(configFromFlags())
	if err := p.serve(); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
