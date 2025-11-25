package main

import (
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
	timeoutFlag  = flag.Int("timeout", 1, "Timeout for DNS queries (seconds)")
	userFlag     = flag.String("user", "nobody", "User to run as after dropping root")
	chrootFlag   = flag.String("chroot", "", "Directory to chroot to")
)

type Options struct {
	listenAddr    string
	multicastAddr net.UDPAddr
	upstreamAddr  []net.UDPAddr
	timeout       time.Duration
	afterSetup    func() error
}

func FromFlags() Options {
	flag.Parse()
	var o Options
	o.listenAddr = *listenFlag
	o.multicastAddr = net.UDPAddr{
		IP:   net.ParseIP("224.0.0.251"),
		Port: 5353,
	}
	for _, up := range strings.Split(*upstreamFlag, ",") {
		addr := net.UDPAddr{IP: net.ParseIP(up), Port: 53}
		o.upstreamAddr = append(o.upstreamAddr, addr)
	}
	o.timeout = time.Duration(*timeoutFlag) * time.Second
	return o
}

type Server struct {
	options     Options
	server      dns.Server
	localBlocks []*net.IPNet
	errc        chan error
}

func (s Server) fetchResponse(q *dns.Msg, addr *net.UDPAddr) (r *dns.Msg, err error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	defer conn.Close()
	if err != nil {
		return nil, fmt.Errorf("listen failed: %w", err)
	}
	conn.SetDeadline(time.Now().Add(s.options.timeout))
	buf, err := q.Pack()
	if err != nil {
		return nil, fmt.Errorf("could not generate query: %w", err)
	}
	if _, err = conn.WriteToUDP(buf, addr); err != nil {
		return nil, fmt.Errorf("could not send query: %w", err)
	}
	buf = make([]byte, 65536)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("could not read response: %w", err)
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(buf[:n]); err != nil {
		return nil, fmt.Errorf("could not parse response: %w", err)
	}
	return msg, nil
}

func (s Server) IsLocal(q *dns.Msg) bool {
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
	for _, block := range s.localBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func (s Server) handleSelf(q *dns.Msg) (r *dns.Msg, err error) {
	response := new(dns.Msg)
	response.SetRcode(q, dns.RcodeNameError)
	return response, nil
}

func (s Server) handleLocal(q *dns.Msg) (r *dns.Msg, err error) {
	q.RecursionDesired = false
	q.Question[0].Qclass |= 1 << 15
	r, err = s.fetchResponse(q, &s.options.multicastAddr)
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

func (s Server) handleUpstream(q *dns.Msg) (r *dns.Msg, err error) {
	for _, addr := range s.options.upstreamAddr {
		r, err = s.fetchResponse(q, &addr)
		if r != nil {
			return
		}
	}
	return
}

func (s Server) handleQuery(w dns.ResponseWriter, q *dns.Msg) {
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
		response, err = s.handleSelf(q)
		mode = "self"
	} else if s.IsLocal(q) {
		response, err = s.handleLocal(q)
		mode = "local"
	} else {
		response, err = s.handleUpstream(q)
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

func ServerFromOptions(o Options) Server {
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
	s := Server{o, dns.Server{Addr: o.listenAddr, Net: "udp"}, localBlocks, make(chan error, 1)}
	dns.HandleFunc(".", func(w dns.ResponseWriter, q *dns.Msg) {
		s.handleQuery(w, q)
	})
	return s
}

func (s Server) ServeInternal() error {
	if err := s.server.ListenAndServe(); err != nil {
		s.errc <- err
		return err
	}
	return nil // not reached
}

func (s Server) Serve() error {
	sigc := make(chan os.Signal)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go s.ServeInternal()
	if s.options.afterSetup != nil {
		if err := s.options.afterSetup(); err != nil {
			return fmt.Errorf("after-setup hook failed: %w", err)
		}
	}
	select {
	case e := <-s.errc:
		return e
	case sig := <-sigc:
		log.Printf("Terminating on signal (%s)", sig)
		return nil
	}
}

func DropPrivileges() error {
	if syscall.Getuid() != 0 {
		return nil
	}
	var u *user.User
	if len(*userFlag) > 0 {
		var err error
		u, err = user.Lookup(*userFlag)
		if err != nil {
			return fmt.Errorf("could not look up user %s: %w", *userFlag, err)
		}
	}
	dir := *chrootFlag
	if dir == "" && u != nil {
		dir = u.HomeDir
	}
	if dir != "" {
		if err := syscall.Chroot(dir); err != nil {
			return fmt.Errorf("could not change root dir to %s: %w", dir, err)
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
	if err = syscall.Setgid(gid); err != nil {
		return fmt.Errorf("could not set GID %d: %w", gid, err)
	}
	if err = syscall.Setuid(uid); err != nil {
		return fmt.Errorf("could not set UID %d: %w", uid, err)
	}
	return nil
}

func main() {
	options := FromFlags()
	options.afterSetup = DropPrivileges
	server := ServerFromOptions(options)
	if err := server.Serve(); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
