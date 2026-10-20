// Command pqbench measures what hybrid post-quantum key exchange costs in TLS 1.3.
//
// Subcommands:
//
//	prims                       time the raw key-exchange primitives
//	server -group G -cert C     serve N TLS handshakes on loopback, report server CPU and bytes per flight
//	client -group G -n N        run N handshakes against a server
//	run                         orchestrate every configuration and write results/*.csv
//
// Everything is standard library (Go 1.24+): crypto/tls supports X25519MLKEM768 natively.
package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"
)

var groups = map[string]tls.CurveID{
	"X25519":         tls.X25519,
	"P256":           tls.CurveP256,
	"X25519MLKEM768": tls.X25519MLKEM768,
}

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Fatal("usage: pqbench prims|server|client|run")
	}
	switch os.Args[1] {
	case "prims":
		prims(os.Args[2:])
	case "server":
		server(os.Args[2:])
	case "client":
		client(os.Args[2:])
	case "run":
		run(os.Args[2:])
	default:
		log.Fatalf("unknown subcommand %q", os.Args[1])
	}
}

// ------------------------------------------------------------------ primitives

func timeOp(n int, f func()) float64 {
	start := time.Now()
	for i := 0; i < n; i++ {
		f()
	}
	return float64(time.Since(start).Nanoseconds()) / float64(n)
}

func prims(args []string) {
	fs := flag.NewFlagSet("prims", flag.ExitOnError)
	reps := fs.Int("reps", 15, "repetitions")
	n := fs.Int("n", 2000, "operations per repetition")
	out := fs.String("out", "results/primitives.csv", "output CSV")
	fs.Parse(args)

	type op struct {
		name string
		f    func()
	}
	x := ecdh.X25519()
	p := ecdh.P256()
	xk, _ := x.GenerateKey(rand.Reader)
	xpeer, _ := x.GenerateKey(rand.Reader)
	pk, _ := p.GenerateKey(rand.Reader)
	ppeer, _ := p.GenerateKey(rand.Reader)
	dk768, _ := mlkem.GenerateKey768()
	ek768 := dk768.EncapsulationKey()
	_, ct768 := ek768.Encapsulate()
	dk1024, _ := mlkem.GenerateKey1024()
	ek1024 := dk1024.EncapsulationKey()
	_, ct1024 := ek1024.Encapsulate()
	ops := []op{
		{"X25519 keygen", func() { x.GenerateKey(rand.Reader) }},
		{"X25519 shared secret", func() { xk.ECDH(xpeer.PublicKey()) }},
		{"P-256 keygen", func() { p.GenerateKey(rand.Reader) }},
		{"P-256 shared secret", func() { pk.ECDH(ppeer.PublicKey()) }},
		{"ML-KEM-768 keygen", func() { mlkem.GenerateKey768() }},
		{"ML-KEM-768 encapsulate", func() { ek768.Encapsulate() }},
		{"ML-KEM-768 decapsulate", func() { dk768.Decapsulate(ct768) }},
		{"ML-KEM-1024 keygen", func() { mlkem.GenerateKey1024() }},
		{"ML-KEM-1024 encapsulate", func() { ek1024.Encapsulate() }},
		{"ML-KEM-1024 decapsulate", func() { dk1024.Decapsulate(ct1024) }},
	}
	f, err := os.Create(*out)
	must(err)
	w := csv.NewWriter(f)
	w.Write([]string{"op", "rep", "ns_per_op"})
	for _, o := range ops {
		timeOp(*n/4, o.f) // warm up
		for r := 0; r < *reps; r++ {
			w.Write([]string{o.name, strconv.Itoa(r), fmt.Sprintf("%.1f", timeOp(*n, o.f))})
		}
		log.Printf("%-26s done", o.name)
	}
	w.Flush()
	must(f.Close())
	sizes := map[string]int{
		"X25519 public key": 32, "P-256 public key (uncompressed)": 65,
		"ML-KEM-768 encapsulation key": len(ek768.Bytes()), "ML-KEM-768 ciphertext": len(ct768),
		"ML-KEM-1024 encapsulation key": len(ek1024.Bytes()), "ML-KEM-1024 ciphertext": len(ct1024),
	}
	b, _ := json.MarshalIndent(sizes, "", " ")
	must(os.WriteFile("results/primitive_sizes.json", b, 0o644))
}

// ------------------------------------------------------------------ certificates

func makeCert(kind string) (tls.Certificate, *x509.CertPool) {
	var priv any
	var pub any
	switch kind {
	case "ECDSA-P256":
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		priv, pub = k, &k.PublicKey
	case "Ed25519":
		p, k, _ := ed25519.GenerateKey(rand.Reader)
		priv, pub = k, p
	case "RSA-2048", "RSA-3072":
		bits := 2048
		if kind == "RSA-3072" {
			bits = 3072
		}
		k, _ := rsa.GenerateKey(rand.Reader, bits)
		priv, pub = k, &k.PublicKey
	default:
		log.Fatalf("unknown cert kind %q", kind)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "svc.internal"},
		DNSNames: []string{"svc.internal"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:        true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	must(err)
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, pool
}

// Certificates are written to disk so the client process trusts the server's.
func certFiles(kind string) (string, string) {
	return fmt.Sprintf("results/.cert-%s.json", kind), ""
}

type certBlob struct {
	Der  []byte
	Kind string
	Key  []byte
}

func saveCert(kind string) {
	c, _ := makeCert(kind)
	key, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	must(err)
	b, _ := json.Marshal(certBlob{Der: c.Certificate[0], Kind: kind, Key: key})
	p, _ := certFiles(kind)
	must(os.WriteFile(p, b, 0o600))
}

func loadCert(kind string) (tls.Certificate, *x509.CertPool) {
	p, _ := certFiles(kind)
	b, err := os.ReadFile(p)
	must(err)
	var cb certBlob
	must(json.Unmarshal(b, &cb))
	key, err := x509.ParsePKCS8PrivateKey(cb.Key)
	must(err)
	leaf, _ := x509.ParseCertificate(cb.Der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{cb.Der}, PrivateKey: key, Leaf: leaf}, pool
}

// ------------------------------------------------------------------ recording conn

type event struct {
	dir   byte // 'r' read from peer, 'w' written to peer
	bytes int
	at    time.Duration
}

type recConn struct {
	net.Conn
	mu     sync.Mutex
	start  time.Time
	events []event
}

func (c *recConn) add(dir byte, n int) {
	if n <= 0 {
		return
	}
	c.mu.Lock()
	c.events = append(c.events, event{dir, n, time.Since(c.start)})
	c.mu.Unlock()
}
func (c *recConn) Read(b []byte) (int, error)  { n, err := c.Conn.Read(b); c.add('r', n); return n, err }
func (c *recConn) Write(b []byte) (int, error) { n, err := c.Conn.Write(b); c.add('w', n); return n, err }

// flights groups consecutive same-direction events: [client->server bytes, server->client bytes, ...]
// from the server's point of view ('r' = client flight, 'w' = server flight).
func flights(ev []event) []int {
	var out []int
	var last byte
	for _, e := range ev {
		if e.dir != last {
			out = append(out, 0)
			last = e.dir
		}
		out[len(out)-1] += e.bytes
	}
	return out
}

// ------------------------------------------------------------------ server and client

func cpuTime() time.Duration {
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

type serverReport struct {
	Group, Cert         string
	MTLS, Resume        bool
	N                   int
	CPUNsPerHandshake   float64
	WallNsPerHandshake  float64
	Flights             []int
	NegotiatedGroup     string
	ClientHelloBytes    int
	ServerFirstFlight   int
	HelloRetryRequested bool
}

func server(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	group := fs.String("group", "X25519MLKEM768", "server's only supported group")
	cert := fs.String("cert", "ECDSA-P256", "certificate type")
	n := fs.Int("n", 500, "handshakes to serve")
	mtls := fs.Bool("mtls", false, "require client certificates")
	sample := fs.Int("sample", 0, "which connection to record flights from (1 for resumed handshakes)")
	addrFile := fs.String("addr", "results/.addr", "where to write the listen address")
	fs.Parse(args)

	c, pool := loadCert(*cert)
	cfg := &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{groups[*group]}}
	if *mtls {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = pool
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	must(os.WriteFile(*addrFile, []byte(ln.Addr().String()), 0o644))
	rep := serverReport{Group: *group, Cert: *cert, MTLS: *mtls, N: *n}
	var cpu, wall time.Duration
	for i := 0; i < *n; i++ {
		raw, err := ln.Accept()
		must(err)
		rc := &recConn{Conn: raw, start: time.Now()}
		tc := tls.Server(rc, cfg)
		c0, w0 := cpuTime(), time.Now()
		if err := tc.Handshake(); err != nil {
			log.Fatalf("handshake: %v", err)
		}
		// Read the client's single application byte so the client Finished (and any client cert) is counted.
		buf := make([]byte, 1)
		io.ReadFull(tc, buf)
		cpu += cpuTime() - c0
		wall += time.Since(w0)
		if i == *sample {
			st := tc.ConnectionState()
			rep.Resume = st.DidResume
			rep.NegotiatedGroup = *group // the server supports only this group
			rep.Flights = flights(rc.events)
			rep.HelloRetryRequested = len(rep.Flights) > 3
			if len(rep.Flights) > 0 {
				rep.ClientHelloBytes = rep.Flights[0]
			}
			if len(rep.Flights) > 1 {
				rep.ServerFirstFlight = rep.Flights[1]
			}
		}
		tc.Write(buf)
		tc.Close()
	}
	rep.CPUNsPerHandshake = float64(cpu.Nanoseconds()) / float64(*n)
	rep.WallNsPerHandshake = float64(wall.Nanoseconds()) / float64(*n)
	b, _ := json.Marshal(rep)
	fmt.Println(string(b))
}


type clientReport struct {
	CPUNsPerHandshake float64
	Resumed           int
}

func client(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	groupList := fs.String("groups", "X25519MLKEM768,X25519", "client groups in preference order")
	cert := fs.String("cert", "ECDSA-P256", "certificate type (trust anchor and client cert)")
	n := fs.Int("n", 500, "handshakes")
	mtls := fs.Bool("mtls", false, "present a client certificate")
	resume := fs.Bool("resume", false, "use session resumption after the first handshake")
	addrFile := fs.String("addr", "results/.addr", "server address file")
	fs.Parse(args)

	var addr string
	for i := 0; i < 200; i++ {
		b, err := os.ReadFile(*addrFile)
		if err == nil && len(b) > 0 {
			addr = string(b)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	c, pool := loadCert(*cert)
	var prefs []tls.CurveID
	for _, g := range splitComma(*groupList) {
		prefs = append(prefs, groups[g])
	}
	cfg := &tls.Config{RootCAs: pool, ServerName: "svc.internal", MinVersion: tls.VersionTLS13, CurvePreferences: prefs}
	if *mtls {
		cfg.Certificates = []tls.Certificate{c}
	}
	if *resume {
		cfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	}
	rep := clientReport{}
	var cpu time.Duration
	for i := 0; i < *n; i++ {
		c0 := cpuTime()
		conn, err := tls.Dial("tcp", addr, cfg)
		if err != nil {
			log.Fatalf("dial: %v", err)
		}
		conn.Write([]byte{1})
		buf := make([]byte, 1)
		io.ReadFull(conn, buf)
		if conn.ConnectionState().DidResume {
			rep.Resumed++
		}
		cpu += cpuTime() - c0
		conn.Close()
	}
	rep.CPUNsPerHandshake = float64(cpu.Nanoseconds()) / float64(*n)
	b, _ := json.Marshal(rep)
	fmt.Println(string(b))
}

// ------------------------------------------------------------------ orchestration

type scenario struct {
	ServerGroup  string
	ClientGroups string
	Cert         string
	MTLS, Resume bool
}

func run(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	n := fs.Int("n", 400, "handshakes per repetition")
	reps := fs.Int("reps", 7, "repetitions per scenario")
	fs.Parse(args)
	self, _ := os.Executable()
	certs := []string{"ECDSA-P256", "Ed25519", "RSA-2048", "RSA-3072"}
	for _, c := range certs {
		saveCert(c)
	}
	var scen []scenario
	for _, c := range certs {
		for _, g := range []string{"X25519", "P256", "X25519MLKEM768"} {
			for _, m := range []bool{false, true} {
				cg := g
				if g == "X25519MLKEM768" {
					cg = "X25519MLKEM768,X25519" // Go's default client behaviour: hybrid first, classical fallback share
				}
				scen = append(scen, scenario{g, cg, c, m, false})
			}
		}
	}
	// Resumption, and the mismatch cases that force a HelloRetryRequest.
	for _, g := range []string{"X25519", "X25519MLKEM768"} {
		cg := g
		if g == "X25519MLKEM768" {
			cg = "X25519MLKEM768,X25519"
		}
		scen = append(scen, scenario{g, cg, "ECDSA-P256", true, true})
	}
	scen = append(scen,
		scenario{"X25519", "X25519MLKEM768,X25519", "ECDSA-P256", true, false},        // hybrid client, classical-only server
		scenario{"X25519MLKEM768", "X25519MLKEM768", "ECDSA-P256", true, false},        // hybrid-only client
	)
	f, err := os.Create("results/handshakes.csv")
	must(err)
	w := csv.NewWriter(f)
	w.Write([]string{"server_group", "client_groups", "cert", "mtls", "resume", "rep", "server_cpu_ns", "client_cpu_ns",
		"server_wall_ns", "sampled_resumed", "flights", "client_hello_bytes", "server_first_flight_bytes", "total_bytes", "resumed_share"})
	for _, s := range scen {
		for r := 0; r < *reps; r++ {
			os.Remove("results/.addr")
			sample := 0
			if s.Resume {
				sample = 1
			}
			srv := exec.Command(self, "server", "-group", s.ServerGroup, "-cert", s.Cert, "-n", strconv.Itoa(*n),
				fmt.Sprintf("-mtls=%v", s.MTLS), "-sample", strconv.Itoa(sample))
			so, _ := srv.StdoutPipe()
			srv.Stderr = os.Stderr
			must(srv.Start())
			cl := exec.Command(self, "client", "-groups", s.ClientGroups, "-cert", s.Cert, "-n", strconv.Itoa(*n),
				fmt.Sprintf("-mtls=%v", s.MTLS), fmt.Sprintf("-resume=%v", s.Resume))
			cl.Stderr = os.Stderr
			cout, err := cl.Output()
			must(err)
			sline, _ := bufio.NewReader(so).ReadString('\n')
			must(srv.Wait())
			var sr serverReport
			var cr clientReport
			must(json.Unmarshal([]byte(sline), &sr))
			must(json.Unmarshal(cout, &cr))
			total := 0
			for _, x := range sr.Flights {
				total += x
			}
			w.Write([]string{s.ServerGroup, s.ClientGroups, s.Cert, strconv.FormatBool(s.MTLS), strconv.FormatBool(s.Resume),
				strconv.Itoa(r), f1(sr.CPUNsPerHandshake), f1(cr.CPUNsPerHandshake), f1(sr.WallNsPerHandshake), strconv.FormatBool(sr.Resume),
				joinInts(sr.Flights), strconv.Itoa(sr.ClientHelloBytes), strconv.Itoa(sr.ServerFirstFlight), strconv.Itoa(total),
				fmt.Sprintf("%.3f", float64(cr.Resumed)/float64(*n))})
			w.Flush()
		}
		log.Printf("%+v done", s)
	}
	must(f.Close())
}

// ------------------------------------------------------------------ helpers

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
func f1(x float64) string { return fmt.Sprintf("%.1f", x) }
func joinInts(x []int) string {
	s := ""
	for i, v := range x {
		if i > 0 {
			s += "|"
		}
		s += strconv.Itoa(v)
	}
	return s
}
func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, ch := range s {
		if ch == ',' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(ch)
		}
	}
	return append(out, cur)
}

