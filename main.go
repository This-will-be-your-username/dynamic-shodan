// Command dynamic-shodan watches a dynamic DNS hostname, tracks the public
// IP addresses it points to over time, and shows Shodan's intel for the
// current address while discarding findings recorded before you held it.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"dynamic-shodan/internal/monitor"
	"dynamic-shodan/internal/notify"
	"dynamic-shodan/internal/shodan"
	"dynamic-shodan/internal/store"
	"dynamic-shodan/internal/web"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	listen := flag.String("listen", "127.0.0.1:8080", "address for the web UI")
	dataDir := flag.String("data", defaultDataDir(), "directory for config and history")
	flag.Parse()
	if *showVersion {
		fmt.Println("dynamic-shodan", version)
		return
	}
	log.Printf("dynamic-shodan %s", version)

	if err := run(*listen, *dataDir); err != nil {
		log.Fatal(err)
	}
}

func run(listen, dataDir string) error {
	st, err := store.Open(dataDir)
	if err != nil {
		return err
	}
	client := shodan.New()
	notifier := notify.New(st.Config)
	mon := monitor.New(st, client)
	mon.Notifier = notifier
	srv, err := web.New(st, mon, client, notifier)
	if err != nil {
		return err
	}
	if !isLoopback(listen) {
		log.Printf("WARNING: listening on %s; anyone who can reach it can view intel and change settings", listen)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go notifier.Run(ctx)
	go mon.Run(ctx)

	hs := &http.Server{
		Addr:              listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      90 * time.Second, // "Check now" waits on DNS + Shodan
		IdleTimeout:       120 * time.Second,
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	log.Printf("data directory: %s", dataDir)
	log.Printf("web UI: http://%s/", displayAddr(ln.Addr().String()))

	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Print("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return hs.Shutdown(shutCtx)
}

func defaultDataDir() string {
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "dynamic-shodan")
	}
	return "dynamic-shodan-data"
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func displayAddr(a string) string {
	host, port, err := net.SplitHostPort(a)
	if err != nil {
		return a
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		host = "localhost"
	}
	return net.JoinHostPort(host, port)
}
