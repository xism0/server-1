package runner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gotify/server/v2/config"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sync/errgroup"
)

// Run starts the http server and if configured a https server.
func Run(router http.Handler, conf *config.Configuration) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		done := make(chan os.Signal, 1)
		signal.Notify(done, os.Interrupt, syscall.SIGTERM)
		<-done
		cancel()
	}()
	s := &http.Server{Handler: router}
	g, gCtx := errgroup.WithContext(ctx)
	if *conf.Server.SSL.Enabled {
		if *conf.Server.SSL.LetsEncrypt.Enabled {
			certManager := autocert.Manager{
				Prompt:     func(tosURL string) bool { return *conf.Server.SSL.LetsEncrypt.AcceptTOS },
				HostPolicy: autocert.HostWhitelist(conf.Server.SSL.LetsEncrypt.Hosts...),
				Cache:      autocert.DirCache(conf.Server.SSL.LetsEncrypt.Cache),
			}
			s.Handler = certManager.HTTPHandler(s.Handler)
			s.TLSConfig = &tls.Config{GetCertificate: certManager.GetCertificate}
		}
		g.Go(func() error {
			return runTLS(s, conf)
		})
	}
	g.Go(func() error {
		return run(s, conf)
	})
	g.Go(func() error {
		<-gCtx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.Shutdown(ctx)
	})
	if err := g.Wait(); err != nil {
		fmt.Println("Error while running the server", err)
		os.Exit(1)
	}
}

func run(s *http.Server, conf *config.Configuration) error {
	network, addr := listenAddrParse(conf.Server.ListenAddr, conf.Server.Port)
	l, err := startListening(network, addr, conf.Server.KeepAlivePeriodSeconds)
	if err != nil {
		return err
	}
	fmt.Println("Started Listening for plain connection on", l.Addr().Network(), l.Addr().String())
	defer l.Close()
	if err := s.Serve(l); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func runTLS(s *http.Server, conf *config.Configuration) error {
	network, addr := listenAddrParse(conf.Server.SSL.ListenAddr, conf.Server.SSL.Port)
	l, err := startListening(network, addr, conf.Server.KeepAlivePeriodSeconds)
	if err != nil {
		return err
	}
	fmt.Println("Started Listening for TLS connection on", l.Addr().Network(), l.Addr().String())
	defer l.Close()
	if err := s.ServeTLS(l, conf.Server.SSL.CertFile, conf.Server.SSL.CertKey); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func startListening(network, addr string, keepAlive int) (net.Listener, error) {
	lc := net.ListenConfig{KeepAlive: time.Duration(keepAlive) * time.Second}
	conn, err := lc.Listen(context.Background(), network, addr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func listenAddrParse(ListenAddr string, Port int) (string, string) {
	if strings.HasPrefix(ListenAddr, "unix:") {
		return "unix", strings.TrimPrefix(ListenAddr, "unix:")
	}
	return "tcp", fmt.Sprintf("%s:%d", ListenAddr, Port)
}

func redirectToHTTPS(port string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			http.Error(w, "Use HTTPS", http.StatusBadRequest)
			return
		}

		target := "https://" + changePort(r.Host, port) + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusFound)
	}
}

func changePort(hostPort, port string) string {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		// There is no exported error.
		if !strings.Contains(err.Error(), "missing port") {
			return hostPort
		}
		host = hostPort
	}
	return net.JoinHostPort(host, port)
}
