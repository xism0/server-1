package runner

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gotify/server/v2/config"
	"golang.org/x/crypto/acme/autocert"
)

// Run starts the http server and if configured a https server.
func Run(router http.Handler, conf *config.Configuration) {
	httpHandler := router

	if *conf.Server.SSL.Enabled {
		if *conf.Server.SSL.RedirectToHTTPS {
			httpHandler = redirectToHTTPS(strconv.Itoa(conf.Server.SSL.Port))
		}

		network, addr := listenAddrParse(conf.Server.SSL.ListenAddr, conf.Server.SSL.Port)
		s := &http.Server{
			Addr:    addr,
			Handler: router,
		}

		if *conf.Server.SSL.LetsEncrypt.Enabled {
			certManager := autocert.Manager{
				Prompt:     func(tosURL string) bool { return *conf.Server.SSL.LetsEncrypt.AcceptTOS },
				HostPolicy: autocert.HostWhitelist(conf.Server.SSL.LetsEncrypt.Hosts...),
				Cache:      autocert.DirCache(conf.Server.SSL.LetsEncrypt.Cache),
			}
			httpHandler = certManager.HTTPHandler(httpHandler)
			s.TLSConfig = &tls.Config{GetCertificate: certManager.GetCertificate}
		}
		fmt.Println("Started Listening for TLS connection on " + addr)
		go func() {
			l := startListening(network, addr, conf.Server.KeepAlivePeriodSeconds)
			defer l.Close()
			log.Fatal(s.ServeTLS(l, conf.Server.SSL.CertFile, conf.Server.SSL.CertKey))
		}()
	}
	network, addr := listenAddrParse(conf.Server.ListenAddr, conf.Server.Port)
	fmt.Println("Started Listening for plain HTTP connection on " + addr)
	server := &http.Server{Addr: addr, Handler: httpHandler}
	l := startListening(network, addr, conf.Server.KeepAlivePeriodSeconds)
	defer l.Close()
	log.Fatal(server.Serve(l))
}

func startListening(network, addr string, keepAlive int) net.Listener {
	lc := net.ListenConfig{KeepAlive: time.Duration(keepAlive) * time.Second}
	conn, err := lc.Listen(context.Background(), network, addr)
	if err != nil {
		log.Fatalln("Could not listen on", addr, err)
	}
	return conn
}

func listenAddrParse(ListenAddr string, Port int) (string, string) {
	if strings.HasPrefix(ListenAddr, "unix:") {
		path := strings.TrimPrefix(ListenAddr, "unix:")
		os.Remove(path)
		return "unix", path
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
