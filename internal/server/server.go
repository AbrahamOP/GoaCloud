package server

import (
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"os"
)

// Server wraps the HTTPS server and handles TLS setup and HTTP→HTTPS redirect.
type Server struct {
	HTTPPort  string
	HTTPSPort string
	Handler   http.Handler
}

// New creates a new Server.
func New(httpPort, httpsPort string, handler http.Handler) *Server {
	return &Server{
		HTTPPort:  httpPort,
		HTTPSPort: httpsPort,
		Handler:   handler,
	}
}

// EnsureCert generates a self-signed certificate if none exists.
func EnsureCert() error {
	if _, err := os.Stat("server.crt"); os.IsNotExist(err) {
		slog.Info("SSL certificate not found, generating self-signed certificate...")
		return GenerateSelfSignedCert()
	}
	return nil
}

// Start launches the HTTP redirect server and the HTTPS server.
func (s *Server) Start() error {
	go s.startHTTPRedirect()

	slog.Info("HTTPS server starting", "addr", "https://0.0.0.0:"+s.HTTPSPort)

	httpsServer := &http.Server{
		Addr:         ":" + s.HTTPSPort,
		Handler:      s.Handler,
		TLSConfig:    &tls.Config{},
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	return httpsServer.ListenAndServeTLS("server.crt", "server.key")
}

func (s *Server) startHTTPRedirect() {
	slog.Info("HTTP redirect server starting", "addr", "http://0.0.0.0:"+s.HTTPPort)
	redirectMux := http.NewServeMux()
	redirectMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		target := "https://" + host + ":" + s.HTTPSPort + r.RequestURI
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
	if err := http.ListenAndServe(":"+s.HTTPPort, redirectMux); err != nil {
		slog.Error("HTTP redirect server error", "error", err)
	}
}
