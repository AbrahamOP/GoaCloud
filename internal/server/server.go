package server

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"
)

// Server wraps the HTTPS server and handles TLS setup and HTTP→HTTPS redirect.
type Server struct {
	HTTPPort  string
	HTTPSPort string
	Handler   http.Handler

	httpsServer *http.Server
	httpServer  *http.Server
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

	s.httpsServer = &http.Server{
		Addr:    ":" + s.HTTPSPort,
		Handler: s.Handler,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		},
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return s.httpsServer.ListenAndServeTLS("server.crt", "server.key")
}

// Shutdown gracefully shuts down both HTTP and HTTPS servers.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			slog.Error("HTTP server shutdown error", "error", err)
		}
	}
	if s.httpsServer != nil {
		return s.httpsServer.Shutdown(ctx)
	}
	return nil
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
	s.httpServer = &http.Server{
		Addr:         ":" + s.HTTPPort,
		Handler:      redirectMux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("HTTP redirect server error", "error", err)
	}
}
