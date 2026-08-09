package server

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// streamingPaths are the request paths whose response is a long-lived stream
// instead of a bounded document: the SSE feed behind the live refresh, and the
// playbook output written chunk by chunk while ansible-playbook runs.
//
// The console WebSocket (/api/ssh/ws) is deliberately absent: gorilla/websocket
// clears the connection deadlines itself when it hijacks on upgrade.
var streamingPaths = map[string]bool{
	"/api/events":      true,
	"/api/ansible/run": true,
}

// Server wraps the HTTPS server and handles TLS setup and HTTP→HTTPS redirect.
type Server struct {
	HTTPPort  string
	HTTPSPort string
	Handler   http.Handler

	// Cert locates the certificate/key pair served on the HTTPS port. Defaults to
	// the environment (see CertConfigFromEnv); overridable before Start.
	Cert CertConfig

	httpsServer *http.Server
	httpServer  *http.Server
}

// New creates a new Server.
func New(httpPort, httpsPort string, handler http.Handler) *Server {
	return &Server{
		HTTPPort:  httpPort,
		HTTPSPort: httpsPort,
		Handler:   handler,
		Cert:      CertConfigFromEnv(),
	}
}

// EnsureCert makes sure a usable TLS pair is on disk before the server starts:
// either the one supplied by the operator, or a persisted self-signed one that is
// only (re)generated when it is missing, unreadable, expiring, or no longer covers
// the configured hosts. See CertConfig.
func EnsureCert() error {
	return CertConfigFromEnv().Ensure()
}

// streamAware clears the write deadline on the streaming endpoints, leaving the
// server-wide WriteTimeout to cover every other handler.
//
// WriteTimeout is a single deadline armed when the handler starts: it cannot tell
// a client that stopped reading from a response that is MEANT to last, so it cut
// both — the live refresh never survived its first minute. Dropping WriteTimeout
// altogether would have been the easy fix and the wrong one: it is what stops a
// stalled client from pinning a connection, and the goroutine writing to it,
// forever. So the deadline stays global and is lifted here, on the two paths that
// need it.
//
// Nothing equivalent is needed for reads: net/http clears the read deadline itself
// once the request body has been consumed, before the handler runs.
func (s *Server) streamAware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if streamingPaths[r.URL.Path] {
			// The zero time means "no deadline". An error here would mean the
			// ResponseWriter does not support it (never the case for the stdlib
			// server); the request is still served, with the global deadline.
			if err := http.NewResponseController(w).SetWriteDeadline(time.Time{}); err != nil {
				slog.Warn("Cannot lift the write deadline on a streaming endpoint",
					"path", r.URL.Path, "error", err)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Start launches the HTTP redirect server and the HTTPS server.
func (s *Server) Start() error {
	go s.startHTTPRedirect()

	slog.Info("HTTPS server starting", "addr", "https://0.0.0.0:"+s.HTTPSPort)

	s.httpsServer = &http.Server{
		Addr:    ":" + s.HTTPSPort,
		Handler: s.streamAware(s.Handler),
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
		// Global write budget for ordinary responses. Lifted per-request on the
		// streaming endpoints by streamAware — see the comment there.
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return s.httpsServer.ListenAndServeTLS(s.Cert.CertFile, s.Cert.KeyFile)
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
