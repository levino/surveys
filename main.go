package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/levino/surveys/ui"
)

func main() {
	cfg := loadConfig()
	ui.Theme = cfg.Theme

	db, err := openDB(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	app := newApp(cfg, db)
	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           requestLogger(app.routes()),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logJSON("info", "listening", map[string]any{"addr": srv.Addr, "base_url": cfg.BaseURL, "oidc_issuer": cfg.OIDCIssuer})
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	logJSON("info", "shutting down", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
	_ = db.Close()
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	a.mountStatic(mux)
	a.mountPublic(mux)
	a.mountOauth(mux)
	a.mountWebAuth(mux)
	a.mountMcp(mux)
	return mux
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		logJSON("info", "request", map[string]any{
			"method": r.Method, "path": r.URL.Path, "status": sw.status,
			"ms": time.Since(start).Milliseconds(),
		})
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func logJSON(level, msg string, fields map[string]any) {
	rec := map[string]any{"level": level, "msg": msg, "ts": time.Now().UTC().Format(time.RFC3339)}
	for k, v := range fields {
		rec[k] = v
	}
	b, _ := json.Marshal(rec)
	os.Stdout.Write(append(b, '\n'))
}
