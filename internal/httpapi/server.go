package httpapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

const readinessTimeout = time.Second

type databasePinger interface {
	PingContext(context.Context) error
}

type api struct {
	database databasePinger
	logger   *slog.Logger
}

func New(database databasePinger, logger *slog.Logger) http.Handler {
	api := &api{database: database, logger: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", api.health)
	mux.HandleFunc("GET /readyz", api.ready)
	return mux
}

func (a *api) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, statusResponse{Status: "ok"})
}

func (a *api) ready(w http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), readinessTimeout)
	defer cancel()

	if err := a.database.PingContext(ctx); err != nil {
		a.logger.WarnContext(request.Context(), "readiness check failed", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, statusResponse{Status: "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, statusResponse{Status: "ok"})
}

type statusResponse struct {
	Status string `json:"status"`
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
