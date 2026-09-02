package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/juhokoskela/GlassEQServer/internal/activation"
)

const (
	readinessTimeout  = time.Second
	activationTimeout = 20 * time.Second
	maximumBodySize   = 16 * 1024
)

type databasePinger interface {
	PingContext(context.Context) error
}

type activationService interface {
	Activate(context.Context, activation.Input) (activation.Response, error)
}

type api struct {
	database    databasePinger
	activations activationService
	logger      *slog.Logger
}

func New(database databasePinger, activations activationService, logger *slog.Logger) http.Handler {
	api := &api{database: database, activations: activations, logger: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", api.health)
	mux.HandleFunc("GET /readyz", api.ready)
	mux.HandleFunc("POST /v1/activations", api.activate)
	return mux
}

func (a *api) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, statusResponse{Status: "ok"})
}

func (a *api) activate(w http.ResponseWriter, request *http.Request) {
	requestID, err := randomRequestID()
	if err != nil {
		a.logger.ErrorContext(request.Context(), "generate request ID", "error", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.", "")
		return
	}

	body, invalidStatus := decodeActivationRequest(w, request)
	if invalidStatus != 0 {
		writeError(w, invalidStatus, "invalid_request", "The activation request is invalid.", requestID)
		return
	}

	clientIP, err := requestClientIP(request)
	if err != nil {
		a.logger.ErrorContext(request.Context(), "resolve activation client IP", "request_id", requestID, "error", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.", requestID)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), activationTimeout)
	defer cancel()
	response, err := a.activations.Activate(ctx, activation.Input{
		LicenseKey:     body.LicenseKey,
		InstallationID: body.InstallationID,
		IdempotencyKey: body.IdempotencyKey,
		ClientIP:       clientIP,
	})
	if err != nil {
		a.logger.ErrorContext(request.Context(), "activate license", "request_id", requestID, "error", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.", requestID)
		return
	}
	if response.RetryAfterSeconds > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(response.RetryAfterSeconds))
	}
	if response.ErrorCode != "" {
		writeError(w, response.Status, response.ErrorCode, response.ErrorMessage, requestID)
		return
	}
	writeRawJSON(w, response.Status, response.Body)
}

func decodeActivationRequest(w http.ResponseWriter, request *http.Request) (activationRequest, int) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return activationRequest{}, http.StatusUnsupportedMediaType
	}
	idempotencyHeaders := request.Header.Values("Idempotency-Key")
	if len(idempotencyHeaders) != 1 {
		return activationRequest{}, http.StatusBadRequest
	}

	var body activationRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, request.Body, maximumBodySize))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&body)
	if err == nil {
		err = rejectTrailingJSON(decoder)
	}
	if err != nil {
		var maximumBytesError *http.MaxBytesError
		if errors.As(err, &maximumBytesError) {
			return activationRequest{}, http.StatusRequestEntityTooLarge
		}
		return activationRequest{}, http.StatusBadRequest
	}
	body.IdempotencyKey = idempotencyHeaders[0]
	return body, 0
}

func rejectTrailingJSON(decoder *json.Decoder) error {
	var extra json.RawMessage
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("request contains multiple JSON values")
}

func requestClientIP(request *http.Request) (netip.Addr, error) {
	forwarded := request.Header.Values("X-Forwarded-For")
	if len(forwarded) > 0 {
		addresses := strings.Split(forwarded[len(forwarded)-1], ",")
		return canonicalIP(strings.TrimSpace(addresses[len(addresses)-1]))
	}
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("split remote address: %w", err)
	}
	return canonicalIP(host)
}

func canonicalIP(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse IP address: %w", err)
	}
	return address.Unmap(), nil
}

func randomRequestID() (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	return "req_" + base64.RawURLEncoding.EncodeToString(value), nil
}

type activationRequest struct {
	LicenseKey     string `json:"license_key"`
	InstallationID string `json:"installation_id"`
	IdempotencyKey string `json:"-"`
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

func writeError(w http.ResponseWriter, status int, code, message, requestID string) {
	writeJSON(w, status, errorEnvelope{Error: errorResponse{
		Code: code, Message: message, Retryable: status == http.StatusTooManyRequests || status >= 500, RequestID: requestID,
	}})
}

func writeRawJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

type errorEnvelope struct {
	Error errorResponse `json:"error"`
}

type errorResponse struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
	RequestID string `json:"request_id"`
}
