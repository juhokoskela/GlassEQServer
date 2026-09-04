package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/juhokoskela/GlassEQServer/internal/billing"
)

const (
	checkoutOrigin         = "https://glasseq.app"
	checkoutTimeout        = 20 * time.Second
	checkoutBusyRetryAfter = 1
)

type checkoutService interface {
	CreateCheckoutSession(context.Context, billing.CreateCheckoutOrderInput) (billing.CheckoutSession, error)
}

func (a *api) createCheckoutSession(w http.ResponseWriter, request *http.Request) {
	requestID, err := randomRequestID()
	if err != nil {
		a.logger.ErrorContext(request.Context(), "generate request ID", "error", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.", "")
		return
	}
	if !allowCheckoutOrigin(w, request, false) {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return
	}

	idempotencyKey, ok := singleHeader(request, "Idempotency-Key")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_request", "The Checkout request is invalid.", requestID)
		return
	}
	var body checkoutRequest
	if status := decodeJSONRequest(w, request, &body); status != 0 {
		writeError(w, status, "invalid_request", "The Checkout request is invalid.", requestID)
		return
	}
	clientIP, err := requestClientIP(request)
	if err != nil {
		a.logger.ErrorContext(request.Context(), "resolve Checkout client IP", "request_id", requestID, "error", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.", requestID)
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), checkoutTimeout)
	defer cancel()
	session, err := a.checkouts.CreateCheckoutSession(ctx, billing.CreateCheckoutOrderInput{
		RequestID: idempotencyKey,
		Plan:      body.Plan,
		ClientIP:  clientIP,
	})
	if err != nil {
		a.writeCheckoutError(w, request, requestID, err)
		return
	}
	writeJSON(w, http.StatusCreated, checkoutResponse{CheckoutURL: session.URL})
}

func (a *api) checkoutPreflight(w http.ResponseWriter, request *http.Request) {
	w.Header().Add("Vary", "Access-Control-Request-Method")
	w.Header().Add("Vary", "Access-Control-Request-Headers")
	if !allowCheckoutOrigin(w, request, true) || !validCheckoutPreflight(request) {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", "")
		return
	}
	w.Header().Set("Access-Control-Allow-Methods", http.MethodPost)
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Idempotency-Key")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusNoContent)
}

func allowCheckoutOrigin(w http.ResponseWriter, request *http.Request, required bool) bool {
	w.Header().Add("Vary", "Origin")
	origins := request.Header.Values("Origin")
	if len(origins) == 0 {
		return !required
	}
	if len(origins) != 1 || origins[0] != checkoutOrigin {
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", checkoutOrigin)
	return true
}

func validCheckoutPreflight(request *http.Request) bool {
	requestMethod, ok := singleHeader(request, "Access-Control-Request-Method")
	if !ok || requestMethod != http.MethodPost {
		return false
	}
	for _, value := range request.Header.Values("Access-Control-Request-Headers") {
		for header := range strings.SplitSeq(value, ",") {
			header = strings.TrimSpace(header)
			if !strings.EqualFold(header, "Content-Type") && !strings.EqualFold(header, "Idempotency-Key") {
				return false
			}
		}
	}
	return true
}

func (a *api) writeCheckoutError(w http.ResponseWriter, request *http.Request, requestID string, err error) {
	var rateLimitError *billing.CheckoutRateLimitError
	switch {
	case errors.Is(err, billing.ErrInvalidCheckoutRequest):
		writeError(w, http.StatusBadRequest, "invalid_request", "The Checkout request is invalid.", requestID)
	case errors.Is(err, billing.ErrCheckoutIdempotencyConflict):
		writeError(w, http.StatusConflict, "checkout_idempotency_conflict", "The idempotency key was already used for another plan.", requestID)
	case errors.Is(err, billing.ErrCheckoutSessionExpired):
		writeError(w, http.StatusConflict, "checkout_session_expired", "The Checkout Session has expired. Start a new Checkout.", requestID)
	case errors.Is(err, billing.ErrCheckoutSessionComplete):
		writeError(w, http.StatusConflict, "checkout_session_complete", "The Checkout Session is already complete.", requestID)
	case errors.As(err, &rateLimitError):
		if rateLimitError.RetryAfterSeconds > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(rateLimitError.RetryAfterSeconds))
		}
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many Checkout requests. Try again later.", requestID)
	case errors.Is(err, billing.ErrCheckoutBusy):
		w.Header().Set("Retry-After", strconv.Itoa(checkoutBusyRetryAfter))
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.", requestID)
	default:
		a.logger.ErrorContext(request.Context(), "create Checkout Session", "request_id", requestID, "error", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.", requestID)
	}
}

type checkoutRequest struct {
	Plan billing.Plan `json:"plan"`
}

type checkoutResponse struct {
	CheckoutURL string `json:"checkout_url"`
}
