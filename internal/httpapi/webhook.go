package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/juhokoskela/GlassEQServer/internal/billing"
	"github.com/stripe/stripe-go/v86/webhook"
)

const (
	maximumWebhookBytes = 256 * 1024
	webhookTimeout      = 25 * time.Second
)

type billingEventProcessor interface {
	Process(context.Context, []byte) error
}

func (a *api) stripeWebhook(w http.ResponseWriter, request *http.Request) {
	signature, ok := singleHeader(request, "Stripe-Signature")
	if !ok || signature == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, request.Body, maximumWebhookBytes))
	if err != nil {
		var oversized *http.MaxBytesError
		if errors.As(err, &oversized) {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
		return
	}
	if err := webhook.ValidatePayload(body, signature, a.webhookKey); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), webhookTimeout)
	defer cancel()
	if err := a.events.Process(ctx, body); err != nil {
		// Stripe errors and payloads can contain customer data. Keep logs bounded.
		code := "temporarily_unavailable"
		switch {
		case errors.Is(err, billing.ErrInvalidBillingEvent):
			code = "invalid_event"
		case errors.Is(err, billing.ErrInvalidCheckoutSession), errors.Is(err, billing.ErrInvalidSubscription):
			code = "invalid_purchase"
		case errors.Is(err, billing.ErrUnsupportedPurchase):
			code = "unsupported_purchase"
		}
		a.logger.WarnContext(ctx, "Stripe webhook not acknowledged", "code", code)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
