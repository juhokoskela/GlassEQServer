package billing

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stripe/stripe-go/v86"
)

const (
	StripeAPIVersion   = stripe.APIVersion
	PolicyVersion      = "v1"
	CheckoutSuccessURL = "https://glasseq.app/checkout/success"
	CheckoutCancelURL  = "https://glasseq.app/checkout/cancel"

	stripeRequestTimeout = 15 * time.Second
	stripeResponseLimit  = 1 << 20
	checkoutURLHost      = "checkout.stripe.com"
)

var (
	ErrInvalidCheckoutSession = errors.New("Stripe returned an invalid Checkout Session")
	ErrStripeUnavailable      = errors.New("Stripe Checkout is unavailable")
)

type StripeRequestError struct {
	HTTPStatusCode int
	Code           string
	RequestID      string
}

func (e *StripeRequestError) Error() string {
	return "Stripe Checkout request failed"
}

type Plan string

const (
	PlanPerpetualV1 Plan = "perpetual_v1"
	PlanMonthly     Plan = "monthly"
)

type CheckoutConfig struct {
	SecretKey        string
	LiveMode         bool
	PerpetualPriceID string
	MonthlyPriceID   string
}

type CreateCheckoutSessionInput struct {
	OrderID        string
	Plan           Plan
	IdempotencyKey string
}

type CheckoutSession struct {
	ID        string
	URL       string
	ExpiresAt time.Time
}

type CheckoutClient struct {
	sessions         checkoutSessionCreator
	liveMode         bool
	perpetualPriceID string
	monthlyPriceID   string
}

type checkoutSessionCreator interface {
	Create(context.Context, *stripe.CheckoutSessionCreateParams) (*stripe.CheckoutSession, error)
}

func NewCheckoutClient(config CheckoutConfig) (*CheckoutClient, error) {
	if err := validateCheckoutConfig(config); err != nil {
		return nil, err
	}

	httpClient := &http.Client{
		Transport: responseLimitTransport{next: http.DefaultTransport},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	backends := stripe.NewBackendsWithConfig(&stripe.BackendConfig{
		EnableTelemetry: stripe.Bool(false),
		HTTPClient:      httpClient,
		LeveledLogger:   &stripe.LeveledLogger{Level: stripe.LevelNull},
	})
	client := stripe.NewClient(config.SecretKey, stripe.WithBackends(backends))
	return newCheckoutClient(config, client.V1CheckoutSessions), nil
}

func newCheckoutClient(config CheckoutConfig, sessions checkoutSessionCreator) *CheckoutClient {
	return &CheckoutClient{
		sessions:         sessions,
		liveMode:         config.LiveMode,
		perpetualPriceID: config.PerpetualPriceID,
		monthlyPriceID:   config.MonthlyPriceID,
	}
}

func (c *CheckoutClient) Create(ctx context.Context, input CreateCheckoutSessionInput) (CheckoutSession, error) {
	if strings.TrimSpace(input.OrderID) == "" {
		return CheckoutSession{}, errors.New("checkout order ID is required")
	}
	if input.IdempotencyKey == "" || strings.TrimSpace(input.IdempotencyKey) != input.IdempotencyKey || len(input.IdempotencyKey) > 255 {
		return CheckoutSession{}, errors.New("valid Stripe idempotency key is required")
	}

	priceID, mode, err := c.checkoutTerms(input.Plan)
	if err != nil {
		return CheckoutSession{}, err
	}
	metadata := map[string]string{
		"order_id":       input.OrderID,
		"plan":           string(input.Plan),
		"policy_version": PolicyVersion,
	}
	params := &stripe.CheckoutSessionCreateParams{
		CancelURL:         stripe.String(CheckoutCancelURL),
		ClientReferenceID: stripe.String(input.OrderID),
		ConsentCollection: &stripe.CheckoutSessionCreateConsentCollectionParams{
			TermsOfService: stripe.String(string(stripe.CheckoutSessionConsentCollectionTermsOfServiceRequired)),
		},
		LineItems: []*stripe.CheckoutSessionCreateLineItemParams{{
			Price:    stripe.String(priceID),
			Quantity: stripe.Int64(1),
		}},
		ManagedPayments: &stripe.CheckoutSessionCreateManagedPaymentsParams{Enabled: stripe.Bool(true)},
		Metadata:        metadata,
		Mode:            stripe.String(string(mode)),
		SuccessURL:      stripe.String(CheckoutSuccessURL),
	}
	if input.Plan == PlanPerpetualV1 {
		params.CustomerCreation = stripe.String(string(stripe.CheckoutSessionCustomerCreationAlways))
		params.PaymentIntentData = &stripe.CheckoutSessionCreatePaymentIntentDataParams{Metadata: metadata}
	} else {
		params.SubscriptionData = &stripe.CheckoutSessionCreateSubscriptionDataParams{Metadata: metadata}
	}
	params.SetIdempotencyKey(input.IdempotencyKey)

	requestCtx, cancel := context.WithTimeout(ctx, stripeRequestTimeout)
	defer cancel()
	session, err := c.sessions.Create(requestCtx, params)
	if err != nil {
		return CheckoutSession{}, sanitizeStripeError(requestCtx, err)
	}
	if !validCheckoutSession(session, input, mode, c.liveMode) {
		return CheckoutSession{}, ErrInvalidCheckoutSession
	}
	return CheckoutSession{
		ID:        session.ID,
		URL:       session.URL,
		ExpiresAt: time.Unix(session.ExpiresAt, 0).UTC(),
	}, nil
}

func sanitizeStripeError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var stripeError *stripe.Error
	if errors.As(err, &stripeError) {
		return &StripeRequestError{
			HTTPStatusCode: stripeError.HTTPStatusCode,
			Code:           string(stripeError.Code),
			RequestID:      stripeError.RequestID,
		}
	}
	return ErrStripeUnavailable
}

type responseLimitTransport struct {
	next http.RoundTripper
}

func (t responseLimitTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.next.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	response.Body = http.MaxBytesReader(nil, response.Body, stripeResponseLimit)
	return response, nil
}

func (c *CheckoutClient) checkoutTerms(plan Plan) (string, stripe.CheckoutSessionMode, error) {
	switch plan {
	case PlanPerpetualV1:
		return c.perpetualPriceID, stripe.CheckoutSessionModePayment, nil
	case PlanMonthly:
		return c.monthlyPriceID, stripe.CheckoutSessionModeSubscription, nil
	default:
		return "", "", fmt.Errorf("unsupported checkout plan %q", plan)
	}
}

func validateCheckoutConfig(config CheckoutConfig) error {
	if strings.TrimSpace(config.SecretKey) == "" {
		return errors.New("Stripe secret key is required")
	}
	if !strings.HasPrefix(config.PerpetualPriceID, "price_") {
		return errors.New("perpetual Stripe Price ID must start with price_")
	}
	if !strings.HasPrefix(config.MonthlyPriceID, "price_") {
		return errors.New("monthly Stripe Price ID must start with price_")
	}
	return nil
}

func validCheckoutSession(session *stripe.CheckoutSession, input CreateCheckoutSessionInput, mode stripe.CheckoutSessionMode, liveMode bool) bool {
	if session == nil || !strings.HasPrefix(session.ID, "cs_") || session.ExpiresAt <= 0 || session.Status != stripe.CheckoutSessionStatusOpen {
		return false
	}
	if session.Livemode != liveMode || session.Mode != mode || session.ClientReferenceID != input.OrderID {
		return false
	}
	if session.ManagedPayments == nil || !session.ManagedPayments.Enabled {
		return false
	}
	parsedURL, err := url.Parse(session.URL)
	return err == nil && parsedURL.Scheme == "https" && parsedURL.Host == checkoutURLHost && parsedURL.User == nil
}
