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
	maxClientReferenceID = 200
)

var (
	ErrInvalidCheckoutSession = errors.New("Stripe returned an invalid Checkout Session")
	ErrCheckoutSessionExpired = errors.New("Checkout Session has expired")
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

type CheckoutSessionSpec struct {
	OrderID       string
	Plan          Plan
	PriceID       string
	PolicyVersion string
}

type CheckoutSession struct {
	ID        string
	URL       string
	ExpiresAt time.Time
}

type CheckoutClient struct {
	sessions checkoutSessionBackend
	liveMode bool
}

type checkoutSessionBackend interface {
	Create(context.Context, *stripe.CheckoutSessionCreateParams) (*stripe.CheckoutSession, error)
	Retrieve(context.Context, string, *stripe.CheckoutSessionRetrieveParams) (*stripe.CheckoutSession, error)
}

func NewCheckoutClient(secretKey string) (*CheckoutClient, error) {
	liveMode, err := stripeLiveMode(secretKey)
	if err != nil {
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
	client := stripe.NewClient(secretKey, stripe.WithBackends(backends))
	return &CheckoutClient{
		sessions: client.V1CheckoutSessions,
		liveMode: liveMode,
	}, nil
}

func (c *CheckoutClient) Create(ctx context.Context, spec CheckoutSessionSpec, idempotencyKey string) (CheckoutSession, error) {
	mode, err := validateCheckoutSessionSpec(spec)
	if err != nil {
		return CheckoutSession{}, err
	}
	if idempotencyKey == "" || strings.TrimSpace(idempotencyKey) != idempotencyKey || len(idempotencyKey) > 255 {
		return CheckoutSession{}, errors.New("valid Stripe idempotency key is required")
	}

	metadata := map[string]string{
		"order_id":       spec.OrderID,
		"plan":           string(spec.Plan),
		"policy_version": spec.PolicyVersion,
	}
	params := &stripe.CheckoutSessionCreateParams{
		CancelURL:         stripe.String(CheckoutCancelURL),
		ClientReferenceID: stripe.String(spec.OrderID),
		ConsentCollection: &stripe.CheckoutSessionCreateConsentCollectionParams{
			TermsOfService: stripe.String(string(stripe.CheckoutSessionConsentCollectionTermsOfServiceRequired)),
		},
		LineItems:       []*stripe.CheckoutSessionCreateLineItemParams{{Quantity: stripe.Int64(1)}},
		ManagedPayments: &stripe.CheckoutSessionCreateManagedPaymentsParams{Enabled: stripe.Bool(true)},
		Metadata:        metadata,
		SuccessURL:      stripe.String(CheckoutSuccessURL),
	}
	params.LineItems[0].Price = stripe.String(spec.PriceID)
	switch mode {
	case stripe.CheckoutSessionModePayment:
		params.CustomerCreation = stripe.String(string(stripe.CheckoutSessionCustomerCreationAlways))
		params.PaymentIntentData = &stripe.CheckoutSessionCreatePaymentIntentDataParams{Metadata: metadata}
	case stripe.CheckoutSessionModeSubscription:
		params.SubscriptionData = &stripe.CheckoutSessionCreateSubscriptionDataParams{Metadata: metadata}
	}
	params.Mode = stripe.String(string(mode))
	params.SetIdempotencyKey(idempotencyKey)

	requestCtx, cancel := context.WithTimeout(ctx, stripeRequestTimeout)
	defer cancel()
	session, err := c.sessions.Create(requestCtx, params)
	if err != nil {
		return CheckoutSession{}, sanitizeStripeError(requestCtx, err)
	}
	if err := validateCheckoutSession(session, "", spec, mode, c.liveMode, time.Now()); err != nil {
		return CheckoutSession{}, err
	}
	return checkoutSessionResult(session), nil
}

func (c *CheckoutClient) Retrieve(ctx context.Context, sessionID string, spec CheckoutSessionSpec) (CheckoutSession, error) {
	mode, err := validateCheckoutSessionSpec(spec)
	if err != nil {
		return CheckoutSession{}, err
	}
	if !strings.HasPrefix(sessionID, "cs_") || len(sessionID) == len("cs_") || strings.TrimSpace(sessionID) != sessionID {
		return CheckoutSession{}, errors.New("valid Checkout Session ID is required")
	}

	requestCtx, cancel := context.WithTimeout(ctx, stripeRequestTimeout)
	defer cancel()
	session, err := c.sessions.Retrieve(requestCtx, sessionID, &stripe.CheckoutSessionRetrieveParams{})
	if err != nil {
		return CheckoutSession{}, sanitizeStripeError(requestCtx, err)
	}
	if err := validateCheckoutSession(session, sessionID, spec, mode, c.liveMode, time.Now()); err != nil {
		return CheckoutSession{}, err
	}
	return checkoutSessionResult(session), nil
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

func stripeLiveMode(key string) (bool, error) {
	switch {
	case validStripeKeyPrefix(key, "sk_test_"), validStripeKeyPrefix(key, "rk_test_"):
		return false, nil
	case validStripeKeyPrefix(key, "sk_live_"), validStripeKeyPrefix(key, "rk_live_"):
		return true, nil
	default:
		return false, errors.New("Stripe API key must be a test or live secret or restricted key")
	}
}

func validStripeKeyPrefix(key, prefix string) bool {
	return len(key) > len(prefix) && strings.HasPrefix(key, prefix) && strings.TrimSpace(key) == key
}

func validPriceID(value string) bool {
	return len(value) > len("price_") && strings.HasPrefix(value, "price_") && strings.TrimSpace(value) == value
}

func validateCheckoutSessionSpec(spec CheckoutSessionSpec) (stripe.CheckoutSessionMode, error) {
	if spec.OrderID == "" || strings.TrimSpace(spec.OrderID) != spec.OrderID || len(spec.OrderID) > maxClientReferenceID {
		return "", errors.New("valid Checkout order ID is required")
	}
	if !validPriceID(spec.PriceID) {
		return "", errors.New("valid Stripe Price ID is required")
	}
	if spec.PolicyVersion == "" || strings.TrimSpace(spec.PolicyVersion) != spec.PolicyVersion {
		return "", errors.New("valid policy version is required")
	}
	switch spec.Plan {
	case PlanPerpetualV1:
		return stripe.CheckoutSessionModePayment, nil
	case PlanMonthly:
		return stripe.CheckoutSessionModeSubscription, nil
	default:
		return "", fmt.Errorf("unsupported Checkout plan %q", spec.Plan)
	}
}

func validateCheckoutSession(session *stripe.CheckoutSession, expectedID string, spec CheckoutSessionSpec, mode stripe.CheckoutSessionMode, liveMode bool, now time.Time) error {
	if session == nil || !strings.HasPrefix(session.ID, "cs_") || session.ExpiresAt <= 0 || (expectedID != "" && session.ID != expectedID) {
		return ErrInvalidCheckoutSession
	}
	if session.ExpiresAt <= now.Unix() {
		return ErrCheckoutSessionExpired
	}
	if session.Status != stripe.CheckoutSessionStatusOpen {
		return ErrInvalidCheckoutSession
	}
	if session.Livemode != liveMode || session.Mode != mode || session.ClientReferenceID != spec.OrderID {
		return ErrInvalidCheckoutSession
	}
	if session.ManagedPayments == nil || !session.ManagedPayments.Enabled {
		return ErrInvalidCheckoutSession
	}
	if session.Metadata["order_id"] != spec.OrderID || session.Metadata["plan"] != string(spec.Plan) || session.Metadata["policy_version"] != spec.PolicyVersion {
		return ErrInvalidCheckoutSession
	}
	parsedURL, err := url.Parse(session.URL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Host != checkoutURLHost || parsedURL.User != nil {
		return ErrInvalidCheckoutSession
	}
	return nil
}

func checkoutSessionResult(session *stripe.CheckoutSession) CheckoutSession {
	return CheckoutSession{ID: session.ID, URL: session.URL, ExpiresAt: time.Unix(session.ExpiresAt, 0).UTC()}
}
