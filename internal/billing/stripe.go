package billing

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/stripe/stripe-go/v86"
)

const (
	StripeAPIVersion     = "2026-07-29.preview"
	PolicyVersion        = "v1"
	stripeRequestTimeout = 15 * time.Second
	stripeResponseLimit  = 1 << 20
)

var (
	ErrInvalidCheckoutSession = errors.New("Stripe returned an invalid Checkout Session")
	ErrStripeUnavailable      = errors.New("Stripe is unavailable")
)

type StripeRequestError struct {
	HTTPStatusCode int
	Code           string
	RequestID      string
}

func (e *StripeRequestError) Error() string { return "Stripe request failed" }

type Plan string

const (
	PlanPerpetualV1 Plan = "perpetual_v1"
	PlanMonthly     Plan = "monthly"
)

type CheckoutClient struct {
	sessions      checkoutSessionBackend
	sessionList   checkoutSessionListBackend
	prices        stripePriceBackend
	links         stripePaymentLinkBackend
	subscriptions stripeSubscriptionBackend
	invoices      stripeInvoiceBackend
	liveMode      bool
}

type checkoutSessionBackend interface {
	Retrieve(context.Context, string, *stripe.CheckoutSessionRetrieveParams) (*stripe.CheckoutSession, error)
}

type checkoutSessionListBackend interface {
	List(context.Context, *stripe.CheckoutSessionListParams) *stripe.V1List[*stripe.CheckoutSession]
}

type stripePriceBackend interface {
	Retrieve(context.Context, string, *stripe.PriceRetrieveParams) (*stripe.Price, error)
}

type stripePaymentLinkBackend interface {
	Retrieve(context.Context, string, *stripe.PaymentLinkRetrieveParams) (*stripe.PaymentLink, error)
}

func (c *CheckoutClient) LiveMode() bool { return c.liveMode }

func NewCheckoutClient(secretKey string) (*CheckoutClient, error) {
	liveMode, err := stripeLiveMode(secretKey)
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{
		Transport:     responseLimitTransport{next: http.DefaultTransport},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	backends := stripe.NewBackendsWithConfig(&stripe.BackendConfig{
		EnableTelemetry: stripe.Bool(false), HTTPClient: httpClient,
		LeveledLogger: &stripe.LeveledLogger{Level: stripe.LevelNull},
	})
	client := stripe.NewClient(secretKey, stripe.WithBackends(backends))
	return &CheckoutClient{
		sessions: client.V1CheckoutSessions, sessionList: client.V1CheckoutSessions, prices: client.V1Prices,
		subscriptions: client.V1Subscriptions, invoices: client.V1Invoices, links: client.V1PaymentLinks, liveMode: liveMode,
	}, nil
}

func (c *CheckoutClient) FindPurchaseBySubscription(ctx context.Context, subscriptionID string) (*stripe.CheckoutSession, error) {
	if !validStripeID(subscriptionID, "sub_") {
		return nil, ErrInvalidCheckoutSession
	}
	requestCtx, cancel := context.WithTimeout(ctx, stripeRequestTimeout)
	defer cancel()
	params := &stripe.CheckoutSessionListParams{Subscription: stripe.String(subscriptionID)}
	params.Limit = stripe.Int64(2)
	sessions := c.sessionList.List(requestCtx, params)
	if err := sessions.Err(); err != nil {
		return nil, sanitizeStripeError(requestCtx, err)
	}
	if len(sessions.Data()) > 1 || sessions.Meta().HasMore {
		return nil, ErrInvalidCheckoutSession
	}
	if len(sessions.Data()) == 0 {
		return nil, nil
	}
	return sessions.Data()[0], nil
}

func sanitizeStripeError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var stripeError *stripe.Error
	if errors.As(err, &stripeError) {
		return &StripeRequestError{HTTPStatusCode: stripeError.HTTPStatusCode, Code: string(stripeError.Code), RequestID: stripeError.RequestID}
	}
	return ErrStripeUnavailable
}

type responseLimitTransport struct{ next http.RoundTripper }

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

func validPriceID(value string) bool   { return validStripeID(value, "price_") }
func validProductID(value string) bool { return validStripeID(value, "prod_") }

func validStripeID(value, prefix string) bool {
	return len(value) > len(prefix) && strings.HasPrefix(value, prefix) && strings.TrimSpace(value) == value
}
