package billing

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/juhokoskela/GlassEQServer/internal/activation"
	"github.com/stripe/stripe-go/v86"
)

const maximumBillingEventBytes = 256 * 1024

var ErrInvalidBillingEvent = errors.New("invalid or unsupported Stripe EventBridge message")

type EventDestination struct {
	Source   string
	Account  string
	Region   string
	LiveMode bool
}

type purchaseRetriever interface {
	RetrievePurchase(context.Context, string) (*stripe.CheckoutSession, error)
	RetrieveSubscription(context.Context, string) (*stripe.Subscription, error)
	RetrieveInvoice(context.Context, string) (*stripe.Invoice, error)
}

type purchasedLicenseIssuer interface {
	IssuePurchasedLicense(context.Context, *sql.Tx, activation.PurchasedLicense, time.Time) (string, error)
}

type ProductCatalog struct {
	PerpetualV1 string
	Monthly     string
}

type EventProcessor struct {
	database    *sql.DB
	checkout    purchaseRetriever
	adjustments adjustmentClient
	licenses    purchasedLicenseIssuer
	destination EventDestination
	products    ProductCatalog
	now         func() time.Time
}

func NewEventProcessor(database *sql.DB, checkout billingClient, licenses purchasedLicenseIssuer, destination EventDestination, products ProductCatalog) (*EventProcessor, error) {
	if database == nil || checkout == nil || licenses == nil {
		return nil, errors.New("billing event database, Checkout client, and license issuer are required")
	}
	if !strings.HasPrefix(destination.Source, "aws.partner/stripe.com/") || len(destination.Source) > 256 ||
		len(destination.Source) == len("aws.partner/stripe.com/") || len(destination.Account) != 12 || destination.Region != "eu-north-1" {
		return nil, errors.New("invalid billing EventBridge destination")
	}
	for _, digit := range destination.Account {
		if digit < '0' || digit > '9' {
			return nil, errors.New("invalid billing AWS account")
		}
	}
	if !validProductID(products.PerpetualV1) || !validProductID(products.Monthly) {
		return nil, errors.New("perpetual and monthly Stripe Product IDs are required for fulfillment")
	}
	return &EventProcessor{database: database, checkout: checkout, adjustments: checkout, licenses: licenses,
		destination: destination, products: products, now: time.Now}, nil
}

type billingEvent struct {
	ID         string `json:"id"`
	Object     string `json:"object"`
	APIVersion string `json:"api_version"`
	Type       string `json:"type"`
	Created    int64  `json:"created"`
	LiveMode   *bool  `json:"livemode"`
	Data       struct {
		Object struct {
			ID     string `json:"id"`
			Object string `json:"object"`
		} `json:"object"`
	} `json:"data"`
}

func decodeBillingEvent(body []byte, destination EventDestination, now time.Time) (billingEvent, error) {
	if len(body) > maximumBillingEventBytes {
		return billingEvent{}, ErrInvalidBillingEvent
	}
	var envelope struct {
		Version    string       `json:"version"`
		Source     string       `json:"source"`
		Account    string       `json:"account"`
		Region     string       `json:"region"`
		DetailType string       `json:"detail-type"`
		Detail     billingEvent `json:"detail"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Version != "0" || envelope.Source != destination.Source ||
		envelope.Account != destination.Account || envelope.Region != destination.Region {
		return billingEvent{}, ErrInvalidBillingEvent
	}
	event := envelope.Detail
	if !validStripeID(event.ID, "evt_") || len(event.ID) > 255 || event.Object != "event" ||
		event.APIVersion != StripeAPIVersion || event.LiveMode == nil || *event.LiveMode != destination.LiveMode ||
		event.Type != envelope.DetailType || event.Created <= 0 || event.Created > now.Add(5*time.Minute).Unix() ||
		len(event.Data.Object.ID) > 255 {
		return billingEvent{}, ErrInvalidBillingEvent
	}
	var prefix, object string
	switch event.Type {
	case "checkout.session.completed", "checkout.session.async_payment_succeeded", "checkout.session.async_payment_failed", "checkout.session.expired":
		prefix, object = "cs_", "checkout.session"
	case "invoice.paid", "invoice.payment_failed", "invoice.updated":
		prefix, object = "in_", "invoice"
	case "customer.subscription.updated", "customer.subscription.deleted":
		prefix, object = "sub_", "subscription"
	case "refund.created", "refund.updated", "refund.failed":
		prefix, object = "re_", "refund"
	case "charge.dispute.created", "charge.dispute.closed":
		prefix, object = "du_", "dispute"
	default:
		return billingEvent{}, ErrInvalidBillingEvent
	}
	if !validStripeID(event.Data.Object.ID, prefix) || event.Data.Object.Object != object {
		return billingEvent{}, ErrInvalidBillingEvent
	}
	return event, nil
}

// Process commits the event outcome and any fulfillment together. The queue owner
// may acknowledge only a nil result; unsupported lifecycle events remain retryable.
func (p *EventProcessor) Process(ctx context.Context, body []byte) error {
	now := p.now().UTC().Truncate(time.Microsecond)
	event, err := decodeBillingEvent(body, p.destination, now)
	if err != nil {
		return err
	}
	if _, err := p.database.ExecContext(ctx, `
		INSERT INTO stripe_events (stripe_event_id, event_type, object_id, stripe_created_at)
		VALUES ($1, $2, $3, $4) ON CONFLICT (stripe_event_id) DO NOTHING`,
		event.ID, event.Type, event.Data.Object.ID, time.Unix(event.Created, 0).UTC()); err != nil {
		return fmt.Errorf("record billing event: %w", err)
	}
	processed, err := matchingBillingEvent(ctx, p.database, event, false)
	if err != nil || processed {
		return err
	}
	if event.Data.Object.Object == "refund" || event.Data.Object.Object == "dispute" {
		return p.processAdjustment(ctx, event, now)
	}
	if event.Data.Object.Object != "checkout.session" {
		return p.processMonthlyEvent(ctx, event, nil, now)
	}
	// No database transaction or connection is retained while Stripe responds.
	session, err := p.checkout.RetrievePurchase(ctx, event.Data.Object.ID)
	if err != nil {
		return err
	}
	if session == nil || session.ID != event.Data.Object.ID || session.Livemode != p.destination.LiveMode {
		return ErrInvalidCheckoutSession
	}
	if session.Mode == stripe.CheckoutSessionModeSubscription {
		return p.processMonthlyEvent(ctx, event, session, now)
	}
	tx, err := p.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin billing event: %w", err)
	}
	defer tx.Rollback()
	processed, err = matchingBillingEvent(ctx, tx, event, true)
	if err != nil || processed {
		return err
	}
	order, state, found, err := lockPurchaseOrder(ctx, tx, session)
	if err != nil {
		return err
	}
	outcome := "ignored_unowned"
	if found {
		blocked, err := billingRestriction(ctx, tx, order.id)
		if err != nil {
			return err
		}
		outcome = "no_change"
		if !blocked {
			if err := validatePerpetualPurchase(session, order, p.products.PerpetualV1); err != nil {
				return err
			}
			if state != "fulfilled" {
				if session.PaymentStatus == stripe.CheckoutSessionPaymentStatusPaid {
					if err := p.issuePerpetualPurchase(ctx, tx, order, session, now); err != nil {
						return err
					}
					outcome = "fulfilled"
				} else {
					switch session.Status {
					case stripe.CheckoutSessionStatusExpired:
						outcome = "failed"
					case stripe.CheckoutSessionStatusOpen, stripe.CheckoutSessionStatusComplete:
						if event.Type == "checkout.session.async_payment_failed" {
							outcome = "failed"
						}
					default:
						return ErrInvalidCheckoutSession
					}
					if outcome == "failed" && state != "paid" {
						if _, err := tx.ExecContext(ctx, `UPDATE checkout_orders SET state = 'failed',
					    stripe_checkout_session_id = $2 WHERE id = $1`, order.id, session.ID); err != nil {
							return fmt.Errorf("fail unpaid order: %w", err)
						}
					}
				}
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE checkout_orders SET billing_revision = billing_revision + 1 WHERE id = $1`, order.id); err != nil {
			return fmt.Errorf("advance billing revision: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE stripe_events SET processed_at = $2, outcome = $3
		WHERE stripe_event_id = $1`, event.ID, now, outcome); err != nil {
		return fmt.Errorf("complete billing event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit billing event: %w", err)
	}
	return nil
}

func matchingBillingEvent(ctx context.Context, database checkoutOrderQuerier, event billingEvent, lock bool) (bool, error) {
	query := `SELECT event_type, object_id, stripe_created_at, processed_at FROM stripe_events WHERE stripe_event_id = $1`
	if lock {
		query += " FOR UPDATE"
	}
	var eventType, objectID string
	var created time.Time
	var processed sql.NullTime
	if err := database.QueryRowContext(ctx, query, event.ID).Scan(&eventType, &objectID, &created, &processed); err != nil {
		return false, fmt.Errorf("load billing event: %w", err)
	}
	if eventType != event.Type || objectID != event.Data.Object.ID || created.Unix() != event.Created {
		return false, ErrInvalidBillingEvent
	}
	return processed.Valid, nil
}

func lockPurchaseOrder(ctx context.Context, tx *sql.Tx, session *stripe.CheckoutSession) (checkoutOrder, string, bool, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, plan, policy_version, stripe_price_id, stripe_checkout_session_id, stripe_payment_intent_id, created_at, state
		FROM checkout_orders WHERE stripe_checkout_session_id = $1 OR id = $2 OR id = $3
		ORDER BY id FOR UPDATE`, session.ID, session.ClientReferenceID, session.Metadata["order_id"])
	if err != nil {
		return checkoutOrder{}, "", false, fmt.Errorf("lock purchase order: %w", err)
	}
	defer rows.Close()
	var order checkoutOrder
	var state string
	count := 0
	for rows.Next() {
		count++
		if count > 1 {
			return checkoutOrder{}, "", false, ErrInvalidCheckoutSession
		}
		if err := rows.Scan(&order.id, &order.plan, &order.policyVersion, &order.priceID, &order.sessionID, &order.paymentID, &order.createdAt, &state); err != nil {
			return checkoutOrder{}, "", false, fmt.Errorf("read purchase order: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return checkoutOrder{}, "", false, fmt.Errorf("read purchase orders: %w", err)
	}
	return order, state, count == 1, nil
}

func (p *EventProcessor) issuePerpetualPurchase(ctx context.Context, tx *sql.Tx, order checkoutOrder, session *stripe.CheckoutSession, now time.Time) error {
	licenseID, err := p.licenses.IssuePurchasedLicense(ctx, tx, activation.PurchasedLicense{
		Plan: string(order.plan), PolicyVersion: order.policyVersion, CustomerID: session.Customer.ID, Email: session.CustomerDetails.Email,
	}, now)
	if err != nil {
		return err
	}
	// There is no committed paid-but-unfulfilled gap for this synchronous
	// perpetual path. A rollback leaves the SQS message to retry all of it.
	if _, err := tx.ExecContext(ctx, `
		UPDATE checkout_orders SET state = 'fulfilled', license_id = $2, fulfilled_at = $3,
		    stripe_checkout_session_id = $4, stripe_payment_intent_id = $5
		WHERE id = $1`, order.id, licenseID, now, session.ID, session.PaymentIntent.ID); err != nil {
		return fmt.Errorf("fulfill purchase order: %w", err)
	}
	return nil
}
