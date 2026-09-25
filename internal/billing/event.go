package billing

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/juhokoskela/GlassEQServer/internal/activation"
	"github.com/stripe/stripe-go/v86"
)

const maximumBillingEventBytes = 256 * 1024

var ErrInvalidBillingEvent = errors.New("invalid or unsupported Stripe webhook event")

type purchaseRetriever interface {
	RetrievePurchase(context.Context, string) (*stripe.CheckoutSession, error)
	RetrieveSubscription(context.Context, string) (*stripe.Subscription, error)
	RetrieveInvoice(context.Context, string) (*stripe.Invoice, error)
}

type purchasedLicenseIssuer interface {
	IssuePurchasedLicense(context.Context, *sql.Tx, activation.PurchasedLicense, time.Time) (string, error)
}

type BillingCatalog struct {
	PerpetualV1      string
	Monthly          string
	PerpetualPriceID string
	MonthlyPriceID   string
	PerpetualLinkID  string
	MonthlyLinkID    string
}

type checkoutOrder struct {
	id            string
	plan          Plan
	policyVersion string
	priceID       string
	sessionID     sql.NullString
	paymentID     sql.NullString
	createdAt     time.Time
}

type checkoutOrderQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type EventProcessor struct {
	database *sql.DB
	checkout purchaseRetriever
	licenses purchasedLicenseIssuer
	liveMode bool
	products BillingCatalog
	now      func() time.Time
}

func NewEventProcessor(database *sql.DB, checkout purchaseRetriever, licenses purchasedLicenseIssuer, liveMode bool, products BillingCatalog) (*EventProcessor, error) {
	if database == nil || checkout == nil || licenses == nil {
		return nil, errors.New("billing event database, Checkout client, and license issuer are required")
	}
	if !validProductID(products.PerpetualV1) || !validProductID(products.Monthly) ||
		!validPriceID(products.PerpetualPriceID) || !validPriceID(products.MonthlyPriceID) ||
		!validStripeID(products.PerpetualLinkID, "plink_") || !validStripeID(products.MonthlyLinkID, "plink_") {
		return nil, errors.New("Stripe product, price, and payment link IDs are required for fulfillment")
	}
	return &EventProcessor{database: database, checkout: checkout, licenses: licenses,
		liveMode: liveMode, products: products, now: time.Now}, nil
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

func decodeBillingEvent(body []byte, liveMode bool, now time.Time) (billingEvent, error) {
	if len(body) > maximumBillingEventBytes {
		return billingEvent{}, ErrInvalidBillingEvent
	}
	var event billingEvent
	if json.Unmarshal(body, &event) != nil {
		return billingEvent{}, ErrInvalidBillingEvent
	}
	if !validStripeID(event.ID, "evt_") || len(event.ID) > 255 || event.Object != "event" ||
		event.APIVersion != StripeAPIVersion || event.LiveMode == nil || *event.LiveMode != liveMode ||
		event.Created <= 0 || event.Created > now.Add(5*time.Minute).Unix() ||
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
	default:
		return billingEvent{}, ErrInvalidBillingEvent
	}
	if !validStripeID(event.Data.Object.ID, prefix) || event.Data.Object.Object != object {
		return billingEvent{}, ErrInvalidBillingEvent
	}
	return event, nil
}

// Process commits the event outcome and any fulfillment together. The webhook
// acknowledges only a nil result; unsupported lifecycle events remain retryable.
func (p *EventProcessor) Process(ctx context.Context, body []byte) error {
	now := p.now().UTC().Truncate(time.Microsecond)
	event, err := decodeBillingEvent(body, p.liveMode, now)
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
	if event.Data.Object.Object != "checkout.session" {
		return p.processMonthlyEvent(ctx, event, nil, now)
	}
	// No database transaction or connection is retained while Stripe responds.
	session, err := p.checkout.RetrievePurchase(ctx, event.Data.Object.ID)
	if err != nil {
		return err
	}
	if session == nil || session.ID != event.Data.Object.ID || session.Livemode != p.liveMode {
		return ErrInvalidCheckoutSession
	}
	owned, err := p.ensurePaymentLinkOrder(ctx, session, now)
	if err != nil {
		return err
	}
	if !owned {
		return p.commitMonthlyEvent(ctx, event, monthlyOrder{}, nil, nil, nil, nil, now)
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
		if err := validatePerpetualPurchase(session, order, p.products.PerpetualV1, p.products.PerpetualLinkID); err != nil {
			return err
		}
		outcome = "no_change"
		if state != "fulfilled" {
			if session.PaymentStatus == stripe.CheckoutSessionPaymentStatusPaid {
				licenseID, err := p.licenses.IssuePurchasedLicense(ctx, tx, activation.PurchasedLicense{
					Plan: string(order.plan), PolicyVersion: order.policyVersion, CustomerID: session.Customer.ID, Email: session.CustomerDetails.Email,
				}, now)
				if err != nil {
					return err
				}
				// There is no committed paid-but-unfulfilled gap for this synchronous
				// perpetual path. A rollback leaves Stripe to retry all of it.
				if _, err := tx.ExecContext(ctx, `
					UPDATE checkout_orders SET state = 'fulfilled', license_id = $2, fulfilled_at = $3,
					    stripe_checkout_session_id = $4, stripe_payment_intent_id = $5
					WHERE id = $1`, order.id, licenseID, now, session.ID, session.PaymentIntent.ID); err != nil {
					return fmt.Errorf("fulfill purchase order: %w", err)
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

// A Payment Link has no preceding server order. Bind its immutable session ID
// to the configured link and catalog before creating the local purchase row.
func (p *EventProcessor) ensurePaymentLinkOrder(ctx context.Context, session *stripe.CheckoutSession, now time.Time) (bool, error) {
	if session.PaymentLink == nil {
		return false, nil
	}
	var plan Plan
	var priceID, productID string
	var mode stripe.CheckoutSessionMode
	switch session.PaymentLink.ID {
	case p.products.PerpetualLinkID:
		plan, priceID, productID, mode = PlanPerpetualV1, p.products.PerpetualPriceID, p.products.PerpetualV1, stripe.CheckoutSessionModePayment
	case p.products.MonthlyLinkID:
		plan, priceID, productID, mode = PlanMonthly, p.products.MonthlyPriceID, p.products.Monthly, stripe.CheckoutSessionModeSubscription
	default:
		return false, nil
	}
	if session.Object != "checkout.session" || session.Mode != mode ||
		session.ManagedPayments == nil || !session.ManagedPayments.Enabled ||
		session.LineItems == nil || session.LineItems.HasMore || len(session.LineItems.Data) != 1 {
		return false, ErrInvalidCheckoutSession
	}
	item := session.LineItems.Data[0]
	if item == nil || item.Quantity != 1 || !matchingMonthlyPrice(item.Price, priceID, productID, session.Livemode) {
		return false, ErrInvalidCheckoutSession
	}
	_, err := p.database.ExecContext(ctx, `
		INSERT INTO checkout_orders (id, plan, policy_version, stripe_price_id, stripe_checkout_session_id, state, created_at)
		VALUES ($1, $2, $3, $4, $1, 'pending', $5)
		ON CONFLICT (id) DO NOTHING`, session.ID, plan, PolicyVersion, priceID, now)
	if err != nil {
		return false, fmt.Errorf("record payment link purchase: %w", err)
	}
	var storedPlan, storedPrice, storedSession string
	if err := p.database.QueryRowContext(ctx, `
		SELECT plan, stripe_price_id, stripe_checkout_session_id FROM checkout_orders WHERE id = $1`, session.ID).
		Scan(&storedPlan, &storedPrice, &storedSession); err != nil {
		return false, fmt.Errorf("load payment link purchase: %w", err)
	}
	if storedPlan != string(plan) || storedPrice != priceID || storedSession != session.ID {
		return false, ErrInvalidCheckoutSession
	}
	return true, nil
}

func lockPurchaseOrder(ctx context.Context, tx *sql.Tx, session *stripe.CheckoutSession) (checkoutOrder, string, bool, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, plan, policy_version, stripe_price_id, stripe_checkout_session_id, stripe_payment_intent_id, created_at, state
		FROM checkout_orders WHERE stripe_checkout_session_id = $1
		FOR UPDATE`, session.ID)
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
