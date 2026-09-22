package billing

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/juhokoskela/GlassEQServer/internal/activation"
	"github.com/stripe/stripe-go/v86"
)

var errBillingSnapshotChanged = errors.New("billing order changed during Stripe hydration")

type monthlyOrder struct {
	checkoutOrder
	state          string
	licenseID      sql.NullString
	subscriptionID sql.NullString
	revision       int64
}

type purchaseOrderReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func readMonthlyOrder(ctx context.Context, database purchaseOrderReader, sessionID, referenceID, metadataID, subscriptionID string, lock bool) (monthlyOrder, bool, error) {
	query := `SELECT id, plan, policy_version, stripe_price_id, stripe_checkout_session_id, created_at,
		state, license_id, stripe_subscription_id, billing_revision FROM checkout_orders
		WHERE stripe_checkout_session_id = $1 OR id = $2 OR id = $3 OR stripe_subscription_id = $4 ORDER BY id`
	if lock {
		query += " FOR UPDATE"
	}
	rows, err := database.QueryContext(ctx, query, sessionID, referenceID, metadataID, subscriptionID)
	if err != nil {
		return monthlyOrder{}, false, fmt.Errorf("read monthly order: %w", err)
	}
	defer rows.Close()
	var order monthlyOrder
	found := false
	for rows.Next() {
		if found {
			return monthlyOrder{}, false, ErrInvalidSubscription
		}
		found = true
		if err := rows.Scan(&order.id, &order.plan, &order.policyVersion, &order.priceID, &order.sessionID, &order.createdAt,
			&order.state, &order.licenseID, &order.subscriptionID, &order.revision); err != nil {
			return monthlyOrder{}, false, fmt.Errorf("scan monthly order: %w", err)
		}
	}
	return order, found, rows.Err()
}

func (p *EventProcessor) processMonthlyEvent(ctx context.Context, event billingEvent, session *stripe.CheckoutSession, now time.Time) error {
	var sessionID, referenceID, metadataID, subscriptionID string
	if session != nil {
		sessionID, referenceID, metadataID = session.ID, session.ClientReferenceID, session.Metadata["order_id"]
	} else {
		subscriptionID = event.Data.Object.ID
		if event.Data.Object.Object == "invoice" {
			invoice, err := p.checkout.RetrieveInvoice(ctx, event.Data.Object.ID)
			if err != nil {
				return err
			}
			if invoice == nil || invoice.ID != event.Data.Object.ID || invoice.Object != "invoice" || invoice.Livemode != p.destination.LiveMode {
				return ErrInvalidSubscription
			}
			subscriptionID = invoiceSubscriptionID(invoice)
			if subscriptionID == "" {
				return p.commitMonthlyEvent(ctx, event, monthlyOrder{}, nil, nil, nil, nil, now)
			}
		}
		// This first read resolves ownership only. A second read below supplies
		// state after the database revision has been captured.
		subscription, err := p.checkout.RetrieveSubscription(ctx, subscriptionID)
		if err != nil {
			return err
		}
		if subscription == nil || subscription.ID != subscriptionID || subscription.Object != "subscription" || subscription.Livemode != p.destination.LiveMode {
			return ErrInvalidSubscription
		}
		metadataID = subscription.Metadata["order_id"]
	}
	order, found, err := readMonthlyOrder(ctx, p.database, sessionID, referenceID, metadataID, subscriptionID, false)
	if err != nil {
		return err
	}
	if !found {
		return p.commitMonthlyEvent(ctx, event, monthlyOrder{}, nil, nil, nil, nil, now)
	}
	if order.plan != PlanMonthly {
		return ErrInvalidSubscription
	}
	if sessionID == "" {
		// Checkout creation attaches the Session ID, or its event recovers it
		// through order metadata. Until then this lifecycle event must retry.
		if !order.sessionID.Valid {
			return errBillingSnapshotChanged
		}
		sessionID = order.sessionID.String
	}
	// Refresh Checkout as well: a payment may complete between ownership lookup
	// and revision capture. No database connection remains held during these calls.
	session, err = p.checkout.RetrievePurchase(ctx, sessionID)
	if err != nil {
		return err
	}
	if session == nil || session.ID != sessionID || session.Livemode != p.destination.LiveMode {
		return ErrInvalidSubscription
	}
	if err := validateMonthlySession(session, order, p.products.Monthly); err != nil {
		return err
	}
	if session.Status != stripe.CheckoutSessionStatusComplete {
		if subscriptionID != "" {
			return ErrInvalidSubscription
		}
		return p.commitMonthlyEvent(ctx, event, order, session, nil, nil, nil, now)
	}
	if subscriptionID != "" && subscriptionID != session.Subscription.ID {
		return ErrInvalidSubscription
	}
	subscription, err := p.checkout.RetrieveSubscription(ctx, session.Subscription.ID)
	if err != nil {
		return err
	}
	if err := validateMonthlySubscription(subscription, session, order, p.products.Monthly); err != nil {
		return err
	}
	if session.Invoice == nil || !validStripeID(session.Invoice.ID, "in_") || subscription.LatestInvoice == nil || !validStripeID(subscription.LatestInvoice.ID, "in_") {
		return ErrInvalidSubscription
	}
	latest, err := p.checkout.RetrieveInvoice(ctx, subscription.LatestInvoice.ID)
	if err != nil {
		return err
	}
	if latest == nil || latest.ID != subscription.LatestInvoice.ID {
		return ErrInvalidSubscription
	}
	if _, err := monthlyInvoicePeriod(latest, subscription, order, p.products.Monthly); err != nil {
		return err
	}
	var initial *stripe.Invoice
	if !order.licenseID.Valid {
		initial = latest
		if session.Invoice.ID != latest.ID {
			initial, err = p.checkout.RetrieveInvoice(ctx, session.Invoice.ID)
			if err != nil {
				return err
			}
		}
		if initial == nil || initial.ID != session.Invoice.ID || initial.BillingReason != stripe.InvoiceBillingReasonSubscriptionCreate {
			return ErrInvalidSubscription
		}
		if _, err := monthlyInvoicePeriod(initial, subscription, order, p.products.Monthly); err != nil {
			return err
		}
	}
	if event.Data.Object.Object == "invoice" && event.Data.Object.ID != latest.ID {
		invoice, err := p.checkout.RetrieveInvoice(ctx, event.Data.Object.ID)
		if err != nil {
			return err
		}
		if invoice == nil || invoice.ID != event.Data.Object.ID {
			return ErrInvalidSubscription
		}
		paidEnd, err := monthlyInvoicePeriod(invoice, subscription, order, p.products.Monthly)
		if err != nil {
			return err
		}
		latestPaidEnd, err := monthlyInvoicePeriod(latest, subscription, order, p.products.Monthly)
		if err != nil {
			return err
		}
		if paidEnd.After(latestPaidEnd) {
			latest = invoice
		}
	}
	return p.commitMonthlyEvent(ctx, event, order, session, subscription, initial, latest, now)
}

func (p *EventProcessor) commitMonthlyEvent(ctx context.Context, event billingEvent, snapshot monthlyOrder, session *stripe.CheckoutSession,
	subscription *stripe.Subscription, initial, latest *stripe.Invoice, now time.Time) error {
	tx, err := p.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin monthly event: %w", err)
	}
	defer tx.Rollback()
	processed, err := matchingBillingEvent(ctx, tx, event, true)
	if err != nil || processed {
		return err
	}
	outcome := "ignored_unowned"
	if snapshot.id != "" {
		order, found, err := readMonthlyOrder(ctx, tx, "", snapshot.id, "", "", true)
		if err != nil {
			return err
		}
		if !found || order.revision != snapshot.revision {
			return errBillingSnapshotChanged
		}
		if err := validateMonthlySession(session, order, p.products.Monthly); err != nil {
			return err
		}
		outcome, err = p.applyMonthlyPurchase(ctx, tx, event, order, session, subscription, initial, latest, now)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE checkout_orders SET billing_revision = billing_revision + 1 WHERE id = $1`, order.id); err != nil {
			return fmt.Errorf("advance billing revision: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE stripe_events SET processed_at = $2, outcome = $3 WHERE stripe_event_id = $1`, event.ID, now, outcome); err != nil {
		return fmt.Errorf("complete monthly event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit monthly event: %w", err)
	}
	return nil
}

func (p *EventProcessor) applyMonthlyPurchase(ctx context.Context, tx *sql.Tx, event billingEvent, order monthlyOrder, session *stripe.CheckoutSession,
	subscription *stripe.Subscription, initial, latest *stripe.Invoice, now time.Time) (string, error) {
	if order.licenseID.Valid {
		var licenseState, customerID, subscriptionID string
		if err := tx.QueryRowContext(ctx, `SELECT state, stripe_customer_id, stripe_subscription_id FROM licenses WHERE id = $1 FOR UPDATE`, order.licenseID.String).
			Scan(&licenseState, &customerID, &subscriptionID); err != nil {
			return "", fmt.Errorf("lock monthly license: %w", err)
		}
		if subscription == nil || subscription.Customer.ID != customerID || subscription.ID != subscriptionID {
			return "", ErrInvalidSubscription
		}
		if licenseState != "active" {
			return "no_change", nil
		}
		var previous subscriptionProjection
		if err := tx.QueryRowContext(ctx, `SELECT state, billing_period_end, recovery_until, COALESCE(last_paid_invoice_id, '') FROM subscriptions WHERE license_id = $1 FOR UPDATE`, order.licenseID.String).
			Scan(&previous.state, &previous.periodEnd, &previous.recoveryUntil, &previous.lastPaidInvoice); err != nil {
			return "", fmt.Errorf("lock subscription projection: %w", err)
		}
		paidEnd, err := monthlyInvoicePeriod(latest, subscription, order, p.products.Monthly)
		if err != nil {
			return "", err
		}
		next, err := reconcileSubscription(previous, subscription, latest.ID, paidEnd, now)
		if err != nil {
			return "", err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE subscriptions SET state = $2, billing_period_end = $3, recovery_until = $4,
			last_paid_invoice_id = $5, last_stripe_event_id = $6, last_reconciled_at = $7, updated_at = $7 WHERE license_id = $1`,
			order.licenseID.String, next.state, next.periodEnd, next.recoveryUntil, next.lastPaidInvoice, event.ID, now); err != nil {
			return "", fmt.Errorf("update subscription: %w", err)
		}
		if next == previous {
			return "no_change", nil
		}
		return next.state, nil
	}
	if subscription != nil && initial.Status == stripe.InvoiceStatusPaid && subscription.Status == stripe.SubscriptionStatusActive {
		paidEnd, err := monthlyInvoicePeriod(latest, subscription, order, p.products.Monthly)
		if err != nil {
			return "", err
		}
		initialPaidEnd, err := monthlyInvoicePeriod(initial, subscription, order, p.products.Monthly)
		if err != nil {
			return "", err
		}
		previous := subscriptionProjection{
			periodEnd: initialPaidEnd, recoveryUntil: initialPaidEnd.Add(14 * 24 * time.Hour), lastPaidInvoice: initial.ID,
		}
		next, err := reconcileSubscription(previous, subscription, latest.ID, paidEnd, now)
		if err != nil {
			return "", err
		}
		licenseID, err := p.licenses.IssuePurchasedLicense(ctx, tx, activation.PurchasedLicense{
			Plan: string(order.plan), PolicyVersion: order.policyVersion, CustomerID: session.Customer.ID,
			SubscriptionID: subscription.ID, Email: session.CustomerDetails.Email,
		}, now)
		if err != nil {
			return "", err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO subscriptions (license_id, state, billing_period_end, recovery_until,
			last_paid_invoice_id, last_stripe_event_id, last_reconciled_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $7)`,
			licenseID, next.state, next.periodEnd, next.recoveryUntil, next.lastPaidInvoice, event.ID, now); err != nil {
			return "", fmt.Errorf("create subscription: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE checkout_orders SET state = 'fulfilled', license_id = $2, fulfilled_at = $3,
			stripe_checkout_session_id = $4, stripe_subscription_id = $5 WHERE id = $1`, order.id, licenseID, now, session.ID, subscription.ID); err != nil {
			return "", fmt.Errorf("fulfill monthly order: %w", err)
		}
		return "fulfilled", nil
	}
	failed := session.Status == stripe.CheckoutSessionStatusExpired || event.Type == "checkout.session.async_payment_failed"
	if subscription != nil {
		failed = failed || subscription.Status == stripe.SubscriptionStatusCanceled || subscription.Status == stripe.SubscriptionStatusIncompleteExpired || subscription.Status == stripe.SubscriptionStatusUnpaid
	}
	state, outcome := order.state, "no_change"
	if failed {
		state, outcome = "failed", "failed"
	}
	var subscriptionID any
	if subscription != nil {
		subscriptionID = subscription.ID
	}
	if _, err := tx.ExecContext(ctx, `UPDATE checkout_orders SET state = $2, stripe_checkout_session_id = $3, stripe_subscription_id = $4 WHERE id = $1`,
		order.id, state, session.ID, subscriptionID); err != nil {
		return "", fmt.Errorf("record unpaid monthly order: %w", err)
	}
	return outcome, nil
}
