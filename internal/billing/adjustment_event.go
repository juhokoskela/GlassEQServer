package billing

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/stripe/stripe-go/v86"
)

// Ordinary billing writers lock the order before this check. Prepared external
// work must finish first; applied restrictions also prevent late fulfillment.
func billingRestriction(ctx context.Context, tx *sql.Tx, orderID string) (bool, error) {
	var pending, blocked bool
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(bool_or(pending OR cancel_required), false), COALESCE(bool_or(state = 'blocking'), false)
		FROM billing_adjustments WHERE order_id = $1`, orderID).Scan(&pending, &blocked); err != nil {
		return false, fmt.Errorf("read billing restrictions: %w", err)
	}
	if pending {
		return false, errBillingSnapshotChanged
	}
	return blocked, nil
}

func (p *EventProcessor) processAdjustment(ctx context.Context, event billingEvent, now time.Time) error {
	a, err := p.retrieveAdjustment(ctx, event, now)
	if err != nil {
		return err
	}
	identity, _, _, err := p.adjustmentIdentity(ctx, a)
	if err != nil {
		return err
	}
	order, found, err := readPurchaseOrder(ctx, p.database, identity, false)
	if err != nil {
		return err
	}
	if !found {
		_, _, err := p.prepareAdjustment(ctx, event, adjustmentSnapshot{}, now)
		return err
	}
	view, err := p.hydrateAdjustment(ctx, event, order, now)
	if err != nil {
		return err
	}
	order, done, err := p.prepareAdjustment(ctx, event, view, now)
	if err != nil || done {
		return err
	}
	view.order = order
	var cancelRequired bool
	if err := p.database.QueryRowContext(ctx, `SELECT COALESCE(bool_or(cancel_required), false) FROM billing_adjustments WHERE order_id = $1`, order.id).Scan(&cancelRequired); err != nil {
		return err
	}
	if cancelRequired && order.plan == PlanMonthly {
		if subscriptionCanBill(view.subscription) {
			if err := p.adjustments.CancelSubscription(ctx, view.subscription.ID); err != nil {
				return err
			}
		}
		// The cancellation response can be lost. A retry sees the durable intent,
		// retrieves the now-canceled subscription, and never needs to cancel twice.
		current, err := p.hydrateAdjustment(ctx, event, order, now)
		if err != nil {
			return err
		}
		if current.adjustment.chargeID != view.adjustment.chargeID || subscriptionCanBill(current.subscription) {
			return errBillingSnapshotChanged
		}
		view = current
	}
	return p.commitAdjustment(ctx, event, view, now)
}

func subscriptionCanBill(subscription *stripe.Subscription) bool {
	return subscription.Status != stripe.SubscriptionStatusCanceled && subscription.Status != stripe.SubscriptionStatusIncompleteExpired
}

func (p *EventProcessor) prepareAdjustment(ctx context.Context, event billingEvent, view adjustmentSnapshot, now time.Time) (purchaseOrder, bool, error) {
	tx, err := p.database.BeginTx(ctx, nil)
	if err != nil {
		return purchaseOrder{}, false, err
	}
	defer tx.Rollback()
	processed, err := matchingBillingEvent(ctx, tx, event, true)
	if err != nil || processed {
		return purchaseOrder{}, processed, err
	}
	outcome := "ignored_unowned"
	var order purchaseOrder
	if view.order.id != "" {
		var found bool
		order, found, err = readPurchaseOrder(ctx, tx, purchaseIdentity{referenceID: view.order.id}, true)
		if err != nil {
			return order, false, err
		}
		if !found || order.revision != view.order.revision || (order.sessionID.Valid && order.sessionID.String != view.session.ID) {
			return order, false, errBillingSnapshotChanged
		}
		outcome = "no_change"
		a := view.adjustment
		if a.state == "" {
			var existingState string
			err := tx.QueryRowContext(ctx, `SELECT state FROM billing_adjustments WHERE stripe_object_id = $1 AND (pending OR cancel_required)`, a.id).Scan(&existingState)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return order, false, err
			}
			if err == nil {
				a.state = existingState
			}
		}
		if a.state != "" {
			if _, err := tx.ExecContext(ctx, `INSERT INTO billing_adjustments (stripe_object_id, order_id, kind, stripe_charge_id, state, pending, cancel_required, effective_at, updated_at)
				VALUES ($1, $2, $3, $4, $5, true, $8, $6, $7) ON CONFLICT (stripe_object_id) DO NOTHING`, a.id, order.id, a.kind, a.chargeID, a.state, a.effectiveAt, now, a.state == "blocking" && order.plan == PlanMonthly); err != nil {
				return order, false, err
			}
			var storedOrder, kind, charge string
			var effectiveAt time.Time
			if err := tx.QueryRowContext(ctx, `SELECT order_id, kind, stripe_charge_id, effective_at FROM billing_adjustments WHERE stripe_object_id = $1 FOR UPDATE`, a.id).
				Scan(&storedOrder, &kind, &charge, &effectiveAt); err != nil {
				return order, false, err
			}
			if storedOrder != order.id || kind != a.kind || charge != a.chargeID || !effectiveAt.Equal(a.effectiveAt) {
				return order, false, ErrInvalidAdjustment
			}
			if _, err := tx.ExecContext(ctx, `UPDATE billing_adjustments SET state = $2, pending = true, cancel_required = cancel_required OR $4, updated_at = $3 WHERE stripe_object_id = $1`, a.id, a.state, now, a.state == "blocking" && order.plan == PlanMonthly); err != nil {
				return order, false, err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE checkout_orders SET billing_revision = billing_revision + 1 WHERE id = $1`, order.id); err != nil {
			return order, false, err
		}
		order.revision++
		if a.state != "" {
			return order, false, tx.Commit()
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE stripe_events SET processed_at = $2, outcome = $3 WHERE stripe_event_id = $1`, event.ID, now, outcome); err != nil {
		return order, false, err
	}
	return order, true, tx.Commit()
}

func (p *EventProcessor) commitAdjustment(ctx context.Context, event billingEvent, view adjustmentSnapshot, now time.Time) error {
	tx, err := p.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	processed, err := matchingBillingEvent(ctx, tx, event, true)
	if err != nil || processed {
		return err
	}
	order, found, err := readPurchaseOrder(ctx, tx, purchaseIdentity{referenceID: view.order.id}, true)
	if err != nil {
		return err
	}
	if !found || order.revision != view.order.revision {
		return errBillingSnapshotChanged
	}
	if _, err := tx.ExecContext(ctx, `UPDATE billing_adjustments SET pending = false, updated_at = $2 WHERE stripe_object_id = $1`, view.adjustment.id, now); err != nil {
		return err
	}
	if view.adjustment.state != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE billing_adjustments SET state = $2 WHERE stripe_object_id = $1`, view.adjustment.id, view.adjustment.state); err != nil {
			return err
		}
	}
	if order.plan == PlanMonthly && !subscriptionCanBill(view.subscription) {
		if _, err := tx.ExecContext(ctx, `UPDATE billing_adjustments SET cancel_required = false WHERE order_id = $1`, order.id); err != nil {
			return err
		}
	}
	view.order = order
	outcome, err := p.applyAdjustments(ctx, tx, event, view, now)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE checkout_orders SET billing_revision = billing_revision + 1 WHERE id = $1`, order.id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE stripe_events SET processed_at = $2, outcome = $3 WHERE stripe_event_id = $1`, event.ID, now, outcome); err != nil {
		return err
	}
	return tx.Commit()
}

func (p *EventProcessor) applyAdjustments(ctx context.Context, tx *sql.Tx, event billingEvent, view adjustmentSnapshot, now time.Time) (string, error) {
	order := view.order
	var refund, blocked bool
	var effectiveAt sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(bool_or(kind = 'refund'), false), count(*) > 0, min(effective_at)
		FROM billing_adjustments WHERE order_id = $1 AND state = 'blocking'`, order.id).Scan(&refund, &blocked, &effectiveAt); err != nil {
		return "", err
	}
	var licenseState string
	var previous subscriptionProjection
	if order.licenseID.Valid {
		var customerID string
		var subscriptionID sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT state, stripe_customer_id, stripe_subscription_id FROM licenses WHERE id = $1 FOR UPDATE`, order.licenseID.String).
			Scan(&licenseState, &customerID, &subscriptionID); err != nil {
			return "", err
		}
		if customerID != view.session.Customer.ID || (order.plan == PlanMonthly && (!subscriptionID.Valid || subscriptionID.String != view.subscription.ID)) {
			return "", ErrInvalidAdjustment
		}
		if licenseState == "revoked" {
			return "no_change", nil
		}
		if order.plan == PlanMonthly {
			if err := tx.QueryRowContext(ctx, `SELECT state, billing_period_end, recovery_until, COALESCE(last_paid_invoice_id, '') FROM subscriptions WHERE license_id = $1 FOR UPDATE`, order.licenseID.String).
				Scan(&previous.state, &previous.periodEnd, &previous.recoveryUntil, &previous.lastPaidInvoice); err != nil {
				return "", err
			}
		}
	}
	if blocked {
		// Another event may have prepared a cancellation after this resolved
		// dispute was read. Let that event confirm cancellation before restricting.
		if order.plan == PlanMonthly && subscriptionCanBill(view.subscription) {
			return "no_change", nil
		}
		state := "charged_back"
		if refund {
			state = "refunded"
		}
		if !order.licenseID.Valid {
			var paymentID, subscriptionID sql.NullString
			if order.plan == PlanMonthly {
				subscriptionID = sql.NullString{String: view.subscription.ID, Valid: true}
			} else {
				paymentID = sql.NullString{String: view.session.PaymentIntent.ID, Valid: true}
			}
			_, err := tx.ExecContext(ctx, `UPDATE checkout_orders SET state = 'failed', stripe_checkout_session_id = $2,
				stripe_payment_intent_id = $3, stripe_subscription_id = $4 WHERE id = $1`, order.id, view.session.ID, paymentID, subscriptionID)
			return state, err
		}
		if licenseState == "refunded" && state != "refunded" {
			return "no_change", nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE licenses SET state = $2, updated_at = $3 WHERE id = $1`, order.licenseID.String, state, now); err != nil {
			return "", err
		}
		if order.plan == PlanMonthly {
			if !effectiveAt.Valid {
				return "", errors.New("blocking adjustment has no effective time")
			}
			if _, err := tx.ExecContext(ctx, `UPDATE subscriptions SET terminal_at = LEAST(COALESCE(terminal_at, $2), $2),
				last_stripe_event_id = $3, last_reconciled_at = $4, updated_at = $4 WHERE license_id = $1`, order.licenseID.String, effectiveAt.Time, event.ID, now); err != nil {
				return "", err
			}
		}
		return state, nil
	}
	if view.adjustment.state != "resolved" || licenseState == "refunded" || (licenseState == "active" && order.plan == PlanPerpetualV1) {
		return "no_change", nil
	}
	charge := view.adjustment.charge
	if !charge.Paid || charge.Refunded || charge.AmountRefunded >= charge.Amount {
		return "no_change", nil
	}
	var next subscriptionProjection
	if order.plan == PlanMonthly {
		var eligible bool
		var err error
		next, eligible, err = p.restorationProjection(view, previous, now)
		if err != nil {
			return "", err
		}
		if !eligible && licenseState != "active" {
			return "no_change", nil
		}
	}
	if !order.licenseID.Valid {
		if order.plan == PlanPerpetualV1 {
			return "fulfilled", p.issuePerpetualPurchase(ctx, tx, order.checkoutOrder, view.session, now)
		}
		return "fulfilled", p.issueMonthlyPurchase(ctx, tx, order, view.session, next, event.ID, now)
	}
	if licenseState != "charged_back" && licenseState != "active" {
		return "no_change", nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE licenses SET state = 'active', updated_at = $2 WHERE id = $1`, order.licenseID.String, now); err != nil {
		return "", err
	}
	if order.plan == PlanMonthly {
		if _, err := tx.ExecContext(ctx, `UPDATE subscriptions SET state = $2, billing_period_end = $3, recovery_until = $4, terminal_at = NULL,
			last_paid_invoice_id = $5, last_stripe_event_id = $6, last_reconciled_at = $7, updated_at = $7 WHERE license_id = $1`,
			order.licenseID.String, next.state, next.periodEnd, next.recoveryUntil, next.lastPaidInvoice, event.ID, now); err != nil {
			return "", err
		}
	}
	return "restored", nil
}

func (p *EventProcessor) restorationProjection(view adjustmentSnapshot, previous subscriptionProjection, now time.Time) (subscriptionProjection, bool, error) {
	if view.initial == nil || view.initial.Status != stripe.InvoiceStatusPaid {
		return previous, false, nil
	}
	switch view.subscription.Status {
	case stripe.SubscriptionStatusActive, stripe.SubscriptionStatusPastDue, stripe.SubscriptionStatusUnpaid, stripe.SubscriptionStatusCanceled:
	default:
		return previous, false, nil
	}
	for _, invoice := range []*stripe.Invoice{view.initial, view.invoice, view.latest} {
		end, err := monthlyInvoicePeriod(invoice, view.subscription, view.order, p.products.Monthly)
		if err != nil {
			return previous, false, err
		}
		if end.After(previous.periodEnd) && invoice.ID != previous.lastPaidInvoice {
			previous.periodEnd, previous.lastPaidInvoice = end, invoice.ID
			previous.recoveryUntil = end.Add(14 * 24 * time.Hour)
		}
	}
	end, err := monthlyInvoicePeriod(view.latest, view.subscription, view.order, p.products.Monthly)
	if err != nil {
		return previous, false, err
	}
	next, err := reconcileSubscription(previous, view.subscription, view.latest.ID, end, now)
	if err != nil {
		return next, false, err
	}
	if view.subscription.Status == stripe.SubscriptionStatusCanceled {
		// Dispute restoration grants remaining paid access, not a new retry window
		// on a subscription that Stripe can no longer collect from.
		next.recoveryUntil = next.periodEnd
	}
	return next, now.Before(next.recoveryUntil.Add(7 * 24 * time.Hour)), nil
}
