package billing

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/stripe/stripe-go/v86"
)

const (
	reconciliationPageSize = 100
	maximumLinkSessions    = 10000
)

type paymentLinkSessionLister interface {
	ListPaymentLinkSessions(context.Context, string, string) ([]*stripe.CheckoutSession, bool, error)
}

type Reconciler struct {
	processor *EventProcessor
	sessions  paymentLinkSessionLister
}

func NewReconciler(processor *EventProcessor, sessions paymentLinkSessionLister) (*Reconciler, error) {
	if processor == nil || sessions == nil {
		return nil, errors.New("billing processor and Payment Link session lister are required")
	}
	return &Reconciler{processor: processor, sessions: sessions}, nil
}

func (c *CheckoutClient) ListPaymentLinkSessions(ctx context.Context, linkID, after string) ([]*stripe.CheckoutSession, bool, error) {
	if !validStripeID(linkID, "plink_") || (after != "" && !validStripeID(after, "cs_")) {
		return nil, false, ErrInvalidCheckoutSession
	}
	requestCtx, cancel := context.WithTimeout(ctx, stripeRequestTimeout)
	defer cancel()
	params := &stripe.CheckoutSessionListParams{PaymentLink: stripe.String(linkID), Status: stripe.String("complete")}
	params.Limit = stripe.Int64(reconciliationPageSize)
	if after != "" {
		params.StartingAfter = stripe.String(after)
	}
	list := c.sessionList.List(requestCtx, params)
	if list == nil {
		return nil, false, ErrStripeUnavailable
	}
	if err := list.Err(); err != nil {
		return nil, false, sanitizeStripeError(requestCtx, err)
	}
	return list.Data(), list.Meta().HasMore, nil
}

// Run scans completed Sessions from both configured links. A later run starts
// from the newest Session again, so an interrupted scan needs no cursor state.
func (r *Reconciler) Run(ctx context.Context, day time.Time) (int, error) {
	day = day.UTC().Truncate(24 * time.Hour)
	recovered := 0
	var firstErr error
	for _, linkID := range []string{r.processor.products.PerpetualLinkID, r.processor.products.MonthlyLinkID} {
		cursor := ""
		seen := 0
		for {
			sessions, more, err := r.sessions.ListPaymentLinkSessions(ctx, linkID, cursor)
			if err != nil {
				return recovered, fmt.Errorf("list Payment Link %s: %w", linkID, err)
			}
			if len(sessions) == 0 && more {
				return recovered, fmt.Errorf("Payment Link %s returned an empty page with more sessions", linkID)
			}
			seen += len(sessions)
			if seen > maximumLinkSessions {
				return recovered, fmt.Errorf("Payment Link %s exceeded the reconciliation limit", linkID)
			}
			for _, session := range sessions {
				if err := ctx.Err(); err != nil {
					return recovered, err
				}
				if session == nil || !validStripeID(session.ID, "cs_") || session.PaymentLink == nil || session.PaymentLink.ID != linkID ||
					session.Livemode != r.processor.liveMode || session.Status != stripe.CheckoutSessionStatusComplete {
					return recovered, ErrInvalidCheckoutSession
				}
				if session.PaymentStatus != stripe.CheckoutSessionPaymentStatusPaid {
					continue
				}
				var fulfilled, restricted bool
				err := r.processor.database.QueryRowContext(ctx, `SELECT
					EXISTS (SELECT 1 FROM checkout_orders WHERE stripe_checkout_session_id = $1 AND state = 'fulfilled'),
					EXISTS (SELECT 1 FROM billing_adjustments AS a JOIN checkout_orders AS o ON o.id = a.order_id
						WHERE o.stripe_checkout_session_id = $1 AND (a.state = 'blocking' OR a.pending OR a.cancel_required))`, session.ID).
					Scan(&fulfilled, &restricted)
				if err != nil {
					return recovered, fmt.Errorf("check reconciled purchase: %w", err)
				}
				if restricted || (fulfilled && linkID == r.processor.products.PerpetualLinkID) {
					continue
				}
				if err := r.processor.reconcileSession(ctx, session.ID, day); err != nil {
					if firstErr == nil {
						firstErr = fmt.Errorf("reconcile Session %s: %w", session.ID, err)
					}
					continue
				}
				if !fulfilled {
					recovered++
				}
			}
			if !more {
				break
			}
			next := sessions[len(sessions)-1].ID
			if next == cursor {
				return recovered, fmt.Errorf("Payment Link %s repeated a page", linkID)
			}
			cursor = next
		}
	}
	return recovered, firstErr
}

func (p *EventProcessor) reconcileSession(ctx context.Context, sessionID string, day time.Time) error {
	now := p.now().UTC().Truncate(time.Microsecond)
	event := billingEvent{ID: "reconcile_" + day.Format("20060102") + "_" + sessionID,
		Type: "reconciliation.checkout_session", Created: day.Unix()}
	event.Data.Object.ID, event.Data.Object.Object = sessionID, "checkout.session"
	if err := p.processEvent(ctx, event, now); err != nil {
		return err
	}
	var fulfilled, restricted bool
	if err := p.database.QueryRowContext(ctx, `SELECT o.state = 'fulfilled', COALESCE(bool_or(a.state = 'blocking'), false)
		FROM checkout_orders AS o LEFT JOIN billing_adjustments AS a ON a.order_id = o.id
		WHERE o.stripe_checkout_session_id = $1 GROUP BY o.id`, sessionID).Scan(&fulfilled, &restricted); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvalidCheckoutSession
		}
		return err
	}
	if !fulfilled && !restricted {
		return fmt.Errorf("paid Session %s remains unfulfilled", sessionID)
	}
	return nil
}
