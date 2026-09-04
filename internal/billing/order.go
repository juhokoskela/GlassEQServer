package billing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"
	"uuid"
)

const (
	checkoutReservationLifetime = 24 * time.Hour
	checkoutRetryMargin         = 5 * time.Minute
	checkoutAttemptWindow       = time.Minute
	checkoutAttemptLimit        = 60
	checkoutReservationWindow   = time.Hour
	checkoutReservationLimit    = 20
	checkoutStripeConcurrency   = 4
)

var (
	ErrInvalidCheckoutRequest      = errors.New("invalid Checkout request")
	ErrCheckoutIdempotencyConflict = errors.New("Checkout idempotency key was used for another plan")
	ErrCheckoutBusy                = errors.New("Checkout is busy")
)

type CheckoutRateLimitError struct {
	RetryAfterSeconds int
}

func (e *CheckoutRateLimitError) Error() string {
	return "too many Checkout requests"
}

type PriceCatalog struct {
	PerpetualV1 string
	Monthly     string
}

type CreateCheckoutOrderInput struct {
	RequestID string
	Plan      Plan
	ClientIP  netip.Addr
}

type checkoutOrderClient interface {
	Create(context.Context, CheckoutSessionSpec, string, string) (CheckoutSession, error)
	Retrieve(context.Context, string, CheckoutSessionSpec) (CheckoutSession, error)
}

type OrderService struct {
	database         *sql.DB
	checkout         checkoutOrderClient
	prices           PriceCatalog
	rateLimitHMACKey []byte
	stripeSlots      chan struct{}
	now              func() time.Time
}

func NewOrderService(database *sql.DB, checkout checkoutOrderClient, prices PriceCatalog, rateLimitHMACKey []byte) (*OrderService, error) {
	if database == nil {
		return nil, errors.New("Checkout database is required")
	}
	if checkout == nil {
		return nil, errors.New("Checkout client is required")
	}
	if !validPriceID(prices.PerpetualV1) {
		return nil, errors.New("perpetual Stripe Price ID must start with price_")
	}
	if !validPriceID(prices.Monthly) {
		return nil, errors.New("monthly Stripe Price ID must start with price_")
	}
	if len(rateLimitHMACKey) != sha256.Size {
		return nil, errors.New("rate-limit HMAC key must contain 32 bytes")
	}
	return &OrderService{
		database:         database,
		checkout:         checkout,
		prices:           prices,
		rateLimitHMACKey: append([]byte(nil), rateLimitHMACKey...),
		stripeSlots:      make(chan struct{}, checkoutStripeConcurrency),
		now:              time.Now,
	}, nil
}

func (s *OrderService) CreateCheckoutSession(ctx context.Context, input CreateCheckoutOrderInput) (CheckoutSession, error) {
	prepared, err := prepareCheckoutOrder(input)
	if err != nil {
		return CheckoutSession{}, err
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	retryAfter, err := s.consumeCheckoutAttempt(ctx, prepared.clientIP, now)
	if err != nil {
		return CheckoutSession{}, err
	}
	if retryAfter > 0 {
		return CheckoutSession{}, &CheckoutRateLimitError{RetryAfterSeconds: retryAfter}
	}
	order, err := s.reserveOrder(ctx, prepared, now)
	if err != nil {
		return CheckoutSession{}, err
	}
	spec := CheckoutSessionSpec{
		OrderID:       order.id,
		Plan:          order.plan,
		PolicyVersion: order.policyVersion,
	}
	if order.sessionID.Valid {
		if !s.acquireStripeSlot() {
			return CheckoutSession{}, ErrCheckoutBusy
		}
		session, err := s.checkout.Retrieve(ctx, order.sessionID.String, spec)
		s.releaseStripeSlot()
		if err != nil {
			return CheckoutSession{}, err
		}
		return usableCheckoutSession(session)
	}
	// Stripe may discard POST idempotency results after 24 hours. Do not let an
	// old unattached reservation create a replacement Session under the same key.
	// The margin keeps the request clear of Stripe's pruning boundary.
	retryNow := s.now().UTC()
	if !retryNow.Before(order.createdAt.Add(checkoutReservationLifetime - checkoutRetryMargin)) {
		return CheckoutSession{}, ErrCheckoutSessionExpired
	}
	if !s.acquireStripeSlot() {
		return CheckoutSession{}, ErrCheckoutBusy
	}

	session, err := s.checkout.Create(ctx, spec, order.priceID, "checkout-"+prepared.requestID)
	s.releaseStripeSlot()
	if err != nil {
		return CheckoutSession{}, err
	}
	if err := s.attachSession(ctx, order.id, session.ID); err != nil {
		return CheckoutSession{}, err
	}
	return usableCheckoutSession(session)
}

func usableCheckoutSession(session CheckoutSession) (CheckoutSession, error) {
	switch session.State {
	case CheckoutSessionOpen:
		return session, nil
	case CheckoutSessionExpired:
		return CheckoutSession{}, ErrCheckoutSessionExpired
	case CheckoutSessionComplete:
		return CheckoutSession{}, ErrCheckoutSessionComplete
	default:
		return CheckoutSession{}, ErrInvalidCheckoutSession
	}
}

type preparedCheckoutOrder struct {
	requestID string
	plan      Plan
	clientIP  netip.Addr
}

func prepareCheckoutOrder(input CreateCheckoutOrderInput) (preparedCheckoutOrder, error) {
	if len(input.RequestID) != 36 {
		return preparedCheckoutOrder{}, ErrInvalidCheckoutRequest
	}
	requestID, err := uuid.Parse(input.RequestID)
	if err != nil || requestID.String() != input.RequestID || requestID[6]>>4 != 4 || requestID[8]&0xc0 != 0x80 {
		return preparedCheckoutOrder{}, ErrInvalidCheckoutRequest
	}
	if input.Plan != PlanPerpetualV1 && input.Plan != PlanMonthly {
		return preparedCheckoutOrder{}, ErrInvalidCheckoutRequest
	}
	if !input.ClientIP.IsValid() {
		return preparedCheckoutOrder{}, ErrInvalidCheckoutRequest
	}
	clientIP := input.ClientIP.Unmap()
	if clientIP.Is6() {
		clientIP = netip.PrefixFrom(clientIP, 64).Masked().Addr()
	}
	return preparedCheckoutOrder{requestID: input.RequestID, plan: input.Plan, clientIP: clientIP}, nil
}

type checkoutOrder struct {
	id            string
	plan          Plan
	policyVersion string
	priceID       string
	sessionID     sql.NullString
	createdAt     time.Time
}

func (s *OrderService) reserveOrder(ctx context.Context, input preparedCheckoutOrder, now time.Time) (checkoutOrder, error) {
	order, found, err := loadCheckoutOrder(ctx, s.database, input.requestID)
	if err != nil {
		return checkoutOrder{}, err
	}
	if found {
		return matchingCheckoutOrder(order, input.plan)
	}

	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return checkoutOrder{}, fmt.Errorf("begin Checkout order reservation: %w", err)
	}
	defer tx.Rollback()

	order = checkoutOrder{
		id:            "ord_" + strings.ReplaceAll(input.requestID, "-", ""),
		plan:          input.plan,
		policyVersion: PolicyVersion,
		priceID:       s.priceID(input.plan),
		createdAt:     now,
	}
	result, err := tx.ExecContext(ctx, `
		INSERT INTO checkout_orders (
		    id, request_id, plan, policy_version, stripe_price_id, state, created_at
		) VALUES ($1, $2, $3, $4, $5, 'pending', $6)
		ON CONFLICT (request_id) DO NOTHING`,
		order.id, input.requestID, order.plan, order.policyVersion, order.priceID, order.createdAt)
	if err != nil {
		return checkoutOrder{}, fmt.Errorf("reserve Checkout order: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return checkoutOrder{}, fmt.Errorf("inspect Checkout order reservation: %w", err)
	}
	if inserted == 0 {
		order, found, err = loadCheckoutOrder(ctx, tx, input.requestID)
		if err != nil {
			return checkoutOrder{}, err
		}
		if !found {
			return checkoutOrder{}, errors.New("conflicting Checkout order disappeared")
		}
		return matchingCheckoutOrder(order, input.plan)
	}

	retryAfter, err := s.consumeCheckoutReservation(ctx, tx, input.clientIP, now)
	if err != nil {
		return checkoutOrder{}, err
	}
	if retryAfter > 0 {
		return checkoutOrder{}, &CheckoutRateLimitError{RetryAfterSeconds: retryAfter}
	}
	if err := tx.Commit(); err != nil {
		return checkoutOrder{}, fmt.Errorf("commit Checkout order reservation: %w", err)
	}
	return order, nil
}

type checkoutOrderQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func loadCheckoutOrder(ctx context.Context, database checkoutOrderQuerier, requestID string) (checkoutOrder, bool, error) {
	var order checkoutOrder
	err := database.QueryRowContext(ctx, `
		SELECT id, plan, policy_version, stripe_price_id, stripe_checkout_session_id, created_at
		FROM checkout_orders
		WHERE request_id = $1`, requestID).Scan(
		&order.id, &order.plan, &order.policyVersion, &order.priceID, &order.sessionID, &order.createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return checkoutOrder{}, false, nil
	}
	if err != nil {
		return checkoutOrder{}, false, fmt.Errorf("load Checkout order: %w", err)
	}
	return order, true, nil
}

func matchingCheckoutOrder(order checkoutOrder, plan Plan) (checkoutOrder, error) {
	if order.plan != plan {
		return checkoutOrder{}, ErrCheckoutIdempotencyConflict
	}
	return order, nil
}

func (s *OrderService) priceID(plan Plan) string {
	if plan == PlanPerpetualV1 {
		return s.prices.PerpetualV1
	}
	return s.prices.Monthly
}

func (s *OrderService) consumeCheckoutAttempt(ctx context.Context, clientIP netip.Addr, now time.Time) (int, error) {
	windowStart := now.Truncate(checkoutAttemptWindow)
	subjectHash := s.checkoutIPHash(clientIP)
	var attempts int
	err := s.database.QueryRowContext(ctx, `
		INSERT INTO activation_rate_limits (kind, subject_hash, window_start, attempts)
		VALUES ('checkout_attempt_ip', $1, $2, 1)
		ON CONFLICT (kind, subject_hash, window_start)
		DO UPDATE SET attempts = activation_rate_limits.attempts + 1
		RETURNING attempts`, subjectHash[:], windowStart).Scan(&attempts)
	if err != nil {
		return 0, fmt.Errorf("update Checkout attempt rate limit: %w", err)
	}
	if attempts <= checkoutAttemptLimit {
		return 0, nil
	}
	seconds := int(math.Ceil(windowStart.Add(checkoutAttemptWindow).Sub(now).Seconds()))
	return max(seconds, 1), nil
}

func (s *OrderService) consumeCheckoutReservation(ctx context.Context, tx *sql.Tx, clientIP netip.Addr, now time.Time) (int, error) {
	windowStart := now.Truncate(checkoutReservationWindow)
	subjectHash := s.checkoutIPHash(clientIP)
	var attempts int
	err := tx.QueryRowContext(ctx, `
		INSERT INTO activation_rate_limits (kind, subject_hash, window_start, attempts)
		VALUES ('checkout_ip', $1, $2, 1)
		ON CONFLICT (kind, subject_hash, window_start)
		DO UPDATE SET attempts = activation_rate_limits.attempts + 1
		RETURNING attempts`, subjectHash[:], windowStart).Scan(&attempts)
	if err != nil {
		return 0, fmt.Errorf("update Checkout IP rate limit: %w", err)
	}
	if attempts <= checkoutReservationLimit {
		return 0, nil
	}
	seconds := int(math.Ceil(windowStart.Add(checkoutReservationWindow).Sub(now).Seconds()))
	return max(seconds, 1), nil
}

func (s *OrderService) checkoutIPHash(clientIP netip.Addr) [sha256.Size]byte {
	digest := hmac.New(sha256.New, s.rateLimitHMACKey)
	digest.Write([]byte("checkout_ip\x00"))
	digest.Write([]byte(clientIP.String()))
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func (s *OrderService) acquireStripeSlot() bool {
	select {
	case s.stripeSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *OrderService) releaseStripeSlot() {
	<-s.stripeSlots
}

func (s *OrderService) attachSession(ctx context.Context, orderID, sessionID string) error {
	result, err := s.database.ExecContext(ctx, `
		UPDATE checkout_orders
		SET stripe_checkout_session_id = $1
		WHERE id = $2 AND stripe_checkout_session_id IS NULL`, sessionID, orderID)
	if err != nil {
		return fmt.Errorf("attach Checkout Session: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect Checkout Session attachment: %w", err)
	}
	if updated == 1 {
		return nil
	}

	var storedSessionID string
	if err := s.database.QueryRowContext(ctx, `
		SELECT stripe_checkout_session_id
		FROM checkout_orders
		WHERE id = $1`, orderID).Scan(&storedSessionID); err != nil {
		return fmt.Errorf("load attached Checkout Session: %w", err)
	}
	if storedSessionID != sessionID {
		return errors.New("Checkout order is attached to another Stripe Session")
	}
	return nil
}
