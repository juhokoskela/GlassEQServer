package billing

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	testCheckoutRequestID = "2b1bc1ba-407a-49f2-ad2e-a260a56bcf23"
	testCheckoutOrderID   = "ord_2b1bc1ba407a49f2ad2ea260a56bcf23"
)

var testCheckoutNow = time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)

func TestCheckoutOrderLifecycleWithPostgreSQL(t *testing.T) {
	database := openBillingTestDatabase(t)
	resetBillingData(t, database)
	checkout := newFakeOrderCheckout()
	service := newTestOrderService(t, database, checkout)

	input := checkoutOrderInput(testCheckoutRequestID, PlanPerpetualV1)
	created, err := service.CreateCheckoutSession(context.Background(), input)
	if err != nil {
		t.Fatalf("create Checkout order: %v", err)
	}
	if created.URL != checkout.session.URL {
		t.Errorf("Checkout URL = %q, want %q", created.URL, checkout.session.URL)
	}

	assertCheckoutOrder(t, database, testCheckoutRequestID, PlanPerpetualV1, "price_perpetual", checkout.session.ID)
	assertCheckoutRateLimit(t, database, 1)
	createCall := checkout.createCall(t, 0)
	if createCall.spec.OrderID != testCheckoutOrderID || createCall.spec.PolicyVersion != PolicyVersion || createCall.spec.PriceID != "price_perpetual" {
		t.Errorf("Checkout spec = %+v", createCall.spec)
	}
	if createCall.idempotencyKey != "checkout-"+testCheckoutRequestID {
		t.Errorf("Stripe idempotency key = %q", createCall.idempotencyKey)
	}

	service.prices.PerpetualV1 = "price_replacement"
	replayed, err := service.CreateCheckoutSession(context.Background(), input)
	if err != nil {
		t.Fatalf("replay Checkout order: %v", err)
	}
	if replayed != created {
		t.Errorf("replay = %+v, want %+v", replayed, created)
	}
	if checkout.createCount() != 1 || checkout.retrieveCount() != 1 {
		t.Errorf("Stripe calls = %d creates, %d retrieves", checkout.createCount(), checkout.retrieveCount())
	}
	if call := checkout.retrieveCall(t, 0); call.sessionID != checkout.session.ID || call.spec != createCall.spec {
		t.Errorf("retrieve call = %+v", call)
	}
	assertCheckoutRateLimit(t, database, 1)

	_, err = service.CreateCheckoutSession(context.Background(), checkoutOrderInput(testCheckoutRequestID, PlanMonthly))
	if !errors.Is(err, ErrCheckoutIdempotencyConflict) {
		t.Fatalf("conflicting plan error = %v, want ErrCheckoutIdempotencyConflict", err)
	}
	if checkout.createCount() != 1 || checkout.retrieveCount() != 1 {
		t.Error("conflicting replay called Stripe")
	}
}

func TestCheckoutOrderRetriesUnattachedReservationWithPostgreSQL(t *testing.T) {
	database := openBillingTestDatabase(t)
	resetBillingData(t, database)
	checkout := newFakeOrderCheckout()
	checkout.createErr = ErrStripeUnavailable
	service := newTestOrderService(t, database, checkout)
	input := checkoutOrderInput(testCheckoutRequestID, PlanMonthly)

	if _, err := service.CreateCheckoutSession(context.Background(), input); !errors.Is(err, ErrStripeUnavailable) {
		t.Fatalf("first attempt error = %v, want ErrStripeUnavailable", err)
	}
	assertCheckoutOrder(t, database, testCheckoutRequestID, PlanMonthly, "price_monthly", "")
	assertCheckoutRateLimit(t, database, 1)

	checkout.createErr = nil
	result, err := service.CreateCheckoutSession(context.Background(), input)
	if err != nil {
		t.Fatalf("retry Checkout order: %v", err)
	}
	if result != checkout.session {
		t.Errorf("retry result = %+v, want %+v", result, checkout.session)
	}
	if checkout.createCount() != 2 {
		t.Fatalf("Stripe create calls = %d, want 2", checkout.createCount())
	}
	first := checkout.createCall(t, 0)
	second := checkout.createCall(t, 1)
	if first != second {
		t.Errorf("retry changed Stripe request: first=%+v second=%+v", first, second)
	}
	assertCheckoutOrder(t, database, testCheckoutRequestID, PlanMonthly, "price_monthly", checkout.session.ID)
	assertCheckoutRateLimit(t, database, 1)
}

func TestCheckoutOrderRejectsExpiredUnattachedReservationWithPostgreSQL(t *testing.T) {
	database := openBillingTestDatabase(t)
	resetBillingData(t, database)
	checkout := newFakeOrderCheckout()
	service := newTestOrderService(t, database, checkout)
	input := checkoutOrderInput(testCheckoutRequestID, PlanMonthly)

	checkout.createErr = ErrStripeUnavailable
	if _, err := service.CreateCheckoutSession(context.Background(), input); !errors.Is(err, ErrStripeUnavailable) {
		t.Fatalf("first attempt error = %v", err)
	}
	checkout.createErr = nil
	service.now = func() time.Time { return testCheckoutNow.Add(checkoutReservationLifetime) }

	if _, err := service.CreateCheckoutSession(context.Background(), input); !errors.Is(err, ErrCheckoutSessionExpired) {
		t.Fatalf("expired reservation error = %v, want ErrCheckoutSessionExpired", err)
	}
	if checkout.createCount() != 1 {
		t.Errorf("Stripe create calls = %d, want 1", checkout.createCount())
	}
}

func TestCheckoutOrderRateLimitRollsBackReservationWithPostgreSQL(t *testing.T) {
	database := openBillingTestDatabase(t)
	resetBillingData(t, database)
	checkout := newFakeOrderCheckout()
	service := newTestOrderService(t, database, checkout)
	input := checkoutOrderInput(testCheckoutRequestID, PlanMonthly)
	seedCheckoutRateLimit(t, database, service, input.ClientIP, checkoutIPAttemptLimit)

	_, err := service.CreateCheckoutSession(context.Background(), input)
	var rateLimitError *CheckoutRateLimitError
	if !errors.As(err, &rateLimitError) {
		t.Fatalf("rate-limit error = %v, want CheckoutRateLimitError", err)
	}
	if rateLimitError.RetryAfterSeconds != 3600 {
		t.Errorf("Retry-After = %d, want 3600", rateLimitError.RetryAfterSeconds)
	}
	if checkout.createCount() != 0 {
		t.Error("rate-limited request called Stripe")
	}
	assertCheckoutOrderCount(t, database, 0)
	assertCheckoutRateLimit(t, database, checkoutIPAttemptLimit)
}

func TestConcurrentCheckoutOrderRetryCreatesOneReservationWithPostgreSQL(t *testing.T) {
	database := openBillingTestDatabase(t)
	resetBillingData(t, database)
	checkout := newFakeOrderCheckout()
	checkout.createStarted = make(chan struct{}, 2)
	checkout.releaseCreate = make(chan struct{})
	service := newTestOrderService(t, database, checkout)
	input := checkoutOrderInput(testCheckoutRequestID, PlanMonthly)

	results := make([]CheckoutSession, 2)
	errorsByIndex := make([]error, 2)
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[index], errorsByIndex[index] = service.CreateCheckoutSession(context.Background(), input)
		}()
	}
	for range results {
		select {
		case <-checkout.createStarted:
		case <-time.After(time.Second):
			t.Fatal("concurrent request did not reach Stripe")
		}
	}
	close(checkout.releaseCreate)
	wait.Wait()

	for index, err := range errorsByIndex {
		if err != nil {
			t.Fatalf("concurrent request %d: %v", index, err)
		}
		if results[index] != checkout.session {
			t.Errorf("concurrent result %d = %+v", index, results[index])
		}
	}
	assertCheckoutOrderCount(t, database, 1)
	assertCheckoutRateLimit(t, database, 1)
}

func TestCheckoutOrderDoesNotHoldDatabaseConnectionDuringStripeCall(t *testing.T) {
	database := openBillingTestDatabase(t)
	resetBillingData(t, database)
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	checkout := newFakeOrderCheckout()
	checkout.createStarted = make(chan struct{}, 1)
	checkout.releaseCreate = make(chan struct{})
	service := newTestOrderService(t, database, checkout)

	done := make(chan error, 1)
	go func() {
		_, err := service.CreateCheckoutSession(context.Background(), checkoutOrderInput(testCheckoutRequestID, PlanMonthly))
		done <- err
	}()
	select {
	case <-checkout.createStarted:
	case <-time.After(time.Second):
		t.Fatal("request did not reach Stripe")
	}

	pingCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := database.PingContext(pingCtx); err != nil {
		t.Errorf("database connection remained held during Stripe call: %v", err)
	}
	close(checkout.releaseCreate)
	if err := <-done; err != nil {
		t.Fatalf("create Checkout order: %v", err)
	}
}

func checkoutOrderInput(requestID string, plan Plan) CreateCheckoutOrderInput {
	return CreateCheckoutOrderInput{
		RequestID: requestID,
		Plan:      plan,
		ClientIP:  netip.MustParseAddr("192.0.2.50"),
	}
}

func newTestOrderService(t *testing.T, database *sql.DB, checkout checkoutOrderClient) *OrderService {
	t.Helper()
	service, err := NewOrderService(database, checkout, PriceCatalog{
		PerpetualV1: "price_perpetual",
		Monthly:     "price_monthly",
	}, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("create order service: %v", err)
	}
	service.now = func() time.Time { return testCheckoutNow }
	return service
}

func openBillingTestDatabase(t *testing.T) *sql.DB {
	t.Helper()
	databaseURL := os.Getenv("GLASSEQ_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("GLASSEQ_TEST_DATABASE_URL is not set")
	}
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := database.PingContext(context.Background()); err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	return database
}

func resetBillingData(t *testing.T, database *sql.DB) {
	t.Helper()
	if _, err := database.ExecContext(context.Background(), "TRUNCATE checkout_orders, activation_rate_limits"); err != nil {
		t.Fatalf("reset billing data: %v", err)
	}
}

func assertCheckoutOrder(t *testing.T, database *sql.DB, requestID string, plan Plan, priceID, sessionID string) {
	t.Helper()
	var gotPlan Plan
	var gotPriceID string
	var gotSessionID sql.NullString
	var state, policyVersion string
	err := database.QueryRowContext(context.Background(), `
		SELECT plan, policy_version, stripe_price_id, stripe_checkout_session_id, state
		FROM checkout_orders
		WHERE request_id = $1`, requestID).Scan(&gotPlan, &policyVersion, &gotPriceID, &gotSessionID, &state)
	if err != nil {
		t.Fatalf("load Checkout order: %v", err)
	}
	if gotPlan != plan || policyVersion != PolicyVersion || gotPriceID != priceID || gotSessionID.String != sessionID || state != "pending" {
		t.Errorf("stored Checkout order = plan %q, policy %q, price %q, session %q, state %q", gotPlan, policyVersion, gotPriceID, gotSessionID.String, state)
	}
}

func assertCheckoutOrderCount(t *testing.T, database *sql.DB, want int) {
	t.Helper()
	var got int
	if err := database.QueryRowContext(context.Background(), "SELECT count(*) FROM checkout_orders").Scan(&got); err != nil {
		t.Fatalf("count Checkout orders: %v", err)
	}
	if got != want {
		t.Errorf("Checkout order count = %d, want %d", got, want)
	}
}

func seedCheckoutRateLimit(t *testing.T, database *sql.DB, service *OrderService, clientIP netip.Addr, attempts int) {
	t.Helper()
	subjectHash := service.checkoutIPHash(clientIP)
	_, err := database.ExecContext(context.Background(), `
		INSERT INTO activation_rate_limits (kind, subject_hash, window_start, attempts)
		VALUES ('checkout_ip', $1, $2, $3)`, subjectHash[:], testCheckoutNow.Truncate(rateLimitWindow), attempts)
	if err != nil {
		t.Fatalf("seed Checkout rate limit: %v", err)
	}
}

func assertCheckoutRateLimit(t *testing.T, database *sql.DB, want int) {
	t.Helper()
	var attempts int
	if err := database.QueryRowContext(context.Background(), `
		SELECT attempts FROM activation_rate_limits WHERE kind = 'checkout_ip'`).Scan(&attempts); err != nil {
		t.Fatalf("load Checkout rate limit: %v", err)
	}
	if attempts != want {
		t.Errorf("Checkout rate-limit attempts = %d, want %d", attempts, want)
	}
}

type checkoutCall struct {
	spec           CheckoutSessionSpec
	idempotencyKey string
	sessionID      string
}

type fakeOrderCheckout struct {
	mu            sync.Mutex
	session       CheckoutSession
	createErr     error
	retrieveErr   error
	creates       []checkoutCall
	retrieves     []checkoutCall
	createStarted chan struct{}
	releaseCreate chan struct{}
}

func newFakeOrderCheckout() *fakeOrderCheckout {
	return &fakeOrderCheckout{session: CheckoutSession{
		ID:        "cs_test_order",
		URL:       "https://checkout.stripe.com/c/pay/order",
		ExpiresAt: testCheckoutNow.Add(24 * time.Hour),
	}}
}

func (f *fakeOrderCheckout) Create(ctx context.Context, spec CheckoutSessionSpec, idempotencyKey string) (CheckoutSession, error) {
	f.mu.Lock()
	f.creates = append(f.creates, checkoutCall{spec: spec, idempotencyKey: idempotencyKey})
	started, release := f.createStarted, f.releaseCreate
	response, err := f.session, f.createErr
	f.mu.Unlock()
	if started != nil {
		started <- struct{}{}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return CheckoutSession{}, ctx.Err()
		}
	}
	return response, err
}

func (f *fakeOrderCheckout) Retrieve(_ context.Context, sessionID string, spec CheckoutSessionSpec) (CheckoutSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.retrieves = append(f.retrieves, checkoutCall{spec: spec, sessionID: sessionID})
	return f.session, f.retrieveErr
}

func (f *fakeOrderCheckout) createCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.creates)
}

func (f *fakeOrderCheckout) retrieveCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.retrieves)
}

func (f *fakeOrderCheckout) createCall(t *testing.T, index int) checkoutCall {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.creates) <= index {
		t.Fatalf("Stripe create call %d is missing", index)
	}
	return f.creates[index]
}

func (f *fakeOrderCheckout) retrieveCall(t *testing.T, index int) checkoutCall {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.retrieves) <= index {
		t.Fatalf("Stripe retrieve call %d is missing", index)
	}
	return f.retrieves[index]
}
