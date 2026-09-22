package billing

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juhokoskela/GlassEQServer/internal/activation"
	"github.com/juhokoskela/GlassEQServer/internal/entitlement"
	"github.com/stripe/stripe-go/v86"
)

func TestPurchaseFulfillmentWithPostgreSQL(t *testing.T) {
	p, licenses, checkout := purchaseFixture(t)
	// One connection makes any database connection held across hydration observable.
	p.database.SetMaxOpenConns(1)
	checkout.database = p.database
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	body := eventBody(t, "evt_purchase", "checkout.session.completed")
	if err := p.Process(ctx, body); err != nil {
		t.Fatal(err)
	}
	assertFulfillmentCounts(t, p.database, 1, 1)
	key := deliveredKey(t, p.database)
	result, err := licenses.Activate(ctx, activation.Input{
		LicenseKey: key, InstallationID: "b5c3a3a1-5bb7-4801-882f-05ccf2c0ae66",
		IdempotencyKey: "5870ddf6-7d70-4bf5-8236-f4c350aa7c57", ClientIP: netip.MustParseAddr("192.0.2.1"),
	})
	if err != nil || result.Status != 201 {
		t.Fatalf("delivered key activation: status=%d error=%v code=%s", result.Status, err, result.ErrorCode)
	}
	var response struct {
		Entitlement string `json:"entitlement"`
	}
	if err := json.Unmarshal(result.Body, &response); err != nil || response.Entitlement == "" {
		t.Fatal("activation did not issue an entitlement")
	}
	// Simulate a lost acknowledgement: even a provider outage cannot break replay.
	checkout.err = ErrStripeUnavailable
	if err := p.Process(ctx, body); err != nil {
		t.Fatalf("committed event replay: %v", err)
	}
	if checkout.calls.Load() != 1 {
		t.Fatalf("replayed event hydrated %d times", checkout.calls.Load())
	}
	assertFulfillmentCounts(t, p.database, 1, 1)
}

func TestConcurrentPurchaseEventsWithPostgreSQL(t *testing.T) {
	p, _, _ := purchaseFixture(t)
	const count = 16
	bodies := make([][]byte, count)
	for i := range count {
		// Both repeated event IDs and different events for the same order race.
		bodies[i] = eventBody(t, fmt.Sprintf("evt_%d", i%4), "checkout.session.completed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := make(chan struct{})
	errorsOut := make(chan error, count)
	var workers sync.WaitGroup
	for i := range count {
		workers.Go(func() { <-start; errorsOut <- p.Process(ctx, bodies[i]) })
	}
	close(start)
	workers.Wait()
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Error(err)
		}
	}
	assertFulfillmentCounts(t, p.database, 1, 4)
}

func TestPurchaseRollbackAndRetryWithPostgreSQL(t *testing.T) {
	p, licenses, _ := purchaseFixture(t)
	p.licenses = failingPurchaseIssuer{licenses}
	body := eventBody(t, "evt_retry", "checkout.session.completed")
	if err := p.Process(context.Background(), body); err == nil {
		t.Fatal("injected failure was lost")
	}
	assertFulfillmentCounts(t, p.database, 0, 0)
	p.licenses = licenses
	if err := p.Process(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	assertFulfillmentCounts(t, p.database, 1, 1)
}

func TestDelayedPurchaseAndReorderedEventsWithPostgreSQL(t *testing.T) {
	p, _, checkout := purchaseFixture(t)
	checkout.session.PaymentStatus = stripe.CheckoutSessionPaymentStatusUnpaid
	for i, kind := range []string{"checkout.session.completed", "checkout.session.async_payment_failed"} {
		if err := p.Process(context.Background(), eventBody(t, fmt.Sprintf("evt_unpaid%d", i), kind)); err != nil {
			t.Fatal(err)
		}
	}
	assertFulfillmentCounts(t, p.database, 0, 2)
	checkout.session = paidPurchase()
	if err := p.Process(context.Background(), eventBody(t, "evt_paid", "checkout.session.async_payment_succeeded")); err != nil {
		t.Fatal(err)
	}
	// A late failure notification hydrates the current paid state and cannot undo fulfillment.
	if err := p.Process(context.Background(), eventBody(t, "evt_late", "checkout.session.async_payment_failed")); err != nil {
		t.Fatal(err)
	}
	assertFulfillmentCounts(t, p.database, 1, 4)
}

func TestPurchaseRejectsOwnedMismatchWithPostgreSQL(t *testing.T) {
	for _, kind := range []string{"price", "session", "metadata", "monthly", "email", "payment_reference"} {
		t.Run(kind, func(t *testing.T) {
			p, _, checkout := purchaseFixture(t)
			switch kind {
			case "price":
				checkout.session.LineItems.Data[0].Price.ID = "price_other"
			case "session":
				if _, err := p.database.Exec(`UPDATE checkout_orders SET stripe_checkout_session_id = 'cs_other'`); err != nil {
					t.Fatal(err)
				}
			case "metadata":
				checkout.session.Metadata["order_id"] = "ord_other"
			case "monthly":
				if _, err := p.database.Exec(`UPDATE checkout_orders SET plan = 'monthly'`); err != nil {
					t.Fatal(err)
				}
			case "email":
				checkout.session.CustomerDetails.Email = "not an email"
			case "payment_reference":
				if _, err := p.database.Exec(`UPDATE checkout_orders SET stripe_checkout_session_id = 'cs_purchase', stripe_payment_intent_id = 'pi_other'`); err != nil {
					t.Fatal(err)
				}
			}
			if err := p.Process(context.Background(), eventBody(t, "evt_invalid", "checkout.session.completed")); err == nil {
				t.Fatal("owned mismatch was acknowledged")
			}
			assertFulfillmentCounts(t, p.database, 0, 0)
		})
	}
}

func TestStaleUnpaidSnapshotCannotUndoFulfillmentWithPostgreSQL(t *testing.T) {
	p, _, _ := purchaseFixture(t)
	stale := *p
	loaded := make(chan struct{})
	release := make(chan struct{})
	stale.checkout = purchaseRetrieverFunc(func(ctx context.Context, _ string) (*stripe.CheckoutSession, error) {
		session := paidPurchase()
		session.PaymentStatus = stripe.CheckoutSessionPaymentStatusUnpaid
		close(loaded)
		select {
		case <-release:
			return session, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	body := eventBody(t, "evt_stale_failure", "checkout.session.async_payment_failed")
	go func() { result <- stale.Process(ctx, body) }()
	select {
	case <-loaded:
	case <-ctx.Done():
		t.Fatal("stale hydration did not start")
	}
	if err := p.Process(ctx, eventBody(t, "evt_current_paid", "checkout.session.completed")); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	assertFulfillmentCounts(t, p.database, 1, 2)
}

type purchaseRetrieverFunc func(context.Context, string) (*stripe.CheckoutSession, error)

func (f purchaseRetrieverFunc) RetrievePurchase(ctx context.Context, id string) (*stripe.CheckoutSession, error) {
	return f(ctx, id)
}

func TestUnownedPurchaseAndEventCollisionWithPostgreSQL(t *testing.T) {
	p, _, checkout := purchaseFixture(t)
	checkout.session.ClientReferenceID = "ord_unknown"
	checkout.session.Metadata["order_id"] = "ord_unknown"
	body := eventBody(t, "evt_unowned", "checkout.session.completed")
	if err := p.Process(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	assertFulfillmentCounts(t, p.database, 0, 1)
	var outcome string
	if err := p.database.QueryRow(`SELECT outcome FROM stripe_events WHERE stripe_event_id = 'evt_unowned'`).Scan(&outcome); err != nil || outcome != "ignored_unowned" {
		t.Fatalf("unowned outcome=%s error=%v", outcome, err)
	}
	if err := p.Process(context.Background(), []byte(strings.ReplaceAll(string(body), "cs_purchase", "cs_collision"))); !errors.Is(err, ErrInvalidBillingEvent) {
		t.Fatalf("event ID collision: %v", err)
	}
}

func purchaseFixture(t *testing.T) (*EventProcessor, *activation.Service, *fakePurchaseRetriever) {
	t.Helper()
	database := openBillingTestDatabase(t)
	if _, err := database.Exec(`TRUNCATE licenses, checkout_orders, stripe_events, activation_rate_limits CASCADE`); err != nil {
		t.Fatal(err)
	}
	_, err := database.Exec(`INSERT INTO checkout_orders (id, request_id, plan, policy_version, stripe_price_id, state, created_at)
		VALUES ($1, $2, 'perpetual_v1', 'v1', 'price_perpetual', 'pending', $3)`, testCheckoutOrderID, testCheckoutRequestID, testCheckoutNow)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := entitlement.NewIssuer("test-purchase", purchaseSigner(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))))
	if err != nil {
		t.Fatal(err)
	}
	licenses, err := activation.NewService(database, issuer, activation.Secrets{
		IdempotencyKey: bytes.Repeat([]byte{1}, 32), RateLimitHMACKey: bytes.Repeat([]byte{2}, 32),
		EmailLookupHMACKey: bytes.Repeat([]byte{3}, 32), DatabaseEncryptionKey: bytes.Repeat([]byte{4}, 32),
	}, purchaseEmailQueue{})
	if err != nil {
		t.Fatal(err)
	}
	checkout := &fakePurchaseRetriever{session: paidPurchase()}
	processor, err := NewEventProcessor(database, checkout, licenses, testDestination, ProductCatalog{PerpetualV1: "prod_perpetual", Monthly: "prod_monthly"})
	if err != nil {
		t.Fatal(err)
	}
	processor.now = func() time.Time { return testCheckoutNow }
	return processor, licenses, checkout
}

type fakePurchaseRetriever struct {
	unsupportedAdjustments
	session  *stripe.CheckoutSession
	database *sql.DB
	err      error
	calls    atomic.Int32
}

func (c *fakePurchaseRetriever) RetrievePurchase(ctx context.Context, _ string) (*stripe.CheckoutSession, error) {
	c.calls.Add(1)
	if c.database != nil {
		if err := c.database.PingContext(ctx); err != nil {
			return nil, err
		}
	}
	return c.session, c.err
}

type failingPurchaseIssuer struct{ service *activation.Service }

func (f failingPurchaseIssuer) IssuePurchasedLicense(ctx context.Context, tx *sql.Tx, purchase activation.PurchasedLicense, now time.Time) (string, error) {
	if _, err := f.service.IssuePurchasedLicense(ctx, tx, purchase, now); err != nil {
		return "", err
	}
	return "", errors.New("injected failure after license and outbox writes")
}

type purchaseSigner ed25519.PrivateKey

func (s purchaseSigner) Sign(_ context.Context, message []byte) ([]byte, error) {
	return ed25519.Sign(ed25519.PrivateKey(s), message), nil
}

type purchaseEmailQueue struct{}

func (purchaseEmailQueue) SendRecoveryEmail(context.Context, activation.RecoveryEmail) error {
	return errors.New("unexpected email dispatch")
}

func assertFulfillmentCounts(t *testing.T, database *sql.DB, licenses, events int) {
	t.Helper()
	for _, check := range []struct {
		query string
		want  int
	}{
		{`SELECT count(*) FROM licenses`, licenses}, {`SELECT count(*) FROM license_keys`, licenses},
		{`SELECT count(*) FROM license_delivery_outbox`, licenses},
		{`SELECT count(*) FROM checkout_orders WHERE state = 'fulfilled'`, licenses},
		{`SELECT count(*) FROM stripe_events WHERE processed_at IS NOT NULL`, events},
	} {
		var got int
		if err := database.QueryRow(check.query).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != check.want {
			t.Errorf("%s = %d, want %d", check.query, got, check.want)
		}
	}
}

func deliveredKey(t *testing.T, database *sql.DB) string {
	t.Helper()
	var licenseID, keyID string
	var keyCiphertext, emailCiphertext []byte
	var created, expires time.Time
	err := database.QueryRow(`SELECT l.id, k.id, k.delivery_ciphertext, k.created_at, k.delivery_expires_at, l.recovery_email_ciphertext
		FROM licenses l JOIN license_keys k ON l.id = k.license_id`).Scan(&licenseID, &keyID, &keyCiphertext, &created, &expires, &emailCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	if expires.Sub(created) != 7*24*time.Hour {
		t.Fatal("incorrect delivery lifetime")
	}
	block, err := aes.NewCipher(bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	aad := binary.BigEndian.AppendUint64([]byte("license-delivery\x00"+keyID+"\x00"+licenseID+"\x00"), uint64(expires.Unix()))
	key, err := aead.Open(nil, keyCiphertext[:aead.NonceSize()], keyCiphertext[aead.NonceSize():], aad)
	if err != nil {
		t.Fatal(err)
	}
	email, err := aead.Open(nil, emailCiphertext[:aead.NonceSize()], emailCiphertext[aead.NonceSize():], []byte("recovery-email\x00"+licenseID))
	if err != nil || string(email) != "buyer@example.com" {
		t.Fatal("email did not round-trip in the recovery format")
	}
	return string(key)
}

func (*fakePurchaseRetriever) RetrieveSubscription(context.Context, string) (*stripe.Subscription, error) {
	return nil, ErrUnsupportedPurchase
}
func (*fakePurchaseRetriever) RetrieveInvoice(context.Context, string) (*stripe.Invoice, error) {
	return nil, ErrUnsupportedPurchase
}
func (purchaseRetrieverFunc) RetrieveSubscription(context.Context, string) (*stripe.Subscription, error) {
	return nil, ErrUnsupportedPurchase
}
func (purchaseRetrieverFunc) RetrieveInvoice(context.Context, string) (*stripe.Invoice, error) {
	return nil, ErrUnsupportedPurchase
}
