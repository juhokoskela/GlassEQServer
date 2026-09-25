package activation

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

type recordingLicenseEmailSender struct {
	message LicenseEmail
	calls   int
	err     error
}

func (*recordingLicenseEmailSender) SendRecoveryEmail(context.Context, RecoveryEmail) error {
	return nil
}

func (s *recordingLicenseEmailSender) SendLicenseEmail(_ context.Context, message LicenseEmail) error {
	s.calls++
	s.message = message
	return s.err
}

func TestPurchasedLicenseEmailDispatchWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	sender := &recordingLicenseEmailSender{err: errors.New("SES unavailable")}
	service := newTestServiceWithEmailSender(t, database, localIssuer(t), sender)
	now := service.now()
	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.IssuePurchasedLicense(context.Background(), tx, PurchasedLicense{
		Plan: "perpetual_v1", PolicyVersion: "v1", CustomerID: "cus_buyer", Email: "Buyer@Example.com",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if worked, err := service.DispatchLicenseEmail(context.Background(), now); err == nil || worked {
		t.Fatalf("failed delivery: worked=%t error=%v", worked, err)
	}
	var pending int
	if err := database.QueryRow(`SELECT count(*) FROM license_delivery_outbox`).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("failed delivery lost outbox: count=%d error=%v", pending, err)
	}
	sender.err = nil
	if worked, err := service.DispatchLicenseEmail(context.Background(), now.Add(time.Minute)); err != nil || !worked {
		t.Fatalf("retry delivery: worked=%t error=%v", worked, err)
	}
	if sender.calls != 2 || sender.message.Email != "buyer@example.com" || sender.message.LicenseKey == "" {
		t.Fatalf("delivered email: calls=%d email=%q key present=%t", sender.calls, sender.message.Email, sender.message.LicenseKey != "")
	}
	var ciphertext []byte
	var expiry sql.NullTime
	if err := database.QueryRow(`SELECT delivery_ciphertext, delivery_expires_at FROM license_keys`).Scan(&ciphertext, &expiry); err != nil || ciphertext != nil || expiry.Valid {
		t.Fatalf("delivery copy retained: ciphertext=%t expiry=%t error=%v", ciphertext != nil, expiry.Valid, err)
	}
	if err := database.QueryRow(`SELECT count(*) FROM license_delivery_outbox`).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("delivered outbox retained: count=%d error=%v", pending, err)
	}
	if worked, err := service.DispatchLicenseEmail(context.Background(), now.Add(2*time.Minute)); err != nil || worked {
		t.Fatalf("duplicate delivery: worked=%t error=%v", worked, err)
	}
}

func TestExpiredLicenseDeliveryCopyIsClearedWithPostgreSQL(t *testing.T) {
	database := openTestDatabase(t)
	resetActivationData(t, database)
	service := newTestServiceWithEmailSender(t, database, localIssuer(t), &recordingLicenseEmailSender{})
	now := service.now()
	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.IssuePurchasedLicense(context.Background(), tx, PurchasedLicense{
		Plan: "perpetual_v1", PolicyVersion: "v1", CustomerID: "cus_buyer", Email: "buyer@example.com",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CleanupExpired(context.Background(), now.Add(7*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	var ciphertext []byte
	var expiry sql.NullTime
	if err := database.QueryRow(`SELECT delivery_ciphertext, delivery_expires_at FROM license_keys`).Scan(&ciphertext, &expiry); err != nil || ciphertext != nil || expiry.Valid {
		t.Fatalf("expired delivery copy retained: ciphertext=%t expiry=%t error=%v", ciphertext != nil, expiry.Valid, err)
	}
	var pending int
	if err := database.QueryRow(`SELECT count(*) FROM license_delivery_outbox`).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("expired outbox retained: count=%d error=%v", pending, err)
	}
}
