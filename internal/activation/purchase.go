package activation

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

type PurchasedLicense struct {
	Plan           string
	SubscriptionID string
	PolicyVersion  string
	CustomerID     string
	Email          string
}

// IssuePurchasedLicense joins the billing owner's transaction. The caller locks
// the order and commits its fulfilled state with this license and delivery record.
// No credential leaves this method in plaintext, and no external service is called.
func (s *Service) IssuePurchasedLicense(ctx context.Context, tx *sql.Tx, purchase PurchasedLicense, now time.Time) (string, error) {
	email, valid := normalizeRecoveryEmail(purchase.Email)
	if !valid || purchase.PolicyVersion == "" || purchase.CustomerID == "" ||
		(purchase.Plan != "perpetual_v1" && purchase.Plan != "monthly") ||
		(purchase.Plan == "monthly") != (purchase.SubscriptionID != "") {
		return "", errors.New("invalid purchased license details")
	}
	licenseID, err := randomValue(s.random, "lic_", 16)
	if err != nil {
		return "", fmt.Errorf("generate purchased license ID: %w", err)
	}
	keyID, err := randomValue(s.random, "key_", 16)
	if err != nil {
		return "", fmt.Errorf("generate purchased key ID: %w", err)
	}
	deliveryID, err := randomValue(s.random, "del_", 16)
	if err != nil {
		return "", fmt.Errorf("generate license delivery ID: %w", err)
	}
	key, normalizedKey, err := generateLicenseKey(s.random)
	if err != nil {
		return "", fmt.Errorf("generate purchased license key: %w", err)
	}
	emailCiphertext, err := s.databaseValues.seal([]byte(email), recoveryEmailAdditionalData(licenseID))
	if err != nil {
		return "", fmt.Errorf("encrypt purchase email: %w", err)
	}
	expiresAt := now.Add(7 * 24 * time.Hour)
	keyCiphertext, err := s.databaseValues.seal([]byte(key), licenseDeliveryAdditionalData(keyID, licenseID, expiresAt))
	if err != nil {
		return "", fmt.Errorf("encrypt license delivery: %w", err)
	}
	emailHash := hmacSHA256(s.emailLookupHMACKey, email)
	keyHash := sha256.Sum256([]byte(normalizedKey))
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO licenses (id, plan, state, policy_version, recovery_email_ciphertext,
		    recovery_email_lookup, stripe_customer_id, stripe_subscription_id, created_at, updated_at)
		VALUES ($1, $2, 'active', $3, $4, $5, $6, NULLIF($7, ''), $8, $8)`,
		licenseID, purchase.Plan, purchase.PolicyVersion, emailCiphertext, emailHash[:], purchase.CustomerID, purchase.SubscriptionID, now); err != nil {
		return "", fmt.Errorf("insert purchased license: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO license_keys (id, license_id, secret_hash, delivery_ciphertext,
		    delivery_expires_at, state, created_at)
		VALUES ($1, $2, $3, $4, $5, 'active', $6)`, keyID, licenseID, keyHash[:], keyCiphertext, expiresAt, now); err != nil {
		return "", fmt.Errorf("insert purchased license key: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO license_delivery_outbox (id, license_key_id, created_at, expires_at, next_attempt_at)
		VALUES ($1, $2, $3, $4, $3)`, deliveryID, keyID, now, expiresAt); err != nil {
		return "", fmt.Errorf("insert license delivery: %w", err)
	}
	return licenseID, nil
}

func licenseDeliveryAdditionalData(keyID, licenseID string, expiresAt time.Time) []byte {
	data := []byte("license-delivery\x00" + keyID + "\x00" + licenseID + "\x00")
	return binary.BigEndian.AppendUint64(data, uint64(expiresAt.Unix()))
}
