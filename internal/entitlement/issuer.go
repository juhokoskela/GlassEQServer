package entitlement

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"uuid"
)

const (
	IssuerURL           = "https://license.glasseq.app"
	Audience            = "com.glasseq.app"
	SchemaVersion       = int64(1)
	HeaderType          = "glasseq-entitlement+jwt"
	monthlyGraceSeconds = int64(7 * 24 * 60 * 60)
)

type plan string

const (
	planPerpetualV1 plan = "perpetual_v1"
	planMonthly     plan = "monthly"
)

type BillingState string

const (
	BillingActive      BillingState = "active"
	BillingRecovering  BillingState = "recovering"
	BillingEnding      BillingState = "ending"
	BillingLapsed      BillingState = "lapsed"
	BillingRefunded    BillingState = "refunded"
	BillingChargedBack BillingState = "charged_back"
)

type Claims struct {
	LicenseID      string
	EntitlementID  string
	IssuedAt       int64
	ActivationID   string
	InstallationID string
	Revision       int64
}

type MonthlyClaims struct {
	Claims
	BillingState               BillingState
	BillingPeriodEnd           int64
	RecoveryUntil              int64
	RefreshAfter               int64
	ExpiresAt                  int64
	SecurityUpdatesAfterExpiry bool
}

type Signer interface {
	Sign(context.Context, []byte) ([]byte, error)
}

type Issuer struct {
	encodedHeader string
	signer        Signer
}

func NewIssuer(keyID string, signer Signer) (*Issuer, error) {
	if err := ValidateKeyID(keyID); err != nil {
		return nil, fmt.Errorf("entitlement key ID %w", err)
	}
	if signer == nil {
		return nil, errors.New("entitlement signer is required")
	}
	header, err := json.Marshal(jwsHeader{
		Algorithm: "EdDSA",
		KeyID:     keyID,
		Type:      HeaderType,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal entitlement header: %w", err)
	}
	return &Issuer{encodedHeader: encodeBase64URL(header), signer: signer}, nil
}

func (i *Issuer) IssuePerpetual(ctx context.Context, claims Claims) (string, error) {
	payload, err := newCommonPayload(claims, planPerpetualV1)
	if err != nil {
		return "", err
	}
	payload.ReleaseScope = "v1"
	return i.issue(ctx, payload)
}

func (i *Issuer) IssueMonthly(ctx context.Context, claims MonthlyClaims) (string, error) {
	payload, err := newCommonPayload(claims.Claims, planMonthly)
	if err != nil {
		return "", err
	}
	if err := validateMonthlyClaims(claims.Claims.IssuedAt, claims); err != nil {
		return "", err
	}
	payload.ReleaseScope = "current"
	payload.SecurityUpdatesAfterExpiry = claims.SecurityUpdatesAfterExpiry
	return i.issue(ctx, monthlyPayload{
		commonPayload:    payload,
		BillingState:     claims.BillingState,
		BillingPeriodEnd: claims.BillingPeriodEnd,
		RecoveryUntil:    claims.RecoveryUntil,
		RefreshAfter:     claims.RefreshAfter,
		ExpiresAt:        claims.ExpiresAt,
	})
}

func (i *Issuer) issue(ctx context.Context, payload any) (string, error) {
	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal entitlement payload: %w", err)
	}
	signingInput := i.encodedHeader + "." + encodeBase64URL(encodedPayload)
	if len(signingInput) > maximumRawKMSMessageSize {
		return "", errors.New("entitlement signing input exceeds AWS KMS 4 KiB limit")
	}
	signature, err := i.signer.Sign(ctx, []byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("sign entitlement: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return "", fmt.Errorf("sign entitlement: signer returned %d-byte signature", len(signature))
	}

	return signingInput + "." + encodeBase64URL(signature), nil
}

type jwsHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

type commonPayload struct {
	Issuer                     string `json:"iss"`
	Audience                   string `json:"aud"`
	LicenseID                  string `json:"sub"`
	EntitlementID              string `json:"jti"`
	IssuedAt                   int64  `json:"iat"`
	Schema                     int64  `json:"schema"`
	Plan                       plan   `json:"plan"`
	ActivationID               string `json:"activation_id"`
	InstallationID             string `json:"installation_id"`
	Revision                   int64  `json:"revision"`
	ReleaseScope               string `json:"release_scope"`
	SecurityUpdatesAfterExpiry bool   `json:"security_updates_after_expiry"`
}

type monthlyPayload struct {
	commonPayload
	BillingState     BillingState `json:"billing_state"`
	BillingPeriodEnd int64        `json:"billing_period_end"`
	RecoveryUntil    int64        `json:"recovery_until"`
	RefreshAfter     int64        `json:"refresh_after"`
	ExpiresAt        int64        `json:"exp"`
}

func newCommonPayload(claims Claims, entitlementPlan plan) (commonPayload, error) {
	installationID, err := validateCommonClaims(claims)
	if err != nil {
		return commonPayload{}, err
	}
	return commonPayload{
		Issuer:         IssuerURL,
		Audience:       Audience,
		LicenseID:      claims.LicenseID,
		EntitlementID:  claims.EntitlementID,
		IssuedAt:       claims.IssuedAt,
		Schema:         SchemaVersion,
		Plan:           entitlementPlan,
		ActivationID:   claims.ActivationID,
		InstallationID: installationID,
		Revision:       claims.Revision,
	}, nil
}

func validateCommonClaims(claims Claims) (string, error) {
	fields := []struct {
		name  string
		value string
	}{
		{name: "license ID", value: claims.LicenseID},
		{name: "entitlement ID", value: claims.EntitlementID},
		{name: "activation ID", value: claims.ActivationID},
		{name: "installation ID", value: claims.InstallationID},
	}
	for _, field := range fields {
		if field.value == "" || len(field.value) > 256 {
			return "", fmt.Errorf("%s must contain 1 to 256 bytes", field.name)
		}
	}
	if len(claims.InstallationID) != 36 {
		return "", errors.New("installation ID must be a canonical UUID")
	}
	installationID, err := uuid.Parse(claims.InstallationID)
	if err != nil {
		return "", errors.New("installation ID must be a canonical UUID")
	}
	if claims.IssuedAt < 0 {
		return "", errors.New("entitlement issue time must not be negative")
	}
	if claims.Revision <= 0 {
		return "", errors.New("entitlement revision must be positive")
	}
	return strings.ToUpper(installationID.String()), nil
}

func validateMonthlyClaims(issuedAt int64, claims MonthlyClaims) error {
	switch claims.BillingState {
	case BillingActive, BillingRecovering, BillingEnding, BillingLapsed, BillingRefunded, BillingChargedBack:
	default:
		return fmt.Errorf("unsupported billing state %q", claims.BillingState)
	}
	if claims.BillingPeriodEnd < 0 || claims.RecoveryUntil < 0 || claims.RefreshAfter < 0 || claims.ExpiresAt < 0 {
		return errors.New("monthly entitlement times must not be negative")
	}
	if issuedAt > claims.RefreshAfter || claims.RefreshAfter > claims.ExpiresAt {
		return errors.New("monthly entitlement refresh time is outside its validity window")
	}
	if claims.RecoveryUntil > math.MaxInt64-monthlyGraceSeconds || claims.ExpiresAt != claims.RecoveryUntil+monthlyGraceSeconds {
		return errors.New("monthly entitlement expiry must be seven days after recovery")
	}
	switch claims.BillingState {
	case BillingActive, BillingRecovering, BillingEnding, BillingLapsed:
		if claims.BillingPeriodEnd > claims.RecoveryUntil {
			return errors.New("monthly entitlement recovery must not precede the billing period end")
		}
	}
	return nil
}

func ValidateKeyID(value string) error {
	if len(value) == 0 || len(value) > 128 {
		return errors.New("must contain 1 to 128 letters, digits, dots, underscores, or hyphens")
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			continue
		}
		switch r {
		case '.', '_', '-':
			continue
		default:
			return errors.New("must contain 1 to 128 letters, digits, dots, underscores, or hyphens")
		}
	}
	return nil
}

func encodeBase64URL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}
