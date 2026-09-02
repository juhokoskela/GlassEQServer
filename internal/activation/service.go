package activation

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"uuid"

	"github.com/juhokoskela/GlassEQServer/internal/entitlement"
)

const (
	idempotencyScope       = "activation"
	idempotencyLifetime    = 24 * time.Hour
	rateLimitWindow        = time.Hour
	licenseKeyAttemptLimit = 20
	ipAttemptLimit         = 100
	maximumActivations     = 2
	monthlyRefreshInterval = 7 * 24 * time.Hour
	monthlyGracePeriod     = 7 * 24 * time.Hour
)

type entitlementIssuer interface {
	IssuePerpetual(context.Context, entitlement.Claims) (string, error)
	IssueMonthly(context.Context, entitlement.MonthlyClaims) (string, error)
}

type Service struct {
	database         *sql.DB
	issuer           entitlementIssuer
	responses        *responseCipher
	rateLimitHMACKey []byte
	random           io.Reader
	now              func() time.Time
}

type Input struct {
	LicenseKey     string
	InstallationID string
	IdempotencyKey string
	ClientIP       string
	RequestID      string
}

type Response struct {
	Status            int
	Body              []byte
	RetryAfterSeconds int
}

func NewService(database *sql.DB, issuer entitlementIssuer, idempotencyKey, rateLimitHMACKey []byte) (*Service, error) {
	if database == nil {
		return nil, errors.New("activation database is required")
	}
	if issuer == nil {
		return nil, errors.New("entitlement issuer is required")
	}
	responses, err := newResponseCipher(idempotencyKey, rand.Reader)
	if err != nil {
		return nil, err
	}
	if len(rateLimitHMACKey) != 32 {
		return nil, errors.New("rate-limit HMAC key must contain 32 bytes")
	}
	return &Service{
		database:         database,
		issuer:           issuer,
		responses:        responses,
		rateLimitHMACKey: append([]byte(nil), rateLimitHMACKey...),
		random:           rand.Reader,
		now:              time.Now,
	}, nil
}

func (s *Service) Activate(ctx context.Context, input Input) (Response, error) {
	if input.RequestID == "" {
		return Response{}, errors.New("activation request ID is required")
	}
	prepared, invalidCode := prepare(input)
	if invalidCode != "" {
		return errorResponse(http.StatusBadRequest, invalidCode, "The activation request is invalid.", input.RequestID), nil
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return Response{}, fmt.Errorf("begin activation: %w", err)
	}
	defer tx.Rollback()

	if err := lockCredential(ctx, tx, prepared.credentialHash); err != nil {
		return Response{}, err
	}
	replayed, found, conflict, err := s.loadIdempotency(ctx, tx, prepared, now)
	if err != nil {
		return Response{}, err
	}
	if conflict {
		return errorResponse(http.StatusConflict, "idempotency_conflict", "The idempotency key was already used for another request.", input.RequestID), nil
	}
	if found {
		return replayed, nil
	}

	retryAfter, err := s.consumeRateLimits(ctx, tx, prepared, now)
	if err != nil {
		return Response{}, err
	}
	if retryAfter > 0 {
		response := errorResponse(http.StatusTooManyRequests, "rate_limited", "Too many activation attempts. Try again later.", input.RequestID)
		response.RetryAfterSeconds = retryAfter
		return s.storeAndCommit(ctx, tx, prepared, response, now)
	}
	if !prepared.credentialValid {
		response := errorResponse(http.StatusUnauthorized, "invalid_credentials", "The license key is invalid.", input.RequestID)
		return s.storeAndCommit(ctx, tx, prepared, response, now)
	}

	license, err := findLicense(ctx, tx, prepared.credentialHash)
	if errors.Is(err, sql.ErrNoRows) {
		response := errorResponse(http.StatusUnauthorized, "invalid_credentials", "The license key is invalid.", input.RequestID)
		return s.storeAndCommit(ctx, tx, prepared, response, now)
	}
	if err != nil {
		return Response{}, err
	}
	terms, eligible, err := entitlementTerms(license, now)
	if err != nil {
		return Response{}, err
	}
	if !eligible {
		response := errorResponse(http.StatusForbidden, "license_not_eligible", "This license is not eligible for activation.", input.RequestID)
		return s.storeAndCommit(ctx, tx, prepared, response, now)
	}

	current, exists, err := findActivation(ctx, tx, license.id, prepared.installationHash)
	if err != nil {
		return Response{}, err
	}
	if !exists || current.state == "deactivated" {
		count, err := activeActivationCount(ctx, tx, license.id)
		if err != nil {
			return Response{}, err
		}
		if count >= maximumActivations {
			response := errorResponse(http.StatusConflict, "activation_limit", "This license already has two active Macs.", input.RequestID)
			return s.storeAndCommit(ctx, tx, prepared, response, now)
		}
	}

	status := http.StatusOK
	activationID := current.id
	revision := int64(1)
	if !exists {
		status = http.StatusCreated
		activationID, err = randomValue(s.random, "act_", 16)
		if err != nil {
			return Response{}, fmt.Errorf("generate activation ID: %w", err)
		}
	} else {
		if current.revision == math.MaxInt64 {
			return Response{}, errors.New("activation revision is exhausted")
		}
		revision = current.revision + 1
	}

	activationToken, err := randomValue(s.random, "gea_", 32)
	if err != nil {
		return Response{}, fmt.Errorf("generate activation token: %w", err)
	}
	entitlementID, err := randomValue(s.random, "ent_", 16)
	if err != nil {
		return Response{}, fmt.Errorf("generate entitlement ID: %w", err)
	}
	// Signing stays inside the transaction so the token hash, entitlement revision,
	// and replay body either commit together or remain unchanged after a KMS failure.
	signedEntitlement, err := s.issueEntitlement(ctx, terms, entitlement.Claims{
		LicenseID:      license.id,
		EntitlementID:  entitlementID,
		IssuedAt:       now.Unix(),
		ActivationID:   activationID,
		InstallationID: prepared.installationID,
		Revision:       revision,
	})
	if err != nil {
		return Response{}, err
	}

	tokenHash := sha256.Sum256([]byte(activationToken))
	if exists {
		_, err = tx.ExecContext(ctx, `
			UPDATE activations
			SET token_hash = $1, state = 'active', entitlement_revision = $2,
			    last_refreshed_at = $3, deactivated_at = NULL
			WHERE id = $4`, tokenHash[:], revision, now, activationID)
	} else {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO activations (
			    id, license_id, installation_hash, token_hash, state,
			    entitlement_revision, activated_at, last_refreshed_at
			) VALUES ($1, $2, $3, $4, 'active', $5, $6, $6)`,
			activationID, license.id, prepared.installationHash[:], tokenHash[:], revision, now)
	}
	if err != nil {
		return Response{}, fmt.Errorf("save activation: %w", err)
	}

	body, err := json.Marshal(successBody{ActivationToken: activationToken, Entitlement: signedEntitlement})
	if err != nil {
		return Response{}, fmt.Errorf("encode activation response: %w", err)
	}
	return s.storeAndCommit(ctx, tx, prepared, Response{Status: status, Body: body}, now)
}

type preparedInput struct {
	credentialHash   [sha256.Size]byte
	credentialValid  bool
	installationID   string
	installationHash [sha256.Size]byte
	idempotencyKey   string
	requestHash      [sha256.Size]byte
	clientIP         string
}

func prepare(input Input) (preparedInput, string) {
	normalizedKey, credentialValid := normalizeLicenseKey(input.LicenseKey)
	credentialHash := sha256.Sum256([]byte(normalizedKey))
	if len(input.InstallationID) != 36 {
		return preparedInput{}, "invalid_request"
	}
	installationID, err := uuid.Parse(input.InstallationID)
	if err != nil {
		return preparedInput{}, "invalid_request"
	}
	if len(input.IdempotencyKey) != 36 {
		return preparedInput{}, "invalid_request"
	}
	idempotencyKey, err := uuid.Parse(input.IdempotencyKey)
	if err != nil {
		return preparedInput{}, "invalid_request"
	}
	clientIP, err := netip.ParseAddr(input.ClientIP)
	if err != nil {
		return preparedInput{}, "invalid_request"
	}

	canonicalInstallationID := strings.ToUpper(installationID.String())
	canonicalRequest, err := json.Marshal(struct {
		LicenseKey     string `json:"license_key"`
		InstallationID string `json:"installation_id"`
	}{LicenseKey: normalizedKey, InstallationID: canonicalInstallationID})
	if err != nil {
		return preparedInput{}, "invalid_request"
	}
	return preparedInput{
		credentialHash:   credentialHash,
		credentialValid:  credentialValid,
		installationID:   canonicalInstallationID,
		installationHash: sha256.Sum256([]byte(canonicalInstallationID)),
		idempotencyKey:   idempotencyKey.String(),
		requestHash:      sha256.Sum256(canonicalRequest),
		clientIP:         clientIP.Unmap().String(),
	}, ""
}

func normalizeLicenseKey(value string) (string, bool) {
	if value == "" || len(value) > 128 {
		return value, false
	}
	var normalized strings.Builder
	normalized.Grow(len(value))
	for i := range len(value) {
		character := value[i]
		if character == '-' {
			continue
		}
		if character >= 'a' && character <= 'z' {
			character -= 'a' - 'A'
		}
		normalized.WriteByte(character)
	}
	result := normalized.String()
	if len(result) != 30 || !strings.HasPrefix(result, "GEQ1") {
		return result, false
	}
	for i := 4; i < len(result); i++ {
		if !strings.ContainsRune("0123456789ABCDEFGHJKMNPQRSTVWXYZ", rune(result[i])) {
			return result, false
		}
	}
	return result, true
}

func lockCredential(ctx context.Context, tx *sql.Tx, credentialHash [sha256.Size]byte) error {
	key := int64(binary.BigEndian.Uint64(credentialHash[:8]))
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", key); err != nil {
		return fmt.Errorf("lock activation credential: %w", err)
	}
	return nil
}

func (s *Service) loadIdempotency(ctx context.Context, tx *sql.Tx, input preparedInput, now time.Time) (Response, bool, bool, error) {
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM idempotency_records
		WHERE scope = $1 AND credential_hash = $2 AND idempotency_key = $3 AND expires_at <= $4`,
		idempotencyScope, input.credentialHash[:], input.idempotencyKey, now); err != nil {
		return Response{}, false, false, fmt.Errorf("remove expired activation replay: %w", err)
	}

	var requestHash, ciphertext []byte
	var status int
	err := tx.QueryRowContext(ctx, `
		SELECT request_hash, status_code, response_ciphertext
		FROM idempotency_records
		WHERE scope = $1 AND credential_hash = $2 AND idempotency_key = $3`,
		idempotencyScope, input.credentialHash[:], input.idempotencyKey).Scan(&requestHash, &status, &ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return Response{}, false, false, nil
	}
	if err != nil {
		return Response{}, false, false, fmt.Errorf("load activation replay: %w", err)
	}
	if len(requestHash) != sha256.Size || subtle.ConstantTimeCompare(requestHash, input.requestHash[:]) != 1 {
		return Response{}, false, true, nil
	}
	response, err := s.openResponse(ciphertext, input, status)
	if err != nil {
		return Response{}, false, false, err
	}
	return response, true, false, nil
}

func (s *Service) consumeRateLimits(ctx context.Context, tx *sql.Tx, input preparedInput, now time.Time) (int, error) {
	windowStart := now.Truncate(rateLimitWindow)
	ipHash := hmacSHA256(s.rateLimitHMACKey, input.clientIP)
	licenseAttempts, err := incrementRateLimit(ctx, tx, "license_key", input.credentialHash, windowStart)
	if err != nil {
		return 0, err
	}
	ipAttempts, err := incrementRateLimit(ctx, tx, "ip", ipHash, windowStart)
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM activation_rate_limits WHERE window_start < $1", windowStart.Add(-rateLimitWindow)); err != nil {
		return 0, fmt.Errorf("remove expired activation rate limits: %w", err)
	}
	if licenseAttempts <= licenseKeyAttemptLimit && ipAttempts <= ipAttemptLimit {
		return 0, nil
	}
	seconds := int(math.Ceil(windowStart.Add(rateLimitWindow).Sub(now).Seconds()))
	return max(seconds, 1), nil
}

func incrementRateLimit(ctx context.Context, tx *sql.Tx, kind string, subjectHash [sha256.Size]byte, windowStart time.Time) (int, error) {
	var attempts int
	err := tx.QueryRowContext(ctx, `
		INSERT INTO activation_rate_limits (kind, subject_hash, window_start, attempts)
		VALUES ($1, $2, $3, 1)
		ON CONFLICT (kind, subject_hash, window_start)
		DO UPDATE SET attempts = activation_rate_limits.attempts + 1
		RETURNING attempts`, kind, subjectHash[:], windowStart).Scan(&attempts)
	if err != nil {
		return 0, fmt.Errorf("update activation %s rate limit: %w", kind, err)
	}
	return attempts, nil
}

func hmacSHA256(key []byte, value string) [sha256.Size]byte {
	digest := hmac.New(sha256.New, key)
	digest.Write([]byte(value))
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

type licenseRecord struct {
	id                string
	plan              string
	state             string
	subscriptionState sql.NullString
	billingPeriodEnd  sql.NullTime
	recoveryUntil     sql.NullTime
	terminalAt        sql.NullTime
}

func findLicense(ctx context.Context, tx *sql.Tx, credentialHash [sha256.Size]byte) (licenseRecord, error) {
	var license licenseRecord
	err := tx.QueryRowContext(ctx, `
		SELECT l.id, l.plan, l.state, s.state, s.billing_period_end, s.recovery_until, s.terminal_at
		FROM license_keys AS k
		JOIN licenses AS l ON l.id = k.license_id
		LEFT JOIN subscriptions AS s ON s.license_id = l.id
		WHERE k.secret_hash = $1 AND k.state = 'active'
		FOR UPDATE OF l`, credentialHash[:]).Scan(
		&license.id, &license.plan, &license.state, &license.subscriptionState,
		&license.billingPeriodEnd, &license.recoveryUntil, &license.terminalAt,
	)
	if err != nil {
		return licenseRecord{}, fmt.Errorf("find activation license: %w", err)
	}
	return license, nil
}

type activationRecord struct {
	id       string
	state    string
	revision int64
}

func findActivation(ctx context.Context, tx *sql.Tx, licenseID string, installationHash [sha256.Size]byte) (activationRecord, bool, error) {
	var activation activationRecord
	err := tx.QueryRowContext(ctx, `
		SELECT id, state, entitlement_revision
		FROM activations
		WHERE license_id = $1 AND installation_hash = $2`, licenseID, installationHash[:]).Scan(
		&activation.id, &activation.state, &activation.revision,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return activationRecord{}, false, nil
	}
	if err != nil {
		return activationRecord{}, false, fmt.Errorf("find installation activation: %w", err)
	}
	return activation, true, nil
}

func activeActivationCount(ctx context.Context, tx *sql.Tx, licenseID string) (int, error) {
	// The license row must stay locked until any new activation commits.
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM activations WHERE license_id = $1 AND state = 'active'", licenseID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count active installations: %w", err)
	}
	return count, nil
}

type issuanceTerms struct {
	plan             string
	billingState     entitlement.BillingState
	billingPeriodEnd int64
	recoveryUntil    int64
	refreshAfter     int64
	expiresAt        int64
}

func entitlementTerms(license licenseRecord, now time.Time) (issuanceTerms, bool, error) {
	switch license.plan {
	case "perpetual_v1":
		if license.state != "active" {
			return issuanceTerms{}, false, nil
		}
		return issuanceTerms{plan: license.plan}, true, nil
	case "monthly":
		return monthlyEntitlementTerms(license, now)
	default:
		return issuanceTerms{}, false, fmt.Errorf("unsupported stored license plan %q", license.plan)
	}
}

func monthlyEntitlementTerms(license licenseRecord, now time.Time) (issuanceTerms, bool, error) {
	if !license.subscriptionState.Valid || !license.billingPeriodEnd.Valid || !license.recoveryUntil.Valid {
		return issuanceTerms{}, false, errors.New("monthly license has incomplete subscription state")
	}
	billingState := entitlement.BillingState(license.subscriptionState.String)
	recoveryUntil := license.recoveryUntil.Time
	switch license.state {
	case "active":
	case "refunded", "charged_back":
		if !license.terminalAt.Valid {
			return issuanceTerms{}, false, errors.New("terminal monthly license has no terminal time")
		}
		billingState = entitlement.BillingState(license.state)
		recoveryUntil = license.terminalAt.Time
	case "revoked":
		return issuanceTerms{}, false, nil
	default:
		return issuanceTerms{}, false, fmt.Errorf("unsupported stored license state %q", license.state)
	}

	expiresAt := recoveryUntil.Add(monthlyGracePeriod)
	if !now.Before(expiresAt) {
		return issuanceTerms{}, false, nil
	}
	refreshAfter := now.Add(monthlyRefreshInterval)
	if refreshAfter.After(expiresAt) {
		refreshAfter = expiresAt
	}
	return issuanceTerms{
		plan:             license.plan,
		billingState:     billingState,
		billingPeriodEnd: license.billingPeriodEnd.Time.Unix(),
		recoveryUntil:    recoveryUntil.Unix(),
		refreshAfter:     refreshAfter.Unix(),
		expiresAt:        expiresAt.Unix(),
	}, true, nil
}

func (s *Service) issueEntitlement(ctx context.Context, terms issuanceTerms, claims entitlement.Claims) (string, error) {
	if terms.plan == "perpetual_v1" {
		return s.issuer.IssuePerpetual(ctx, claims)
	}
	return s.issuer.IssueMonthly(ctx, entitlement.MonthlyClaims{
		Claims:                     claims,
		BillingState:               terms.billingState,
		BillingPeriodEnd:           terms.billingPeriodEnd,
		RecoveryUntil:              terms.recoveryUntil,
		RefreshAfter:               terms.refreshAfter,
		ExpiresAt:                  terms.expiresAt,
		SecurityUpdatesAfterExpiry: true,
	})
}

func randomValue(random io.Reader, prefix string, byteCount int) (string, error) {
	value := make([]byte, byteCount)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(value), nil
}

func (s *Service) storeAndCommit(ctx context.Context, tx *sql.Tx, input preparedInput, response Response, now time.Time) (Response, error) {
	plaintext := make([]byte, 4+len(response.Body))
	binary.BigEndian.PutUint32(plaintext, uint32(response.RetryAfterSeconds))
	copy(plaintext[4:], response.Body)
	additionalData := idempotencyAdditionalData(input, response.Status)
	ciphertext, err := s.responses.seal(plaintext, additionalData)
	if err != nil {
		return Response{}, fmt.Errorf("encrypt activation response: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO idempotency_records (
		    scope, credential_hash, idempotency_key, request_hash, status_code,
		    response_ciphertext, created_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		idempotencyScope, input.credentialHash[:], input.idempotencyKey, input.requestHash[:],
		response.Status, ciphertext, now, now.Add(idempotencyLifetime))
	if err != nil {
		return Response{}, fmt.Errorf("store activation replay: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Response{}, fmt.Errorf("commit activation: %w", err)
	}
	return response, nil
}

func (s *Service) openResponse(ciphertext []byte, input preparedInput, status int) (Response, error) {
	plaintext, err := s.responses.open(ciphertext, idempotencyAdditionalData(input, status))
	if err != nil {
		return Response{}, fmt.Errorf("decrypt activation replay: %w", err)
	}
	if len(plaintext) < 4 {
		return Response{}, errors.New("activation replay is truncated")
	}
	retryAfter := binary.BigEndian.Uint32(plaintext)
	if retryAfter > math.MaxInt32 {
		return Response{}, errors.New("activation replay has invalid retry delay")
	}
	return Response{Status: status, Body: append([]byte(nil), plaintext[4:]...), RetryAfterSeconds: int(retryAfter)}, nil
}

func idempotencyAdditionalData(input preparedInput, status int) []byte {
	return []byte(idempotencyScope + "\x00" + hex.EncodeToString(input.credentialHash[:]) + "\x00" +
		input.idempotencyKey + "\x00" + hex.EncodeToString(input.requestHash[:]) + "\x00" + strconv.Itoa(status))
}

func errorResponse(status int, code, message, requestID string) Response {
	body, _ := json.Marshal(errorEnvelope{Error: errorBody{
		Code: code, Message: message, Retryable: status == http.StatusTooManyRequests || status >= 500, RequestID: requestID,
	}})
	return Response{Status: status, Body: body}
}

type successBody struct {
	ActivationToken string `json:"activation_token"`
	Entitlement     string `json:"entitlement"`
}

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
	RequestID string `json:"request_id"`
}
