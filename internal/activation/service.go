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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"strings"
	"time"
	"uuid"

	"github.com/juhokoskela/GlassEQServer/internal/entitlement"
)

const (
	activationIdempotencyScope = "activation"
	idempotencyLifetime        = 24 * time.Hour
	rateLimitWindow            = time.Hour
	licenseKeyAttemptLimit     = 20
	ipAttemptLimit             = 100
	maximumActivations         = 2
	monthlyRefreshInterval     = 7 * 24 * time.Hour
	monthlyGracePeriod         = 7 * 24 * time.Hour
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
	ClientIP       netip.Addr
}

type Response struct {
	Status            int
	Body              []byte
	ErrorCode         string
	ErrorMessage      string
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
	prepared, invalidCode := prepare(input)
	if invalidCode != "" {
		return responseError(http.StatusBadRequest, invalidCode, "The activation request is invalid."), nil
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	idempotency := prepared.idempotency()
	replayed, found, conflict, err := s.loadIdempotency(ctx, s.database, idempotency, now)
	if err != nil {
		return Response{}, err
	}
	if conflict {
		return responseError(http.StatusConflict, "idempotency_conflict", "The idempotency key was already used for another request."), nil
	}
	if found {
		return replayed, nil
	}

	retryAfter, err := s.consumeRateLimits(ctx, prepared.credentialHash, prepared.clientIP, now)
	if err != nil {
		return Response{}, err
	}
	if retryAfter > 0 {
		response := responseError(http.StatusTooManyRequests, "rate_limited", "Too many activation attempts. Try again later.")
		response.RetryAfterSeconds = retryAfter
		return response, nil
	}
	if !prepared.credentialValid {
		return responseError(http.StatusUnauthorized, "invalid_credentials", "The license key is invalid."), nil
	}

	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return Response{}, fmt.Errorf("begin activation: %w", err)
	}
	defer tx.Rollback()

	locked, err := tryLockCredential(ctx, tx, prepared.credentialHash)
	if err != nil {
		return Response{}, err
	}
	if !locked {
		return databaseBusyResponse(), nil
	}
	replayed, found, conflict, err = s.loadIdempotency(ctx, tx, idempotency, now)
	if err != nil {
		return Response{}, err
	}
	if conflict {
		return responseError(http.StatusConflict, "idempotency_conflict", "The idempotency key was already used for another request."), nil
	}
	if found {
		return replayed, nil
	}

	license, found, err := findLicense(ctx, tx, prepared.credentialHash)
	if err != nil {
		return Response{}, err
	}
	if !found {
		return responseError(http.StatusUnauthorized, "invalid_credentials", "The license key is invalid."), nil
	}
	terms, eligible, err := entitlementTerms(license, now)
	if err != nil {
		return Response{}, err
	}
	if !eligible {
		return responseError(http.StatusForbidden, "license_not_eligible", "This license is not eligible for activation."), nil
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
			return responseError(http.StatusConflict, "activation_limit", "This license already has two active Macs."), nil
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
	return s.storeAndCommit(ctx, tx, idempotency, Response{Status: status, Body: body}, now)
}

type preparedInput struct {
	credentialHash   [sha256.Size]byte
	credentialValid  bool
	installationID   string
	installationHash [sha256.Size]byte
	idempotencyKey   string
	clientIP         netip.Addr
}

func (p preparedInput) idempotency() idempotencyRequest {
	return idempotencyRequest{
		scope:          activationIdempotencyScope,
		credentialHash: p.credentialHash,
		key:            p.idempotencyKey,
		requestHash:    p.installationHash,
	}
}

func prepare(input Input) (preparedInput, string) {
	normalizedKey, credentialValid := normalizeLicenseKey(input.LicenseKey)
	credentialHash := sha256.Sum256([]byte(normalizedKey))
	installationID, installationHash, valid := canonicalInstallation(input.InstallationID)
	if !valid {
		return preparedInput{}, "invalid_request"
	}
	idempotencyKey, valid := canonicalIdempotencyKey(input.IdempotencyKey)
	if !valid {
		return preparedInput{}, "invalid_request"
	}
	if !input.ClientIP.IsValid() {
		return preparedInput{}, "invalid_request"
	}

	return preparedInput{
		credentialHash:   credentialHash,
		credentialValid:  credentialValid,
		installationID:   installationID,
		installationHash: installationHash,
		idempotencyKey:   idempotencyKey,
		clientIP:         input.ClientIP.Unmap(),
	}, ""
}

func canonicalIdempotencyKey(value string) (string, bool) {
	if len(value) != 36 {
		return "", false
	}
	identifier, err := uuid.Parse(value)
	if err != nil {
		return "", false
	}
	return identifier.String(), true
}

func canonicalInstallation(value string) (string, [sha256.Size]byte, bool) {
	if len(value) != 36 {
		return "", [sha256.Size]byte{}, false
	}
	identifier, err := uuid.Parse(value)
	if err != nil {
		return "", [sha256.Size]byte{}, false
	}
	canonical := strings.ToUpper(identifier.String())
	return canonical, sha256.Sum256([]byte(canonical)), true
}

func tryLockCredential(ctx context.Context, tx *sql.Tx, credentialHash [sha256.Size]byte) (bool, error) {
	key := int64(binary.BigEndian.Uint64(credentialHash[:8]))
	var locked bool
	if err := tx.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock($1)", key).Scan(&locked); err != nil {
		return false, fmt.Errorf("lock activation credential: %w", err)
	}
	return locked, nil
}

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type idempotencyRequest struct {
	scope          string
	credentialHash [sha256.Size]byte
	key            string
	requestHash    [sha256.Size]byte
}

func (s *Service) loadIdempotency(ctx context.Context, database rowQuerier, input idempotencyRequest, now time.Time) (Response, bool, bool, error) {
	var requestHash, ciphertext []byte
	var status int
	err := database.QueryRowContext(ctx, `
		SELECT request_hash, status_code, response_ciphertext
		FROM idempotency_records
		WHERE scope = $1 AND credential_hash = $2 AND idempotency_key = $3
		  AND expires_at > $4 AND status_code IN (200, 201)`,
		input.scope, input.credentialHash[:], input.key, now).Scan(&requestHash, &status, &ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return Response{}, false, false, nil
	}
	if err != nil {
		return Response{}, false, false, fmt.Errorf("load idempotency replay: %w", err)
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

func (s *Service) consumeRateLimits(ctx context.Context, credentialHash [sha256.Size]byte, clientIP netip.Addr, now time.Time) (int, error) {
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin credential rate limit: %w", err)
	}
	defer tx.Rollback()

	windowStart := now.Truncate(rateLimitWindow)
	ipHash := hmacSHA256(s.rateLimitHMACKey, clientIP.String())
	ipAttempts, err := incrementRateLimit(ctx, tx, "ip", ipHash, windowStart)
	if err != nil {
		return 0, err
	}
	limited := ipAttempts > ipAttemptLimit
	if !limited {
		licenseAttempts, err := incrementRateLimit(ctx, tx, "license_key", credentialHash, windowStart)
		if err != nil {
			return 0, err
		}
		limited = licenseAttempts > licenseKeyAttemptLimit
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit credential rate limit: %w", err)
	}
	if !limited {
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
		return 0, fmt.Errorf("update credential %s rate limit: %w", kind, err)
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

func findLicense(ctx context.Context, tx *sql.Tx, credentialHash [sha256.Size]byte) (licenseRecord, bool, error) {
	var license licenseRecord
	err := tx.QueryRowContext(ctx, `
		SELECT l.id, l.plan, l.state, s.state, s.billing_period_end, s.recovery_until, s.terminal_at
		FROM license_keys AS k
		JOIN licenses AS l ON l.id = k.license_id
		LEFT JOIN subscriptions AS s ON s.license_id = l.id
		WHERE k.secret_hash = $1 AND k.state = 'active'
		FOR NO KEY UPDATE OF l`, credentialHash[:]).Scan(
		&license.id, &license.plan, &license.state, &license.subscriptionState,
		&license.billingPeriodEnd, &license.recoveryUntil, &license.terminalAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return licenseRecord{}, false, nil
	}
	if err != nil {
		return licenseRecord{}, false, fmt.Errorf("find activation license: %w", err)
	}
	return license, true, nil
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

func randomValueHash(value, prefix string, byteCount int) ([sha256.Size]byte, bool) {
	if !randomValueValid(value, prefix, byteCount) {
		return [sha256.Size]byte{}, false
	}
	return sha256.Sum256([]byte(value)), true
}

func randomValueValid(value, prefix string, byteCount int) bool {
	encodedLength := base64.RawURLEncoding.EncodedLen(byteCount)
	if len(value) != len(prefix)+encodedLength || !strings.HasPrefix(value, prefix) {
		return false
	}
	encoded := value[len(prefix):]
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	return err == nil && len(decoded) == byteCount
}

func (s *Service) storeAndCommit(ctx context.Context, tx *sql.Tx, input idempotencyRequest, response Response, now time.Time) (Response, error) {
	additionalData := idempotencyAdditionalData(input, response.Status)
	ciphertext, err := s.responses.seal(response.Body, additionalData)
	if err != nil {
		return Response{}, fmt.Errorf("encrypt idempotency response: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		INSERT INTO idempotency_records (
		    scope, credential_hash, idempotency_key, request_hash, status_code,
		    response_ciphertext, created_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (scope, credential_hash, idempotency_key)
		DO UPDATE SET request_hash = EXCLUDED.request_hash,
		              status_code = EXCLUDED.status_code,
		              response_ciphertext = EXCLUDED.response_ciphertext,
		              created_at = EXCLUDED.created_at,
		              expires_at = EXCLUDED.expires_at
		WHERE idempotency_records.expires_at <= EXCLUDED.created_at
		   OR idempotency_records.status_code NOT IN (200, 201)`,
		input.scope, input.credentialHash[:], input.key, input.requestHash[:],
		response.Status, ciphertext, now, now.Add(idempotencyLifetime))
	if err != nil {
		return Response{}, fmt.Errorf("store idempotency replay: %w", err)
	}
	stored, err := result.RowsAffected()
	if err != nil {
		return Response{}, fmt.Errorf("read idempotency replay result: %w", err)
	}
	if stored != 1 {
		return Response{}, errors.New("idempotency replay changed while its resource was locked")
	}
	if err := tx.Commit(); err != nil {
		return Response{}, fmt.Errorf("commit idempotent state change: %w", err)
	}
	return response, nil
}

func (s *Service) openResponse(ciphertext []byte, input idempotencyRequest, status int) (Response, error) {
	body, err := s.responses.open(ciphertext, idempotencyAdditionalData(input, status))
	if err != nil {
		return Response{}, fmt.Errorf("decrypt idempotency replay: %w", err)
	}
	return Response{Status: status, Body: body}, nil
}

func idempotencyAdditionalData(input idempotencyRequest, status int) []byte {
	additionalData := make([]byte, 0, len(input.scope)+1+sha256.Size+36+sha256.Size+2)
	additionalData = append(additionalData, input.scope...)
	additionalData = append(additionalData, 0)
	additionalData = append(additionalData, input.credentialHash[:]...)
	additionalData = append(additionalData, input.key...)
	additionalData = append(additionalData, input.requestHash[:]...)
	return binary.BigEndian.AppendUint16(additionalData, uint16(status))
}

func responseError(status int, code, message string) Response {
	return Response{Status: status, ErrorCode: code, ErrorMessage: message}
}

func databaseBusyResponse() Response {
	response := responseError(http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.")
	response.RetryAfterSeconds = 1
	return response
}

func databaseLockUnavailable(err error) bool {
	var databaseError interface{ SQLState() string }
	return errors.As(err, &databaseError) && databaseError.SQLState() == "55P03"
}

type successBody struct {
	ActivationToken string `json:"activation_token"`
	Entitlement     string `json:"entitlement"`
}
