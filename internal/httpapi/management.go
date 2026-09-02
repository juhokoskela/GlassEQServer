package httpapi

import (
	"context"
	"net/http"

	"github.com/juhokoskela/GlassEQServer/internal/activation"
)

func (a *api) createManagementSession(w http.ResponseWriter, request *http.Request) {
	requestID, err := randomRequestID()
	if err != nil {
		a.logger.ErrorContext(request.Context(), "generate request ID", "error", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.", "")
		return
	}

	var body managementSessionRequest
	if status := decodeJSONRequest(w, request, &body); status != 0 {
		writeError(w, status, "invalid_request", "The management session request is invalid.", requestID)
		return
	}
	clientIP, err := requestClientIP(request)
	if err != nil {
		a.logger.ErrorContext(request.Context(), "resolve management session client IP", "request_id", requestID, "error", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.", requestID)
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), activationTimeout)
	defer cancel()
	response, err := a.activations.CreateManagementSession(ctx, activation.ManagementSessionInput{
		LicenseKey: body.LicenseKey,
		ClientIP:   clientIP,
	})
	if err != nil {
		a.logger.ErrorContext(request.Context(), "create management session", "request_id", requestID, "error", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.", requestID)
		return
	}
	writeServiceResponse(w, response, requestID)
}

func (a *api) listManagedActivations(w http.ResponseWriter, request *http.Request) {
	requestID, err := randomRequestID()
	if err != nil {
		a.logger.ErrorContext(request.Context(), "generate request ID", "error", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.", "")
		return
	}

	token, ok := bearerCredential(request)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "The management token is invalid.", requestID)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), activationTimeout)
	defer cancel()
	response, err := a.activations.ListManagedActivations(ctx, token)
	if err != nil {
		a.logger.ErrorContext(request.Context(), "list managed activations", "request_id", requestID, "error", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.", requestID)
		return
	}
	writeServiceResponse(w, response, requestID)
}

func (a *api) deactivateManaged(w http.ResponseWriter, request *http.Request) {
	requestID, err := randomRequestID()
	if err != nil {
		a.logger.ErrorContext(request.Context(), "generate request ID", "error", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.", "")
		return
	}

	token, ok := bearerCredential(request)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "The management token is invalid.", requestID)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), activationTimeout)
	defer cancel()
	response, err := a.activations.DeactivateManaged(ctx, activation.ManagedDeactivationInput{
		ManagementToken: token,
		ActivationID:    request.PathValue("activation_id"),
	})
	if err != nil {
		a.logger.ErrorContext(request.Context(), "deactivate managed activation", "request_id", requestID, "error", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.", requestID)
		return
	}
	writeServiceResponse(w, response, requestID)
}

func (a *api) rotateLicenseKey(w http.ResponseWriter, request *http.Request) {
	requestID, err := randomRequestID()
	if err != nil {
		a.logger.ErrorContext(request.Context(), "generate request ID", "error", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.", "")
		return
	}

	token, ok := bearerCredential(request)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "The management token is invalid.", requestID)
		return
	}
	idempotencyKeys := request.Header.Values("Idempotency-Key")
	if len(idempotencyKeys) != 1 {
		writeError(w, http.StatusBadRequest, "invalid_request", "The license-key rotation request is invalid.", requestID)
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), activationTimeout)
	defer cancel()
	response, err := a.activations.RotateLicenseKey(ctx, activation.LicenseKeyRotationInput{
		ManagementToken: token,
		IdempotencyKey:  idempotencyKeys[0],
	})
	if err != nil {
		a.logger.ErrorContext(request.Context(), "rotate license key", "request_id", requestID, "error", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.", requestID)
		return
	}
	writeServiceResponse(w, response, requestID)
}

type managementSessionRequest struct {
	LicenseKey string `json:"license_key"`
}
