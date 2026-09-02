package httpapi

import (
	"context"
	"net/http"
)

func (a *api) createRecoverySession(w http.ResponseWriter, request *http.Request) {
	requestID, err := randomRequestID()
	if err != nil {
		a.logger.ErrorContext(request.Context(), "generate request ID", "error", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.", "")
		return
	}

	var body recoverySessionRequest
	if status := decodeJSONRequest(w, request, &body); status != 0 {
		writeError(w, status, "invalid_request", "The recovery session request is invalid.", requestID)
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), activationTimeout)
	defer cancel()
	response, err := a.activations.ExchangeRecoveryToken(ctx, body.RecoveryToken)
	if err != nil {
		a.logger.ErrorContext(request.Context(), "create recovery session", "request_id", requestID, "error", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.", requestID)
		return
	}
	writeServiceResponse(w, response, requestID)
}

type recoverySessionRequest struct {
	RecoveryToken string `json:"recovery_token"`
}
