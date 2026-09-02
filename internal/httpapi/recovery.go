package httpapi

import (
	"context"
	"net/http"

	"github.com/juhokoskela/GlassEQServer/internal/activation"
)

func (a *api) createRecoverySession(w http.ResponseWriter, request *http.Request) {
	requestID, err := randomRequestID()
	if err != nil {
		a.logger.ErrorContext(request.Context(), "generate request ID", "error", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.", "")
		return
	}

	token, ok := bearerCredential(request)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "The recovery token is invalid.", requestID)
		return
	}
	idempotencyKey, ok := singleHeader(request, "Idempotency-Key")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_request", "The recovery session request is invalid.", requestID)
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), activationTimeout)
	defer cancel()
	response, err := a.activations.ExchangeRecoveryToken(ctx, activation.RecoverySessionInput{
		RecoveryToken:  token,
		IdempotencyKey: idempotencyKey,
	})
	if err != nil {
		a.logger.ErrorContext(request.Context(), "create recovery session", "request_id", requestID, "error", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "The service is temporarily unavailable.", requestID)
		return
	}
	writeServiceResponse(w, response, requestID)
}
