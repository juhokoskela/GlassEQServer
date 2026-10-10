package httpapi

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stripe/stripe-go/v86/webhook"
)

type recordingBillingProcessor struct {
	body  []byte
	calls int
	err   error
}

func (p *recordingBillingProcessor) Process(_ context.Context, body []byte) error {
	p.calls++
	p.body = append([]byte(nil), body...)
	return p.err
}

func TestStripeWebhookVerifiesSignedBytes(t *testing.T) {
	payload := []byte(`{"id":"evt_test","object":"event"}`)
	signed := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{
		Payload: payload, Secret: "whsec_test", Timestamp: time.Now(),
	})
	processor := &recordingBillingProcessor{}
	handler := NewWithWebhook(&fakeDatabase{}, nil, processor, "whsec_test", discardLogger())
	request := httptest.NewRequest(http.MethodPost, "/v1/stripe/webhook", bytes.NewReader(payload))
	request.Header.Set("Stripe-Signature", signed.Header)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || processor.calls != 1 || !bytes.Equal(processor.body, payload) {
		t.Fatalf("signed webhook: status=%d calls=%d body=%q", response.Code, processor.calls, processor.body)
	}

	processor.err = errors.New("database unavailable")
	response = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/v1/stripe/webhook", bytes.NewReader(payload))
	request.Header.Set("Stripe-Signature", signed.Header)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("processing failure status=%d", response.Code)
	}

	processor.calls = 0
	request = httptest.NewRequest(http.MethodPost, "/v1/stripe/webhook", bytes.NewReader([]byte(`{"id":"forged"}`)))
	request.Header.Set("Stripe-Signature", signed.Header)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || processor.calls != 0 {
		t.Fatalf("forged webhook: status=%d calls=%d", response.Code, processor.calls)
	}
}

func TestStripeWebhookRejectsOversizedBody(t *testing.T) {
	processor := &recordingBillingProcessor{}
	handler := NewWithWebhook(&fakeDatabase{}, nil, processor, "whsec_test", discardLogger())
	request := httptest.NewRequest(http.MethodPost, "/v1/stripe/webhook", bytes.NewReader(bytes.Repeat([]byte{'x'}, maximumWebhookBytes+1)))
	request.Header.Set("Stripe-Signature", "t=1,v1=invalid")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge || processor.calls != 0 {
		t.Fatalf("oversized webhook: status=%d calls=%d", response.Code, processor.calls)
	}
}
