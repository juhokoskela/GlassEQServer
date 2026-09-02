package activation

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

func TestSQSRecoveryEmailQueueSendsFIFOMessage(t *testing.T) {
	client := &recordingSQSSender{}
	queue, err := NewSQSRecoveryEmailQueue(client, "https://sqs.eu-north-1.amazonaws.com/123456789012/recovery.fifo")
	if err != nil {
		t.Fatalf("create recovery email queue: %v", err)
	}
	message := RecoveryEmail{
		Schema:        1,
		DeliveryID:    "red_delivery",
		Email:         testRecoveryEmail,
		RecoveryToken: "ger_token",
		ExpiresAt:     1_800_001_800,
	}

	if err := queue.SendRecoveryEmail(context.Background(), message); err != nil {
		t.Fatalf("send recovery email: %v", err)
	}
	input := client.input
	if input == nil {
		t.Fatal("SQS was not called")
	}
	if value(input.QueueUrl) != "https://sqs.eu-north-1.amazonaws.com/123456789012/recovery.fifo" {
		t.Errorf("queue URL = %q", value(input.QueueUrl))
	}
	if value(input.MessageDeduplicationId) != message.DeliveryID || value(input.MessageGroupId) != message.DeliveryID {
		t.Errorf("FIFO identifiers = (%q, %q)", value(input.MessageDeduplicationId), value(input.MessageGroupId))
	}
	var got RecoveryEmail
	if err := json.Unmarshal([]byte(value(input.MessageBody)), &got); err != nil {
		t.Fatalf("decode message body: %v", err)
	}
	if got != message {
		t.Errorf("message body = %+v, want %+v", got, message)
	}
}

func TestSQSRecoveryEmailQueueRejectsInvalidConfiguration(t *testing.T) {
	client := &recordingSQSSender{}
	for _, queueURL := range []string{
		"http://sqs.eu-north-1.amazonaws.com/123/recovery.fifo",
		"https://sqs.eu-north-1.amazonaws.com/123/recovery",
		"https://user@example.com/recovery.fifo",
		"https://sqs.eu-north-1.amazonaws.com/123/recovery.fifo?secret=value",
	} {
		if _, err := NewSQSRecoveryEmailQueue(client, queueURL); err == nil {
			t.Errorf("accepted queue URL %q", queueURL)
		}
	}
	if _, err := NewSQSRecoveryEmailQueue(nil, "https://sqs.eu-north-1.amazonaws.com/123/recovery.fifo"); err == nil {
		t.Error("accepted nil SQS client")
	}
}

func TestSQSRecoveryEmailQueueReturnsSendError(t *testing.T) {
	want := errors.New("SQS unavailable")
	queue, err := NewSQSRecoveryEmailQueue(
		&recordingSQSSender{err: want},
		"https://sqs.eu-north-1.amazonaws.com/123456789012/recovery.fifo",
	)
	if err != nil {
		t.Fatalf("create recovery email queue: %v", err)
	}
	if err := queue.SendRecoveryEmail(context.Background(), RecoveryEmail{DeliveryID: "red_delivery"}); !errors.Is(err, want) {
		t.Errorf("send error = %v, want %v", err, want)
	}
}

type recordingSQSSender struct {
	input *sqs.SendMessageInput
	err   error
}

func (s *recordingSQSSender) SendMessage(_ context.Context, input *sqs.SendMessageInput, _ ...func(*sqs.Options)) (*sqs.SendMessageOutput, error) {
	s.input = input
	return &sqs.SendMessageOutput{}, s.err
}

func value(pointer *string) string {
	if pointer == nil {
		return ""
	}
	return *pointer
}
