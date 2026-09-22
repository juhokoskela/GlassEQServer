package billing

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

type eventQueue interface {
	ReceiveMessage(context.Context, *sqs.ReceiveMessageInput, ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error)
	DeleteMessage(context.Context, *sqs.DeleteMessageInput, ...func(*sqs.Options)) (*sqs.DeleteMessageOutput, error)
}

type eventHandler interface {
	Process(context.Context, []byte) error
}

// RunEventConsumer processes one message at a time. Its owner cancels ctx and
// waits for return at shutdown; visibility exceeds the entire processing deadline.
func RunEventConsumer(ctx context.Context, queue eventQueue, queueURL string, handler eventHandler, logger *slog.Logger) {
	for ctx.Err() == nil {
		if err := consumeEvent(ctx, queue, queueURL, handler); err != nil && ctx.Err() == nil {
			// Provider/database errors can include payload fragments. The worker logs
			// only bounded classifications, never a body, credential, or raw error.
			code := "temporarily_unavailable"
			switch {
			case errors.Is(err, ErrInvalidBillingEvent):
				code = "invalid_event"
			case errors.Is(err, ErrUnsupportedPurchase):
				code = "unsupported_purchase"
			case errors.Is(err, ErrInvalidCheckoutSession), errors.Is(err, ErrInvalidSubscription):
				code = "invalid_purchase"
			case errors.Is(err, errBillingSnapshotChanged):
				code = "snapshot_changed"
			}
			logger.WarnContext(ctx, "billing event not acknowledged", "code", code)
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
		}
	}
}

func consumeEvent(ctx context.Context, queue eventQueue, queueURL string, handler eventHandler) error {
	receiveCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	response, err := queue.ReceiveMessage(receiveCtx, &sqs.ReceiveMessageInput{
		QueueUrl: aws.String(queueURL), MaxNumberOfMessages: 1, WaitTimeSeconds: 20, VisibilityTimeout: 120,
	})
	cancel()
	if err != nil {
		return err
	}
	if response == nil {
		return errors.New("empty billing queue response")
	}
	if len(response.Messages) == 0 {
		return nil
	}
	message := response.Messages[0]
	if message.Body == nil || message.ReceiptHandle == nil || *message.ReceiptHandle == "" {
		return ErrInvalidBillingEvent
	}
	processCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	err = handler.Process(processCtx, []byte(*message.Body))
	cancel()
	if err != nil {
		return err
	}
	deleteCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err = queue.DeleteMessage(deleteCtx, &sqs.DeleteMessageInput{QueueUrl: aws.String(queueURL), ReceiptHandle: message.ReceiptHandle})
	return err
}
