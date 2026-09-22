package billing

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

func TestBillingQueueAcknowledgesOnlySuccessfulProcessing(t *testing.T) {
	for _, processErr := range []error{nil, ErrInvalidBillingEvent, ErrUnsupportedPurchase, errors.New("database failed")} {
		queue := &fakeEventQueue{}
		handler := eventHandlerFunc(func(ctx context.Context, body []byte) error {
			if string(body) != "body" {
				t.Fatal("message body changed")
			}
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("missing processing deadline")
			}
			if queue.deletes != 0 {
				t.Fatal("acknowledged before processing")
			}
			return processErr
		})
		err := consumeEvent(context.Background(), queue, "queue", handler)
		if !errors.Is(err, processErr) {
			t.Fatalf("error = %v, want %v", err, processErr)
		}
		wantDeletes := 0
		if processErr == nil {
			wantDeletes = 1
		}
		if queue.deletes != wantDeletes {
			t.Fatalf("deletes=%d, want %d", queue.deletes, wantDeletes)
		}
		if queue.receive.MaxNumberOfMessages != 1 || queue.receive.VisibilityTimeout <= 65 {
			t.Fatal("unsafe queue batch or visibility")
		}
	}
}

func TestBillingQueueLostAcknowledgementReprocesses(t *testing.T) {
	queue := &fakeEventQueue{deleteErr: errors.New("lost acknowledgement")}
	calls := 0
	handler := eventHandlerFunc(func(context.Context, []byte) error { calls++; return nil })
	if err := consumeEvent(context.Background(), queue, "queue", handler); err == nil {
		t.Fatal("lost acknowledgement hidden")
	}
	queue.deleteErr = nil
	if err := consumeEvent(context.Background(), queue, "queue", handler); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("process calls=%d", calls)
	}
}

func TestBillingQueueShutdownCancelsReceive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	queue := &fakeEventQueue{receiving: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunEventConsumer(ctx, queue, "queue", eventHandlerFunc(func(context.Context, []byte) error {
			return errors.New("unexpected processing")
		}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	select {
	case <-queue.receiving:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("worker did not receive")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not stop")
	}
}

type eventHandlerFunc func(context.Context, []byte) error

func (f eventHandlerFunc) Process(ctx context.Context, body []byte) error { return f(ctx, body) }

type fakeEventQueue struct {
	receive   *sqs.ReceiveMessageInput
	deletes   int
	deleteErr error
	receiving chan struct{}
}

func (q *fakeEventQueue) ReceiveMessage(ctx context.Context, input *sqs.ReceiveMessageInput, _ ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
	q.receive = input
	if q.receiving != nil {
		close(q.receiving)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return &sqs.ReceiveMessageOutput{Messages: []types.Message{{Body: aws.String("body"), ReceiptHandle: aws.String("receipt")}}}, nil
}

func (q *fakeEventQueue) DeleteMessage(_ context.Context, input *sqs.DeleteMessageInput, _ ...func(*sqs.Options)) (*sqs.DeleteMessageOutput, error) {
	if aws.ToString(input.ReceiptHandle) != "receipt" {
		return nil, errors.New("wrong receipt")
	}
	q.deletes++
	return &sqs.DeleteMessageOutput{}, q.deleteErr
}
