package activation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

type sqsMessageSender interface {
	SendMessage(context.Context, *sqs.SendMessageInput, ...func(*sqs.Options)) (*sqs.SendMessageOutput, error)
}

type SQSRecoveryEmailQueue struct {
	client   sqsMessageSender
	queueURL string
}

func NewSQSRecoveryEmailQueue(client sqsMessageSender, queueURL string) (*SQSRecoveryEmailQueue, error) {
	if client == nil {
		return nil, errors.New("SQS client is required")
	}
	parsed, err := url.Parse(queueURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !strings.HasSuffix(parsed.Path, ".fifo") {
		return nil, errors.New("recovery queue URL must use HTTPS and end in .fifo")
	}
	return &SQSRecoveryEmailQueue{client: client, queueURL: queueURL}, nil
}

func (q *SQSRecoveryEmailQueue) SendRecoveryEmail(ctx context.Context, message RecoveryEmail) error {
	body, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("encode recovery email: %w", err)
	}
	_, err = q.client.SendMessage(ctx, &sqs.SendMessageInput{
		QueueUrl:               aws.String(q.queueURL),
		MessageBody:            aws.String(string(body)),
		MessageDeduplicationId: aws.String(message.DeliveryID),
		MessageGroupId:         aws.String(message.DeliveryID),
	})
	if err != nil {
		return fmt.Errorf("send SQS message: %w", err)
	}
	return nil
}
