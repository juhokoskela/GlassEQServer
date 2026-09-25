package activation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

type sesEmailClient interface {
	SendEmail(context.Context, *sesv2.SendEmailInput, ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error)
}

type SESEmailSender struct {
	client sesEmailClient
	from   string
}

func NewSESEmailSender(client sesEmailClient, from string) (*SESEmailSender, error) {
	if client == nil || from == "" {
		return nil, errors.New("SES client and sender address are required")
	}
	return &SESEmailSender{client: client, from: from}, nil
}

func (s *SESEmailSender) SendRecoveryEmail(ctx context.Context, message RecoveryEmail) error {
	if message.Email == "" || message.RecoveryToken == "" {
		return errors.New("recovery email address and token are required")
	}
	body := fmt.Sprintf("Your GlassEQ recovery token:\n\n%s\n\nIt expires at %s. If you did not request this, you can ignore this email.\n",
		message.RecoveryToken, time.Unix(message.ExpiresAt, 0).UTC().Format("2 January 2006 at 15:04 UTC"))
	return s.send(ctx, message.Email, "GlassEQ license recovery", body)
}

func (s *SESEmailSender) SendLicenseEmail(ctx context.Context, message LicenseEmail) error {
	if message.Email == "" || message.LicenseKey == "" {
		return errors.New("license email address and key are required")
	}
	body := fmt.Sprintf("Your GlassEQ license key:\n\n%s\n\nKeep this email. You will need the key to activate GlassEQ.\n", message.LicenseKey)
	return s.send(ctx, message.Email, "Your GlassEQ license key", body)
}

func (s *SESEmailSender) send(ctx context.Context, to, subject, body string) error {
	_, err := s.client.SendEmail(ctx, &sesv2.SendEmailInput{
		FromEmailAddress: aws.String(s.from),
		Destination:      &types.Destination{ToAddresses: []string{to}},
		Content: &types.EmailContent{Simple: &types.Message{
			Subject: &types.Content{Data: aws.String(subject), Charset: aws.String("UTF-8")},
			Body:    &types.Body{Text: &types.Content{Data: aws.String(body), Charset: aws.String("UTF-8")}},
		}},
	})
	if err != nil {
		return fmt.Errorf("send SES email: %w", err)
	}
	return nil
}
