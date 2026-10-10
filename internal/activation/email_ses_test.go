package activation

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sesv2"
)

type recordingSESClient struct{ input *sesv2.SendEmailInput }

func (c *recordingSESClient) SendEmail(_ context.Context, input *sesv2.SendEmailInput, _ ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error) {
	c.input = input
	return &sesv2.SendEmailOutput{}, nil
}

func TestSESEmailSenderDeliversGlassEQCredentials(t *testing.T) {
	client := &recordingSESClient{}
	sender, err := NewSESEmailSender(client, "licenses@glasseq.app")
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.SendLicenseEmail(context.Background(), LicenseEmail{
		Email: "buyer@example.com", LicenseKey: "GEQ1-TEST-KEY",
	}); err != nil {
		t.Fatal(err)
	}
	if client.input == nil || *client.input.FromEmailAddress != "licenses@glasseq.app" ||
		len(client.input.Destination.ToAddresses) != 1 || client.input.Destination.ToAddresses[0] != "buyer@example.com" ||
		!strings.Contains(*client.input.Content.Simple.Body.Text.Data, "GEQ1-TEST-KEY") {
		t.Fatal("license email did not target the purchase inbox with the key")
	}
	if err := sender.SendRecoveryEmail(context.Background(), RecoveryEmail{
		Email: "buyer@example.com", RecoveryToken: "ger_test", ExpiresAt: 1_800_001_800,
	}); err != nil {
		t.Fatal(err)
	}
	body := *client.input.Content.Simple.Body.Text.Data
	if !strings.Contains(body, "ger_test") || strings.Contains(body, "GEQ1-TEST-KEY") {
		t.Fatalf("recovery email content = %q", body)
	}
}
