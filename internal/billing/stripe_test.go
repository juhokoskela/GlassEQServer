package billing

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestStripeClientDerivesEnvironmentFromSecretKey(t *testing.T) {
	for _, test := range []struct {
		key  string
		live bool
	}{
		{key: "sk_test_secret"},
		{key: "rk_test_secret"},
		{key: "sk_live_secret", live: true},
		{key: "rk_live_secret", live: true},
	} {
		client, err := NewCheckoutClient(test.key)
		if err != nil {
			t.Fatal(err)
		}
		if client.LiveMode() != test.live {
			t.Errorf("key prefix %q produced live mode %t", test.key[:7], client.LiveMode())
		}
	}
}

func TestStripeResponseLimit(t *testing.T) {
	transport := responseLimitTransport{next: stripeRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(strings.Repeat("a", stripeResponseLimit+1)))}, nil
	})}
	response, err := transport.RoundTrip(&http.Request{})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, err = io.ReadAll(response.Body)
	var limitError *http.MaxBytesError
	if !errors.As(err, &limitError) {
		t.Fatalf("read error = %v, want MaxBytesError", err)
	}
}

type stripeRoundTripper func(*http.Request) (*http.Response, error)

func (f stripeRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
