package activation

import (
	"bytes"
	"testing"
)

func TestSecretCipherRoundTripBindsAdditionalData(t *testing.T) {
	cipher, err := newSecretCipher(make([]byte, 32), bytes.NewReader(make([]byte, 12)))
	if err != nil {
		t.Fatalf("create response cipher: %v", err)
	}
	ciphertext, err := cipher.seal([]byte("response"), []byte("request-a"))
	if err != nil {
		t.Fatalf("seal response: %v", err)
	}
	plaintext, err := cipher.open(ciphertext, []byte("request-a"))
	if err != nil {
		t.Fatalf("open response: %v", err)
	}
	if string(plaintext) != "response" {
		t.Errorf("plaintext = %q", plaintext)
	}
	if _, err := cipher.open(ciphertext, []byte("request-b")); err == nil {
		t.Fatal("open with different additional data succeeded")
	}
}

func TestSecretCipherRejectsInvalidConfigurationAndInput(t *testing.T) {
	if _, err := newSecretCipher(make([]byte, 31), bytes.NewReader(nil)); err == nil {
		t.Fatal("create response cipher with short key succeeded")
	}
	if _, err := newSecretCipher(make([]byte, 32), nil); err == nil {
		t.Fatal("create response cipher without randomness succeeded")
	}
	cipher, err := newSecretCipher(make([]byte, 32), bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("create response cipher: %v", err)
	}
	if _, err := cipher.seal([]byte("response"), nil); err == nil {
		t.Fatal("seal without enough randomness succeeded")
	}
	if _, err := cipher.open(make([]byte, 11), nil); err == nil {
		t.Fatal("open truncated response succeeded")
	} else if err.Error() != "ciphertext is truncated" {
		t.Errorf("truncated ciphertext error = %q", err)
	}
}
