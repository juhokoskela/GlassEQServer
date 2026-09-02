package activation

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
)

type responseCipher struct {
	aead   cipher.AEAD
	random io.Reader
}

func newResponseCipher(key []byte, random io.Reader) (*responseCipher, error) {
	if len(key) != 32 {
		return nil, errors.New("idempotency key must contain 32 bytes")
	}
	if random == nil {
		return nil, errors.New("random source is required")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &responseCipher{aead: aead, random: random}, nil
}

func (c *responseCipher) seal(plaintext, additionalData []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(c.random, nonce); err != nil {
		return nil, err
	}
	return c.aead.Seal(nonce, nonce, plaintext, additionalData), nil
}

func (c *responseCipher) open(ciphertext, additionalData []byte) ([]byte, error) {
	nonceSize := c.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("idempotency response is truncated")
	}
	return c.aead.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], additionalData)
}
