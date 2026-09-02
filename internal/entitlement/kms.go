package entitlement

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type kmsClient interface {
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}

type KMSSigner struct {
	client kmsClient
	keyARN string
}

const maximumRawKMSMessageSize = 4 * 1024

func LoadKMSSigner(ctx context.Context, client kmsClient, keyID string) (*KMSSigner, ed25519.PublicKey, error) {
	if client == nil {
		return nil, nil, errors.New("KMS client is required")
	}
	if keyID == "" {
		return nil, nil, errors.New("KMS key ID is required")
	}
	output, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &keyID})
	if err != nil {
		return nil, nil, fmt.Errorf("get entitlement public key: %w", err)
	}
	if output == nil {
		return nil, nil, errors.New("get entitlement public key: KMS returned no result")
	}
	if output.KeyId == nil || *output.KeyId == "" {
		return nil, nil, errors.New("get entitlement public key: KMS returned no key ARN")
	}
	if output.KeySpec != types.KeySpecEccNistEdwards25519 || output.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, nil, errors.New("entitlement KMS key must use ECC_NIST_EDWARDS25519 with SIGN_VERIFY")
	}
	if !slices.Contains(output.SigningAlgorithms, types.SigningAlgorithmSpecEd25519Sha512) {
		return nil, nil, errors.New("entitlement KMS key does not support ED25519_SHA_512")
	}

	parsed, err := x509.ParsePKIXPublicKey(output.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("parse entitlement public key: %w", err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, nil, errors.New("entitlement KMS public key is not Ed25519")
	}
	return &KMSSigner{client: client, keyARN: *output.KeyId}, publicKey, nil
}

func (s *KMSSigner) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if len(message) > maximumRawKMSMessageSize {
		return nil, errors.New("KMS sign: raw message exceeds 4 KiB")
	}
	output, err := s.client.Sign(ctx, &kms.SignInput{
		KeyId:            &s.keyARN,
		Message:          message,
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS sign: %w", err)
	}
	if output == nil {
		return nil, errors.New("KMS sign: KMS returned no result")
	}
	if output.KeyId == nil || *output.KeyId != s.keyARN {
		return nil, errors.New("KMS sign: response key does not match the pinned key ARN")
	}
	if len(output.Signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("KMS sign: returned %d-byte signature", len(output.Signature))
	}
	return output.Signature, nil
}
