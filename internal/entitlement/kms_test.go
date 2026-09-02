package entitlement

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const (
	testKMSAlias  = "alias/glasseq-entitlement"
	testKMSKeyARN = "arn:aws:kms:eu-north-1:123456789012:key/11111111-2222-3333-4444-555555555555"
)

func TestKMSSignerValidatesKeyAndSignsRawMessages(t *testing.T) {
	client, signer, publicKey := newFakeKMSSigner(t)
	if got := *client.publicKeyInput.KeyId; got != testKMSAlias {
		t.Errorf("public key request ID = %q", got)
	}

	message := []byte("header.payload")
	signature, err := signer.Sign(context.Background(), message)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ed25519.Verify(publicKey, message, signature) {
		t.Fatal("signature verification failed")
	}
	if client.signInput.MessageType != types.MessageTypeRaw {
		t.Errorf("message type = %s, want RAW", client.signInput.MessageType)
	}
	if client.signInput.SigningAlgorithm != types.SigningAlgorithmSpecEd25519Sha512 {
		t.Errorf("signing algorithm = %s, want ED25519_SHA_512", client.signInput.SigningAlgorithm)
	}
	if got := *client.signInput.KeyId; got != testKMSKeyARN {
		t.Errorf("signing key ID = %q, want immutable ARN %q", got, testKMSKeyARN)
	}
}

func TestKMSSignerRejectsWrongKeyType(t *testing.T) {
	client := &fakeKMS{publicKeyOutput: kms.GetPublicKeyOutput{
		KeyId:    stringPointer(testKMSKeyARN),
		KeySpec:  types.KeySpecEccNistP256,
		KeyUsage: types.KeyUsageTypeSignVerify,
	}}
	if _, _, err := LoadKMSSigner(context.Background(), client, "kms-key"); err == nil {
		t.Fatal("accepted non-Ed25519 KMS key")
	}
}

func TestKMSSignerRejectsDifferentSigningKey(t *testing.T) {
	client, signer, _ := newFakeKMSSigner(t)
	differentKeyARN := "arn:aws:kms:eu-north-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	client.signOutputKeyID = &differentKeyARN

	if _, err := signer.Sign(context.Background(), []byte("header.payload")); err == nil {
		t.Fatal("accepted signature from a different KMS key")
	}
}

func TestKMSSignerRejectsOversizedRawMessageBeforeRequest(t *testing.T) {
	client, signer, _ := newFakeKMSSigner(t)

	if _, err := signer.Sign(context.Background(), make([]byte, maximumRawKMSMessageSize+1)); err == nil {
		t.Fatal("accepted oversized raw message")
	}
	if client.signCalls != 0 {
		t.Errorf("KMS sign calls = %d, want 0", client.signCalls)
	}
}

type fakeKMS struct {
	privateKey      ed25519.PrivateKey
	publicKeyOutput kms.GetPublicKeyOutput
	publicKeyInput  kms.GetPublicKeyInput
	signInput       kms.SignInput
	signOutputKeyID *string
	signCalls       int
}

func (f *fakeKMS) GetPublicKey(_ context.Context, input *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	f.publicKeyInput = *input
	return &f.publicKeyOutput, nil
}

func (f *fakeKMS) Sign(_ context.Context, input *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.signCalls++
	f.signInput = *input
	keyID := input.KeyId
	if f.signOutputKeyID != nil {
		keyID = f.signOutputKeyID
	}
	return &kms.SignOutput{KeyId: keyID, Signature: ed25519.Sign(f.privateKey, input.Message)}, nil
}

func newFakeKMSSigner(t *testing.T) (*fakeKMS, *KMSSigner, ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	encodedPublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	client := &fakeKMS{
		privateKey: privateKey,
		publicKeyOutput: kms.GetPublicKeyOutput{
			KeyId:             stringPointer(testKMSKeyARN),
			KeySpec:           types.KeySpecEccNistEdwards25519,
			KeyUsage:          types.KeyUsageTypeSignVerify,
			PublicKey:         encodedPublicKey,
			SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEd25519Sha512},
		},
	}
	signer, gotPublicKey, err := LoadKMSSigner(context.Background(), client, testKMSAlias)
	if err != nil {
		t.Fatalf("load signer: %v", err)
	}
	if !gotPublicKey.Equal(publicKey) {
		t.Fatal("public key differs from KMS key")
	}
	return client, signer, publicKey
}

func stringPointer(value string) *string {
	return &value
}
