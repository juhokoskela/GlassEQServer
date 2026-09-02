package activation

import (
	"encoding/base32"
	"io"
	"strings"
)

const (
	licenseKeyPrefix    = "GEQ1"
	licenseKeyByteCount = 16
	licenseKeyAlphabet  = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
)

var licenseKeyEncoding = base32.NewEncoding(licenseKeyAlphabet).WithPadding(base32.NoPadding)

func generateLicenseKey(random io.Reader) (string, string, error) {
	value := make([]byte, licenseKeyByteCount)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", "", err
	}
	encoded := licenseKeyEncoding.EncodeToString(value)
	display := licenseKeyPrefix + "-" + encoded[:5] + "-" + encoded[5:10] + "-" + encoded[10:15] + "-" + encoded[15:20] + "-" + encoded[20:25] + "-" + encoded[25:]
	return display, licenseKeyPrefix + encoded, nil
}

func normalizeLicenseKey(value string) (string, bool) {
	if value == "" || len(value) > 128 {
		return value, false
	}
	var normalized strings.Builder
	normalized.Grow(len(value))
	for i := range len(value) {
		character := value[i]
		if character == '-' {
			continue
		}
		if character >= 'a' && character <= 'z' {
			character -= 'a' - 'A'
		}
		normalized.WriteByte(character)
	}
	result := normalized.String()
	if len(result) != len(licenseKeyPrefix)+licenseKeyEncoding.EncodedLen(licenseKeyByteCount) || !strings.HasPrefix(result, licenseKeyPrefix) {
		return result, false
	}
	for i := len(licenseKeyPrefix); i < len(result); i++ {
		if !strings.ContainsRune(licenseKeyAlphabet, rune(result[i])) {
			return result, false
		}
	}
	return result, true
}
