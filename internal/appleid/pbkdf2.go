package appleid

import (
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

// pbkdf2SHA256 derives a 32-byte key with PBKDF2-HMAC-SHA256.
func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)
}
