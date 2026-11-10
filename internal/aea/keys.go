package aea

import (
	"fmt"

	"golang.org/x/crypto/scrypt"
)

// passwordKeyMaterial implements the profile 5 key schedule: the main salt is
// expanded into a 64 byte scrypt salt with HKDF, whose first half salts scrypt
// and whose second half replaces the main salt for the main key derivation.
func passwordKeyMaterial(password string, strength uint8, mainSalt []byte) (ikm, salt []byte, err error) {
	extended := deriveKey(64, mainSalt, nil, []byte("AEA_SCRYPT"))
	n := uint64(0x4000) << (uint(strength) << 1)
	key, err := scrypt.Key([]byte(password), extended[:32], int(n), 8, 1, macKeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("aea: deriving password key: %w", err)
	}
	return key, extended[32:], nil
}
