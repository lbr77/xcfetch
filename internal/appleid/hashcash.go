package appleid

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"time"
)

// mintHashcash produces the X-Apple-HC value Apple asks for before SRP.
//
// Apple's variant differs from the classic hashcash spec: no random nonce is
// inserted and the counter is decimal, not base64. The value is
//
//	1:<bits>:<YYMMDDhhmmss>:<challenge>:<counter>
//
// where the SHA-1 digest of the whole string has at least <bits> leading zero
// bits (only the first 32 bits are examined, exactly like the Swift client).
func mintHashcash(challenge string, bits uint, now time.Time) string {
	prefix := fmt.Sprintf("1:%d:%s:%s:", bits, now.UTC().Format("060102150405"), challenge)
	for counter := uint64(0); ; counter++ {
		candidate := fmt.Sprintf("%s:%d", prefix, counter)
		if leadingZeroBits([]byte(candidate)) >= int(bits) {
			return candidate
		}
	}
}

// leadingZeroBits reports the leading zero bits of the first three bytes of the
// SHA-1 digest (sufficient for the bit counts Apple uses and for any count up
// to 32).
func leadingZeroBits(data []byte) int {
	sum := sha1.Sum(data)
	head := binary.BigEndian.Uint32(sum[:4])
	bits := 0
	for mask := uint32(1 << 31); mask != 0 && head&mask == 0; mask >>= 1 {
		bits++
	}
	return bits
}
