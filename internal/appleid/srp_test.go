package appleid

import (
	"encoding/hex"
	"strings"
	"testing"
)

// The expected values in this file were produced by swift-srp (the library the
// Swift xcodes CLI uses) with the same fixed inputs, so they pin our
// implementation to Apple's wire behaviour rather than to itself.
const (
	vectorUsername   = "dev@example.com"
	vectorPassword   = "correct horse battery staple"
	vectorIterations = 20000
)

func vectorSalt() []byte {
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	return salt
}

// vectorServerPublic is the deterministic B used by the Swift harness.
func vectorServerPublic() []byte {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte((i*7 + 13) & 0xff)
	}
	return b
}

func vectorPrivate() []byte {
	priv, err := hex.DecodeString("112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00")
	if err != nil {
		panic(err)
	}
	return priv
}

func TestPBKDFMatchesSwift(t *testing.T) {
	cases := []struct {
		protocol string
		want     string
	}{
		{"s2k", "1c3c0e54771f00e752a5eb2d8188e38b222bd66a180d5c20abee815bc006b261"},
		{"s2k_fo", "3de1fd5ea526e345276d913ee6b9c280f6d5bf63952d5bde0290ed7652051fc3"},
	}
	for _, c := range cases {
		got := hex.EncodeToString(pbkdfPassword(vectorPassword, vectorSalt(), vectorIterations, c.protocol))
		if got != c.want {
			t.Errorf("%s: got %s want %s", c.protocol, got, c.want)
		}
	}
}

func TestSRPMatchesSwift(t *testing.T) {
	client, err := newSRPClientWithPrivate(vectorPrivate())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(client.publicKey()), "4096b591feb77332d74ba6a4146b9782095d5f19768f798a3c0e62b80ff8afa3741b24d055dc94dee65b43532234ba802936df339924dd272d130206781fba9ae85819afc3e0e99c59b63ac1ac7042bb79d233b6c07ca90429cce8c384c8787e5338e38ae2577fa064642eb79b0d2ef980191761550e9ad0089343c931c70a97a430205ca828974e08a8ab477dc40eb82f46060270c94b49d69ce99925ac60d6ae6d0a043213aa4fabbd1d981ea77589ce4e6c9605c27b042a0a3a0c266ed4e3f46a49bfe288c8f0500dbe140ef6d9e28cdbcb21dc980777f8a4535a543c43c9318ce830de77a3337bbff24875c71ea3565d25d7efb80b1e2a802ebe3d299159"; got != want {
		t.Fatalf("A mismatch:\n got %s\nwant %s", got, want)
	}

	salt := vectorSalt()
	serverPublic := vectorServerPublic()
	stretched := pbkdfPassword(vectorPassword, salt, vectorIterations, "s2k")

	S, sessionKeyHash, err := client.sharedSecret(vectorUsername, stretched, salt, serverPublic)
	if err != nil {
		t.Fatal(err)
	}
	const wantS = "970c201b44f13d64f174aa5b4d73d12f26b050707555f28a4ac7960ce29a27e0de493ebcb9b31f5f8794bab81a641bbde0035ce8d016a74de940929d6f25c293a16d43ef254649a33da2ffd353abeb66cdab22fcfed48b1fdb4d6916b619d282a149f8865cb5ccbbe8ac972e16c44a47d48cc9ea20e0087aae0e3b8e39cbfb3d4b54e1fc0452cbda9caaf6a5beb226406111d902e21a83ab2fca0fd7cb867a2d86281943c689c82b91be6d1badfe68a4d25b533a63c6d7b8c0d8bd397ea00d06592b441ba494e7df0bb61062b6ba6b158f347abdb5cc6eec87cda71aeb43292f110a6fa7998d733ae0f96da51c77cbcc30d2c975cd207f7c9cbf7e19b7d4e887"
	if got := hex.EncodeToString(S.Bytes()); got != wantS {
		t.Fatalf("S mismatch:\n got %s\nwant %s", got, wantS)
	}

	m1 := client.clientProof(vectorUsername, salt, serverPublic, sessionKeyHash)
	if got, want := hex.EncodeToString(m1), "4085a438e9896e52097454f6da23c633a2bcd896741b7a289b5cca517e590c40"; got != want {
		t.Fatalf("M1 mismatch:\n got %s\nwant %s", got, want)
	}
	m2 := client.serverProof(m1, sessionKeyHash)
	if got, want := hex.EncodeToString(m2), "4c0478415a4416a1783c058e50757f2f748dc9497e32cec5f2d59aff1227d025"; got != want {
		t.Fatalf("M2 mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestHashcashMintsRequiredDifficulty(t *testing.T) {
	const challenge = "abcdef0123456789"
	for _, bits := range []uint{4, 10, 16} {
		value := mintHashcash(challenge, bits, timeFixture())
		if got := leadingZeroBits([]byte(value)); got < int(bits) {
			t.Errorf("bits=%d: value %q has only %d leading zero bits", bits, value, got)
		}
		if !strings.HasPrefix(value, "1:") {
			t.Errorf("value %q does not start with the version", value)
		}
	}
}

func TestHashcashFormat(t *testing.T) {
	got := mintHashcash("chal", 4, timeFixture())
	parts := strings.Split(got, ":")
	if len(parts) != 6 {
		t.Fatalf("unexpected format %q", got)
	}
	if parts[0] != "1" || parts[1] != "4" || parts[2] != "250101000000" || parts[3] != "chal" || parts[4] != "" {
		t.Errorf("unexpected fields %v", parts)
	}
}
