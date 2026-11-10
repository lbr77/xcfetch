package appleid

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

// SRP-6a as Apple's identity service uses it: the RFC 5054 2048-bit group with
// SHA-256, and a password that the caller has already stretched with PBKDF2.
//
// This mirrors swift-srp (the implementation the Swift xcodes CLI uses) exactly:
//
//	k  = H(N || pad(g))            pad() left-zero-pads to the byte length of N
//	x  = H(salt || H(message))     message is ":" + pbkdf2(password) here
//	u  = H(pad(A) || pad(B))
//	S  = (B - k*g^x)^(a + u*x) mod N
//	K  = H(S)
//	M1 = H(H(N) xor H(pad(g)) || H(username) || salt || A || B || K)
//	M2 = H(A || M1 || K)
//
// A, B and S use their minimal big-endian encodings where the specification
// says "A" / "B" (that is what swift-srp's BigNum.bytes produces); only the
// values inside pad() are padded.

var (
	// errNullServerKey reports a degenerate server public key.
	errNullServerKey = errors.New("appleid: server public key is null")
)

// group2048 is the 2048-bit MODP group from RFC 5054 section 3.
var group2048 = mustHex("AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73")

// generator is the group's generator.
var generator = big.NewInt(2)

func mustHex(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("appleid: bad constant")
	}
	return v
}

func hash(data ...[]byte) []byte {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// padLeft left-pads b with zeros to size bytes.
func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func bytesToInt(b []byte) *big.Int { return new(big.Int).SetBytes(b) }

func intToBytes(v *big.Int) []byte { return v.Bytes() }

// srpClient is the client half of one SRP exchange.
type srpClient struct {
	N, g, k *big.Int
	sizeN   int
	a       *big.Int
	A       *big.Int
}

func newSRPClient() (*srpClient, error) {
	for {
		priv := make([]byte, 32)
		if _, err := rand.Read(priv); err != nil {
			return nil, err
		}
		c, err := newSRPClientWithPrivate(priv)
		if err != nil {
			continue
		}
		return c, nil
	}
}

// newSRPClientWithPrivate builds a client around a fixed private exponent. It is
// used by tests to reproduce known vectors.
func newSRPClientWithPrivate(priv []byte) (*srpClient, error) {
	sizeN := len(group2048.Bytes())
	k := bytesToInt(hash(group2048.Bytes(), padLeft(generator.Bytes(), sizeN)))
	a := bytesToInt(priv)
	A := new(big.Int).Exp(generator, a, group2048)
	if A.Sign() == 0 || new(big.Int).Mod(A, group2048).Sign() == 0 {
		return nil, errors.New("appleid: degenerate SRP public key")
	}
	return &srpClient{N: group2048, g: generator, k: k, sizeN: sizeN, a: a, A: A}, nil
}

// publicKey is the A value sent to the server.
func (c *srpClient) publicKey() []byte { return intToBytes(c.A) }

// pbkdfPassword normalises the password exactly like the Swift client: hash the
// UTF-8 password with SHA-256, hex-encode it for the legacy s2k_fo protocol,
// then run PBKDF2-HMAC-SHA256 over that with the server-provided salt.
func pbkdfPassword(password string, salt []byte, iterations int, protocol string) []byte {
	digest := hash([]byte(password))
	secret := digest
	if protocol == "s2k_fo" {
		secret = []byte(hexLower(digest))
	}
	return pbkdf2SHA256(secret, salt, iterations, 32)
}

// sharedSecret computes S from the server's public key B and salt.
func (c *srpClient) sharedSecret(username string, stretchedPassword, salt, serverPublic []byte) (*big.Int, []byte, error) {
	B := bytesToInt(serverPublic)
	if B.Sign() == 0 || new(big.Int).Mod(B, c.N).Sign() == 0 {
		return nil, nil, errNullServerKey
	}
	u := bytesToInt(hash(padLeft(c.publicKey(), c.sizeN), padLeft(serverPublic, c.sizeN)))
	if u.Sign() == 0 {
		return nil, nil, errNullServerKey
	}

	inner := hash(append([]byte{0x3a}, stretchedPassword...))
	x := bytesToInt(hash(salt, inner))

	// S = (B - k * g^x) ^ (a + u*x) mod N
	gx := new(big.Int).Exp(c.g, x, c.N)
	kgx := new(big.Int).Mul(c.k, gx)
	kgx.Mod(kgx, c.N)
	base := new(big.Int).Sub(B, kgx)
	base.Mod(base, c.N)
	exp := new(big.Int).Mul(u, x)
	exp.Add(exp, c.a)
	S := new(big.Int).Exp(base, exp, c.N)
	return S, hash(S.Bytes()), nil
}

// clientProof computes M1, the proof the client sends to the server.
func (c *srpClient) clientProof(username string, salt, serverPublic, sessionKeyHash []byte) []byte {
	hN := hash(c.N.Bytes())
	hG := hash(padLeft(c.g.Bytes(), c.sizeN))
	nx := make([]byte, len(hN))
	for i := range hN {
		nx[i] = hN[i] ^ hG[i]
	}
	parts := [][]byte{nx, hash([]byte(username)), salt, c.publicKey(), serverPublic, sessionKeyHash}
	return hash(parts...)
}

// serverProof computes M2, which the server returns and the client can check.
func (c *srpClient) serverProof(clientProof, sessionKeyHash []byte) []byte {
	return hash(c.publicKey(), clientProof, sessionKeyHash)
}

func hexLower(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}
