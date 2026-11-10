// Package appleid signs in to an Apple ID with SRP-6a and yields the cookie
// session that Apple's developer services accept.
//
// The exchange is plain HTTPS against idmsa.apple.com: a hashcash challenge, SRP
// signin/init, SRP signin/complete (with PBKDF2-stretched password), then a
// second-factor step (SMS or trusted device) and /2sv/trust. No macOS service,
// private framework or anisette data is involved; see srp.go for the exact SRP
// construction, which matches the swift-srp library that Apple-facing Swift
// tools use.
package appleid
